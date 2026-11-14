"""Signed, encrypted commands for the owner's temporary Android test phone.

Only public keys and encrypted envelopes enter the public repository. Inspect
each screenshot before deciding the next UI action. No game states are forged.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import time
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Signature import pss

CMD_BRANCH = 'live-cmd-kickoff-20261113'
RES_BRANCH = 'live-res-kickoff-20261113'
AAD = b'peerlink-owner-phone-lab-v1'


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def encode(value):
    return base64.b64encode(value).decode()


def decode(value):
    return base64.b64decode(value, validate=True)


def seal(payload, recipient, signer):
    key = get_random_bytes(32)
    cipher = AES.new(key, AES.MODE_GCM, nonce=get_random_bytes(12))
    cipher.update(AAD)
    ciphertext, tag = cipher.encrypt_and_digest(canonical(payload))
    result = {'v': 1, 'key': encode(PKCS1_OAEP.new(recipient, hashAlgo=SHA256).encrypt(key)),
              'nonce': encode(cipher.nonce), 'ciphertext': encode(ciphertext), 'tag': encode(tag)}
    result['signature'] = encode(pss.new(signer).sign(SHA256.new(canonical(result))))
    return result


def unseal(envelope, recipient, sender):
    value = dict(envelope)
    signature = decode(value.pop('signature'))
    if value.get('v') != 1:
        raise ValueError('Unknown protocol version')
    pss.new(sender).verify(SHA256.new(canonical(value)), signature)
    key = PKCS1_OAEP.new(recipient, hashAlgo=SHA256).decrypt(decode(value['key']))
    cipher = AES.new(key, AES.MODE_GCM, nonce=decode(value['nonce']))
    cipher.update(AAD)
    return json.loads(cipher.decrypt_and_verify(decode(value['ciphertext']), decode(value['tag'])))


def api(path, payload=None, optional=False):
    command = ['gh', 'api', path]
    if payload is not None:
        command += ['--method', 'POST', '--input', '-']
    result = subprocess.run(command, input=None if payload is None else canonical(payload),
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=40)
    if result.returncode:
        if optional and b'404' in result.stderr:
            return None
        raise RuntimeError('GitHub lab transport request failed')
    return json.loads(result.stdout)


def read_file(repository, branch, path):
    data = api(f'repos/{repository}/contents/{path}?ref={branch}', optional=True)
    if data is None:
        return None
    if data.get('encoding') != 'base64':
        data = api(f'repos/{repository}/git/blobs/{data["sha"]}')
    return base64.b64decode(data['content'])


def put_file(repository, branch, path, data):
    old = api(f'repos/{repository}/contents/{path}?ref={branch}', optional=True)
    value = {'branch': branch, 'message': f'Update temporary phone lab {path}', 'content': encode(data)}
    if old is not None:
        value['sha'] = old['sha']
    result = subprocess.run(['gh', 'api', f'repos/{repository}/contents/{path}', '--method', 'PUT', '--input', '-'],
                            input=canonical(value), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=40)
    if result.returncode:
        raise RuntimeError('GitHub lab transport update failed')


def ensure_branch(repository, name):
    if api(f'repos/{repository}/git/ref/heads/{name}', optional=True) is None:
        head = api(f'repos/{repository}/git/ref/heads/main')['object']['sha']
        api(f'repos/{repository}/git/refs', {'ref': 'refs/heads/' + name, 'sha': head})


def run_command(request, work):
    request_id = request['id']
    if not re.fullmatch(r'[a-zA-Z0-9_-]{1,80}', request_id):
        raise ValueError('Invalid request identifier')
    timeout = max(1, min(int(request.get('timeout', 120)), 900))
    out, err = work / ('stdout-' + request_id), work / ('stderr-' + request_id)
    with out.open('wb') as stdout, err.open('wb') as stderr:
        process = subprocess.Popen(['/bin/bash', '-e', '-o', 'pipefail', '-c', request['command']],
                                   stdout=stdout, stderr=stderr, start_new_session=True)
        try:
            exit_code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            exit_code = process.wait()
    response = {'id': request_id, 'exit_code': exit_code,
                'stdout_b64': encode(out.read_bytes()[-262144:]),
                'stderr_b64': encode(err.read_bytes()[-262144:])}
    if request.get('file'):
        path = Path(request['file'])
        if path.is_file() and path.stat().st_size <= 8 * 1024 * 1024:
            response['file_b64'], response['file_name'] = encode(path.read_bytes()), path.name
    return response


def main():
    repository = os.environ['GITHUB_REPOSITORY']
    work = Path('/tmp/peerlink-kickoff')
    work.mkdir(mode=0o700, exist_ok=True)
    os.umask(0o077)
    controller = RSA.import_key(Path('research/kickoff-phone-controller.pub').read_bytes())
    server = RSA.generate(3072)
    (work / 'server-private.pem').write_bytes(server.export_key())
    ensure_branch(repository, CMD_BRANCH)
    ensure_branch(repository, RES_BRANCH)
    boot = subprocess.run(['sudo', 'docker', 'exec', 'redroid-a', 'getprop', 'sys.boot_completed'],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    status = {'run_id': os.environ['GITHUB_RUN_ID'], 'source_commit': os.environ['GITHUB_SHA'],
              'boot_completed': boot.stdout.decode().strip(), 'server_public_key': server.public_key().export_key().decode(),
              'controller_fingerprint': hashlib.sha256(controller.export_key()).hexdigest(),
              'expires_utc_epoch': int(time.time()) + 95 * 60}
    put_file(repository, RES_BRANCH, 'status.json', canonical(status))
    print('OWNER_PHONE_LAB_READY', flush=True)
    seen = set()
    while time.time() < status['expires_utc_epoch']:
        try:
            raw = read_file(repository, CMD_BRANCH, 'cmd.txt')
            if raw is None:
                time.sleep(10)
                continue
            request = unseal(json.loads(raw), server, controller)
            request_id = request['id']
            if request_id not in seen:
                seen.add(request_id)
                if request.get('stop'):
                    break
                result = run_command(request, work)
                put_file(repository, RES_BRANCH, 'response-' + request_id + '.json',
                         canonical(seal(result, controller, server)))
                print('OWNER_PHONE_COMMAND_FINISHED', request_id, result['exit_code'], flush=True)
        except (ValueError, KeyError, TypeError):
            print('OWNER_PHONE_REJECTED_INVALID_ENVELOPE', flush=True)
        except RuntimeError:
            print('OWNER_PHONE_TRANSPORT_RETRY', flush=True)
        time.sleep(10)


if __name__ == '__main__':
    main()
