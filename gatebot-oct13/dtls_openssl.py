#!/usr/bin/env python3
"""dtls_openssl.py -- a real DTLS 1.2 client, driven through OpenSSL via
ctypes.

Why ctypes: Python ships libssl-3.dll / libcrypto-3.dll (OpenSSL 3.0.16) with
the DTLS entry points exported, and OpenSSL performs the whole protocol --
cookie exchange, ECDHE, extended_master_secret, GCM record layer, Finished --
exactly the way Konami's server expects.  Hand-rolling that would mean
guessing the handshake transcript (which messages are hashed), and getting it
wrong yields a silent drop, which is what cost the earlier attempts.

Transport is a memory BIO pair; UDP is shuttled in Python, one datagram at a
time, so mem-BIO stream semantics cannot bleed across datagram boundaries.

Discovery of the rendezvous is live: turn_rendezvous.py's chain, i.e.

  CMD_GET_TURN_SERVER_LIST -> TCP+TLS 443 STUN Allocate -> 401 + NONCE
    -> SOFTWARE "ip:port,reversed-ipc,0"  (issued per attempt)

  python dtls_openssl.py                  handshake + hold
  python dtls_openssl.py --hold 20        keep the session alive N seconds
  python dtls_openssl.py --appdata 167    send N-byte records while holding
"""
import ctypes
import socket
import ssl as _sslmod
import struct
import sys
import time

sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\work")
import turn_rendezvous as TR                                     # noqa: E402

DLL = (r"C:\Users\Administrator\AppData\Local\Programs\Python"
       r"\Python312\DLLs")
SL = ctypes.CDLL(DLL + r"\libssl-3.dll")
CR = ctypes.CDLL(DLL + r"\libcrypto-3.dll")

# --- libssl -------------------------------------------------------------
SL.SSL_CTX_new.restype = ctypes.c_void_p
SL.SSL_CTX_new.argtypes = [ctypes.c_void_p]
SL.DTLSv1_2_client_method.restype = ctypes.c_void_p
SL.SSL_new.restype = ctypes.c_void_p
SL.SSL_new.argtypes = [ctypes.c_void_p]
SL.SSL_set_bio.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
SL.SSL_do_handshake.argtypes = [ctypes.c_void_p]
SL.SSL_get_error.argtypes = [ctypes.c_void_p, ctypes.c_int]
SL.SSL_get_error.restype = ctypes.c_int
SL.SSL_ctrl.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_long,
                        ctypes.c_void_p]
SL.SSL_ctrl.restype = ctypes.c_long
SL.SSL_get_version.restype = ctypes.c_char_p
SL.SSL_get_version.argtypes = [ctypes.c_void_p]
SL.SSL_is_init_finished.argtypes = [ctypes.c_void_p]
SL.SSL_is_init_finished.restype = ctypes.c_int
SL.SSL_set_connect_state.argtypes = [ctypes.c_void_p]
SL.SSL_CTX_set_verify.argtypes = [ctypes.c_void_p, ctypes.c_int,
                                  ctypes.c_void_p]
SL.SSL_CTX_set_cipher_list.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
SL.SSL_CTX_set_cipher_list.restype = ctypes.c_int
SL.SSL_CTX_set_options.argtypes = [ctypes.c_void_p, ctypes.c_long]
SL.SSL_CTX_set_options.restype = ctypes.c_long
SL.SSL_read_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                           ctypes.POINTER(ctypes.c_size_t)]
SL.SSL_read_ex.restype = ctypes.c_int
SL.SSL_write.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int]
SL.SSL_write.restype = ctypes.c_int
SL.SSL_pending.argtypes = [ctypes.c_void_p]
SL.SSL_pending.restype = ctypes.c_int
SL.SSL_get_server_random.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                     ctypes.c_size_t]
SL.SSL_get_server_random.restype = ctypes.c_size_t
SL.SSL_get_client_random.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                     ctypes.c_size_t]
SL.SSL_get_client_random.restype = ctypes.c_size_t
SL.SSL_free.argtypes = [ctypes.c_void_p]
SL.SSL_CTX_free.argtypes = [ctypes.c_void_p]
SL.SSL_get1_peer_certificate.argtypes = [ctypes.c_void_p]
SL.SSL_get1_peer_certificate.restype = ctypes.c_void_p
SL.SSL_get_verify_result.argtypes = [ctypes.c_void_p]
SL.SSL_get_verify_result.restype = ctypes.c_long
SL.SSL_get_session.argtypes = [ctypes.c_void_p]
SL.SSL_get_session.restype = ctypes.c_void_p

# --- libcrypto ----------------------------------------------------------
CR.BIO_s_mem.restype = ctypes.c_void_p
CR.BIO_new.restype = ctypes.c_void_p
CR.BIO_new.argtypes = [ctypes.c_void_p]
CR.BIO_read.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int]
CR.BIO_read.restype = ctypes.c_int
CR.BIO_write.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int]
CR.BIO_write.restype = ctypes.c_int
CR.BIO_free.argtypes = [ctypes.c_void_p]
CR.BIO_ctrl_pending.argtypes = [ctypes.c_void_p]
CR.BIO_ctrl_pending.restype = ctypes.c_size_t
CR.ERR_peek_last_error.restype = ctypes.c_ulong
CR.ERR_reason_error_string.argtypes = [ctypes.c_ulong]
CR.ERR_reason_error_string.restype = ctypes.c_char_p
CR.ERR_clear_error.restype = ctypes.c_ulong
CR.X509_free.argtypes = [ctypes.c_void_p]


def _cipher_name(ssl_ptr):
    """SSL_get_current_cipher -> SSL_CIPHER_get_name (both in libssl; note
    SSL_SESSION_get_cipher is NOT exported by this build)."""
    try:
        if not hasattr(SL, "SSL_get_current_cipher"):
            return "?"
        SL.SSL_get_current_cipher.restype = ctypes.c_void_p
        SL.SSL_get_current_cipher.argtypes = [ctypes.c_void_p]
        cph = SL.SSL_get_current_cipher(ssl_ptr)
        if not cph:
            return "?"
        if not hasattr(SL, "SSL_CIPHER_get_name"):
            return "?"
        SL.SSL_CIPHER_get_name.restype = ctypes.c_char_p
        SL.SSL_CIPHER_get_name.argtypes = [ctypes.c_void_p]
        nm = SL.SSL_CIPHER_get_name(cph)
        return nm.decode() if nm else "?"
    except Exception as e:                                        # noqa: BLE001
        return "(%s)" % e

# constants
SSL_VERIFY_NONE = 0
SSL_CTRL_SET_TLSEXT_HOSTNAME = 55
TLSEXT_NAMETYPE_host_name = 0
SSL_ERROR_WANT_READ = 2
SSL_ERROR_WANT_WRITE = 3
SSL_ERROR_SYSCALL = 5
SSL_ERROR_ZERO_RETURN = 6
SSL_OP_NO_TICKET = 0x00004000
SSL_OP_NO_COMPRESSION = 0x00020000


def _err():
    e = CR.ERR_peek_last_error()
    if not e:
        return ""
    r = CR.ERR_reason_error_string(e)
    return r.decode("utf-8", "replace") if r else "0x%x" % e


class Dtls:
    """DTLS 1.2 client over a memory-BIO pair, UDP shuttled by the caller."""

    def __init__(self, host, port, ip, sni=b"pes20.turn.konami.com"):
        self.ip, self.port = ip, port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(0.5)
        self.sock.bind(("", 0))
        self.local = self.sock.getsockname()
        self.log = []

        self.ctx = SL.SSL_CTX_new(SL.DTLSv1_2_client_method())
        if not self.ctx:
            raise RuntimeError("SSL_CTX_new: %s" % _err())
        SL.SSL_CTX_set_verify(self.ctx, SSL_VERIFY_NONE, None)
        SL.SSL_CTX_set_options(self.ctx, SSL_OP_NO_COMPRESSION)
        # offer the same suites the real client offered, most-preferred first
        SL.SSL_CTX_set_cipher_list(
            self.ctx,
            b"ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
            b"ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
            b"ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:"
            b"ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:"
            b"ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:"
            b"ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA")

        self.ssl = SL.SSL_new(self.ctx)
        if not self.ssl:
            raise RuntimeError("SSL_new: %s" % _err())
        if sni:
            SL.SSL_ctrl(self.ssl, SSL_CTRL_SET_TLSEXT_HOSTNAME,
                        TLSEXT_NAMETYPE_host_name, sni)
        self.rbio = CR.BIO_new(CR.BIO_s_mem())
        self.wbio = CR.BIO_new(CR.BIO_s_mem())
        SL.SSL_set_bio(self.ssl, self.rbio, self.wbio)
        SL.SSL_set_connect_state(self.ssl)

    # ---- datagram plumbing -------------------------------------------
    def _flush(self):
        """drain wbio -> UDP datagrams"""
        sent = 0
        buf = ctypes.create_string_buffer(65536)
        while CR.BIO_ctrl_pending(self.wbio) > 0:
            n = CR.BIO_read(self.wbio, buf, 65536)
            if n <= 0:
                break
            self.sock.sendto(buf.raw[:n], (self.ip, self.port))
            sent += n
            self.log.append(("tx", n))
        return sent

    def _pump(self, wait=0.5):
        """wait for one datagram, hand it to OpenSSL"""
        try:
            d, frm = self.sock.recvfrom(65536)
        except socket.timeout:
            return None
        CR.BIO_write(self.rbio, d, len(d))
        self.log.append(("rx", len(d), frm))
        return d

    # ---- handshake -----------------------------------------------------
    def handshake(self, timeout=20.0):
        deadline = time.time() + timeout
        CR.ERR_clear_error()
        last_tx = 0
        while True:
            r = SL.SSL_do_handshake(self.ssl)
            if r == 1:
                self._flush()
                return True
            err = SL.SSL_get_error(self.ssl, r)
            tx = self._flush()
            if tx:
                last_tx = time.time()
            if err == SSL_ERROR_WANT_READ:
                d = self._pump(wait=0.6)
                if d is None:
                    # retransmit path: nudge OpenSSL again after silence
                    if time.time() > deadline:
                        tx = sum(e[1] for e in self.log if e[0] == "tx")
                        rx = sum(e[1] for e in self.log if e[0] == "rx")
                        raise TimeoutError(
                            "DTLS handshake timed out after %.0fs "
                            "(%s); tx=%dB rx=%dB flights=%d"
                            % (timeout, _err(), tx, rx,
                               sum(1 for e in self.log if e[0] == "rx")))
                    continue
                continue
            if err == SSL_ERROR_WANT_WRITE:
                if time.time() > deadline:
                    raise TimeoutError("DTLS want_write stalled")
                continue
            raise RuntimeError("DTLS handshake failed: err=%d %s"
                               % (err, _err()))

    # ---- data ----------------------------------------------------------
    def send_appdata(self, payload):
        buf = ctypes.create_string_buffer(payload, len(payload))
        n = SL.SSL_write(self.ssl, buf, len(payload))
        self._flush()
        return n

    def recv_appdata(self, maxlen=4096, timeout=1.0):
        end = time.time() + timeout
        out = b""
        while time.time() < end:
            if SL.SSL_pending(self.ssl):
                buf = ctypes.create_string_buffer(maxlen)
                got = ctypes.c_size_t(0)
                if SL.SSL_read_ex(self.ssl, buf, maxlen, ctypes.byref(got)) == 1:
                    out += buf.raw[:got.value]
                    continue
            if self._pump(wait=0.3) is None and not out:
                break
            self._flush()
        return out

    def close(self):
        try:
            SL.SSL_free(self.ssl)
        except Exception:
            pass
        try:
            SL.SSL_CTX_free(self.ctx)
        except Exception:
            pass
        try:
            self.sock.close()
        except Exception:
            pass

    def report(self):
        ver = SL.SSL_get_version(self.ssl)
        ver = ver.decode() if ver else "?"
        cipher = _cipher_name(self.ssl)
        vfy = SL.SSL_get_verify_result(self.ssl)
        x = SL.SSL_get1_peer_certificate(self.ssl)
        scr = ctypes.create_string_buffer(32)
        ccr = ctypes.create_string_buffer(32)
        SL.SSL_get_server_random(self.ssl, scr, 32)
        SL.SSL_get_client_random(self.ssl, ccr, 32)
        if x:
            CR.X509_free(x)
        return dict(version=ver, cipher=cipher, verify_result=vfy,
                    server_random=scr.raw[:32].hex(),
                    client_random=ccr.raw[:32].hex(),
                    tx=sum(e[1] for e in self.log if e[0] == "tx"),
                    rx=sum(e[1] for e in self.log if e[0] == "rx"))


def main() -> int:
    hold = 0
    appn = 0
    args = sys.argv[1:]
    if "--hold" in args:
        hold = int(args[args.index("--hold") + 1])
    if "--appdata" in args:
        appn = int(args[args.index("--appdata") + 1])

    # --- rendezvous -----------------------------------------------------
    print("=== discovering rendezvous ===")
    try:
        mt, at = TR.allocate()
    except Exception as e:                                        # noqa: BLE001
        print("  TURN allocate failed: %s" % e)
        return 1
    soft = next((v for n, v, _ in at if n == "SOFTWARE"), "")
    print("  method=0x%04x" % mt)
    print("  SOFTWARE %s" % soft)
    if not soft:
        return 1
    host, _, port = soft.split(",")[0].rpartition(":")
    port = int(port)
    ip = socket.getaddrinfo(host, port, socket.AF_INET,
                            socket.SOCK_DGRAM)[0][4][0]
    print("  -> %s:%d (%s)" % (host, port, ip))

    # --- handshake ------------------------------------------------------
    print("\n=== DTLS 1.2 handshake ===")
    c = Dtls(host, port, ip)
    try:
        t0 = time.time()
        c.handshake(timeout=25.0)
        print("  ESTABLISHED in %.2fs" % (time.time() - t0))
        print("  %s" % c.report())
    except Exception as e:                                        # noqa: BLE001
        print("  FAILED: %s" % e)
        print("  flight log: %s" % [(k, n) for k, n, *_
                                    in c.log][:12])
        c.close()
        return 1

    # --- hold -----------------------------------------------------------
    if hold:
        print("\n=== holding %ds ===" % hold)
        end = time.time() + hold
        n = 0
        while time.time() < end:
            if appn:
                try:
                    c.send_appdata(bytes([0x00]) * appn)
                except Exception as e:                            # noqa: BLE001
                    print("  send failed: %s" % e)
                    break
            got = c.recv_appdata(timeout=1.0)
            if got:
                print("  rx %dB: %s" % (len(got), got[:32].hex()))
            n += 1
            time.sleep(1.0)
        print("  cycles=%d  %s" % (n, c.report()))

    c.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
