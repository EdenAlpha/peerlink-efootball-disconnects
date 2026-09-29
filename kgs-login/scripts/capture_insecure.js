// Read eFootball's gRPC request bytes WITHOUT a MITM and WITHOUT any
// BoringSSL symbol.
//
// Two decoded facts from libUE4.so 11.0.1 (byte-identical to the build on the
// phone) make this work:
//
//  1) 0x7b101f8 is the gRPC config loader. It calls the *int* Def_ getter
//     0x2f0eaf0 with the literal "Def_Online_gRPC_insecure" (string at
//     0xc023be, length 0x18) and branches on the result:
//
//        adrp x0, #0xc02000 ; add x0, x0, #0x3be ; mov w1, #0x18
//        bl   0x2f0eaf0
//        cbnz w0, #0x7b105c8          <-- insecure branch
//
//     Forcing that one key non-zero makes the channel plaintext.
//
//  2) With the channel plaintext, gRPC hands HTTP/2 frames straight to the
//     socket, so a hook on libc send/sendto/write shows the request verbatim.
//     No TLS to break, so we never need SSL_write's address (it is stripped).
//
// The game still speaks its own protocol: the bytes come from the game's own
// serializer. We only read them.

'use strict';

const GETTER_INT      = 0x2f0eaf0;    // int Def_ lookup, (x0=key, w1=len) -> w0
const GETTER_STR      = 0x2f0e18c;    // std::string* Def_ lookup, (x0=key, x1=len)

// Every offset below was read out of the binary, not inferred from a length:
//   0x0c023be Def_Online_gRPC_insecure         (24)  int   -> 1
//   0x0ba2aff Def_Online_gRPC_server_address   (30)  str   -> host
//   0x09c69c1 Def_Online_gRPC_server_path      (27)  str   -> RPC path
//   0x0b68de6 Def_Online_gRPC_server_port      (27)  int   -> 443
// (Note _path and _port are both 27 chars, so the two are easy to swap.)
const KEY_INSECURE    = 'Def_Online_gRPC_insecure';
const KEY_INSECURE_VA = 0xc023be;
const KEY_ADDR        = 'Def_Online_gRPC_server_address';
const KEY_ADDR_VA     = 0xba2aff;
const KEY_PATH        = 'Def_Online_gRPC_server_path';
const KEY_PATH_VA     = 0x9c69c1;
const KEY_PORT        = 'Def_Online_gRPC_server_port';
const KEY_PORT_VA     = 0xb68de6;

const HOST = 'pes22-game.cs.konami.net';
const RPC_PATH = '/command_service.CommandService/CommandStream';
const PORT_NUM = 443;

const DUMP_DIR = '/data/local/tmp/kgs';
const MAX_CAPTURE = 4 * 1024 * 1024;

let captured = 0;
let seq = 0;
let hookInstalled = false;

function log(s) { console.log('[kgs] ' + s); }

// ---------------------------------------------- libc++ std::string builder
// 0x2f0e18c returns a std::string*, and the insecure branch dereferences it
// immediately (ldrb w8,[x0]) then calls size() on it. So we have to hand back a
// real std::string object, not a bare char*.
//
// libc++ layout: byte0 = (size<<1) | is_long, data at +1 for short; for long,
// byte0 = 1, size at +8, data pointer at +0x10.
function makeStdString(text) {
    const raw = [];
    for (let i = 0; i < text.length; i++) raw.push(text.charCodeAt(i) & 0xff);
    const obj = Memory.alloc(24);
    obj.writeByteArray(new Uint8Array(24));
    if (raw.length <= 22) {
        const b = new Uint8Array(24);
        b[0] = (raw.length << 1) & 0xff;
        for (let i = 0; i < raw.length; i++) b[1 + i] = raw[i];
        obj.writeByteArray(b);
        obj.add(8).writeU64(0);
        obj.add(0x10).writeU64(0);
    } else {
        const buf = Memory.alloc(raw.length + 1);
        buf.writeByteArray(new Uint8Array(raw.concat([0])));
        obj.writeU8(1);
        obj.add(8).writeU64(raw.length);
        obj.add(0x10).writePointer(buf);
    }
    return obj;
}

function hookAddressGetters() {
    const base = Module.findBaseAddress('libUE4.so');
    const strGet = base.add(GETTER_STR);
    const addrObj = makeStdString(HOST);
    const pathObj = makeStdString(RPC_PATH);
    log('hooking Def_ string getter at ' + strGet);
    log('  ' + KEY_ADDR + ' -> ' + HOST);
    log('  ' + KEY_PATH + ' -> ' + RPC_PATH);
    let nAddr = 0, nPath = 0;
    Interceptor.attach(strGet, {
        onEnter(args) {
            this.hit = 0;
            if (args[0].equals(base.add(KEY_ADDR_VA))) { this.hit = 1; nAddr++; }
            else if (args[0].equals(base.add(KEY_PATH_VA))) { this.hit = 2; nPath++; }
            else {
                try {
                    const k = args[0].readUtf8String(args[1].toInt32());
                    if (k === KEY_ADDR) { this.hit = 1; nAddr++; }
                    else if (k === KEY_PATH) { this.hit = 2; nPath++; }
                } catch (e) { /* not a readable key */ }
            }
        },
        onLeave(retval) {
            if (this.hit === 1) {
                if (nAddr <= 2) log('string getter: address -> ' + HOST);
                retval.replace(addrObj);
            } else if (this.hit === 2) {
                if (nPath <= 2) log('string getter: path -> ' + RPC_PATH);
                retval.replace(pathObj);
            }
        }
    });
    rpc.exports.strHits = function () { return { addr: nAddr, path: nPath }; };
}

// ------------------------------------------------------------ hook the getter
function hookInsecureGetter() {
    const base = Module.findBaseAddress('libUE4.so');
    const target = base.add(GETTER_INT);
    // The key literal lives in the module's read-only segment. If libUE4.so is
    // PIE it is relocated, so the absolute VA is wrong; compare against the
    // relocated address, and fall back to reading the string itself.
    const keyAddr = base.add(KEY_INSECURE_VA);
    const portAddr = base.add(KEY_PORT_VA);
    log('hooking Def_ int getter at ' + target);
    log('key literal expected at ' + keyAddr);
    try {
        log('key literal reads: ' + keyAddr.readUtf8String(KEY_INSECURE.length));
    } catch (e) {
        log('key literal not readable at that address (' + e + ')');
    }
    let matched = 0, nPort = 0;
    Interceptor.attach(target, {
        onEnter(args) {
            this.hit = 0;      // 0 = no match, 1 = insecure, 2 = port
            if (args[0].equals(keyAddr)) { this.hit = 1; }
            else if (args[0].equals(portAddr)) { this.hit = 2; }
            else {
                try {
                    const k = args[0].readUtf8String(args[1].toInt32());
                    if (k === KEY_INSECURE) { this.hit = 1; }
                    else if (k === KEY_PORT) { this.hit = 2; }
                } catch (e) { /* not a readable key, ignore */ }
            }
            if (this.hit === 1) matched++;
            if (this.hit === 2) nPort++;
        },
        onLeave(retval) {
            if (this.hit === 1) {
                if (matched <= 3) log(KEY_INSECURE + ' -> forcing 1 (plaintext gRPC)');
                retval.replace(ptr(1));
            } else if (this.hit === 2) {
                if (nPort <= 3) log(KEY_PORT + ' -> forcing ' + PORT_NUM);
                retval.replace(ptr(PORT_NUM));
            }
        }
    });
    rpc.exports.getterHits = function () { return { insecure: matched, port: nPort }; };
}

// ------------------------------------------------- capture plaintext frames
// With the channel in plaintext, every send() on the konami socket carries
// HTTP/2 frames: the connection preface, SETTINGS, HEADERS, DATA.
//
// We also watch connect() so that, if the Def_ hook above MISSES, the log still
// tells us what the channel did: a first byte of 0x16 means TLS (hook failed)
// and "PRI" means plaintext (hook worked). That distinction is the difference
// between "our approach is wrong" and "our offset is wrong".
const konamiFds = {};
let connectSeen = 0;

function hookConnect() {
    const sym = Module.findExportByName(null, 'connect');
    if (!sym) return;
    Interceptor.attach(sym, {
        onEnter(args) {
            const fd = args[0].toInt32();
            const sa = args[1], len = args[2].toInt32();
            try {
                const family = sa.readU16();
                let ip = '?', port = 0;
                if (family === 2 && len >= 8) {          // AF_INET
                    port = sa.add(2).readU16();
                    const b = [sa.add(4).readU8(), sa.add(5).readU8(),
                               sa.add(6).readU8(), sa.add(7).readU8()];
                    ip = b.join('.');
                } else if (family === 10 && len >= 24) {  // AF_INET6
                    port = sa.add(2).readU16();
                    ip = 'v6';
                }
                connectSeen++;
                if (port === 443) {
                    konamiFds[fd] = { ip: ip, port: port, seen: 0 };
                    if (connectSeen <= 20) {
                        log('connect() fd=' + fd + ' -> ' + ip + ':' + port);
                    }
                }
            } catch (e) { /* ignore */ }
        }
    });
    log('hooked connect');
}

function noteFirstBytes(fd, bytes) {
    const k = konamiFds[fd];
    if (!k || k.seen > 0) return;
    k.seen++;
    const tag = (bytes[0] === 0x50 && bytes[1] === 0x52 && bytes[2] === 0x49)
        ? 'PLAINTEXT h2 preface  -> the Def_ hook WORKED'
        : (bytes[0] === 0x16 ? 'TLS ClientHello       -> the Def_ hook MISSED'
                             : 'unknown first byte 0x' + bytes[0].toString(16));
    log('fd ' + fd + ' (' + k.ip + ':' + k.port + ') first bytes: ' + tag);
    log('   ' + bytes.slice(0, 24).map(function (x) {
        return ('0' + x.toString(16)).slice(-2);
    }).join(' '));
}

function hookSockets() {
    if (hookInstalled) return;
    hookInstalled = true;
    hookConnect();

    ['send', 'sendto', 'write'].forEach(function (name) {
        const sym = Module.findExportByName(null, name) ||
                    Module.findExportByName('libc.so', name);
        if (!sym) return;
        Interceptor.attach(sym, {
            onEnter(args) {
                const fd = args[0].toInt32();
                if (captured > MAX_CAPTURE) return;
                const buf = args[1], len = args[2].toInt32();
                if (len <= 0 || len > 262144) return;

                // always note what a konami socket is doing first
                if (konamiFds[fd]) {
                    try {
                        noteFirstBytes(fd, new Uint8Array(
                            buf.readByteArray(Math.min(len, 24))));
                    } catch (e) { /* ignore */ }
                }

                const head = buf.readByteArray(Math.min(len, 24));
                if (head === null) return;
                const b = new Uint8Array(head);
                const isPreface = b[0] === 0x50 && b[1] === 0x52 && b[2] === 0x49; // "PRI"
                let isFrame = false;
                if (len >= 9) {
                    isFrame = (b[0] & 0x80) !== 0;
                }
                if (!isPreface && !isFrame) return;
                try {
                    const bytes = new Uint8Array(buf.readByteArray(len));
                    captured += len;
                    seq++;
                    const path = DUMP_DIR + '/frame_' + seq + '.bin';
                    const f = new File(path, 'wb');
                    f.write(bytes);
                    f.close();
                    log('captured ' + len + ' B  ' + name + '  fd=' + fd + '  ' +
                        (isPreface ? 'PREFACE' : 'h2 frame type=0x' +
                         bytes[0].toString(16)) + '  -> ' + path);
                    if (seq === 1) {
                        log('first 48 bytes: ' + bytes.slice(0, 48)
                            .map(function (x) {
                                return ('0' + x.toString(16)).slice(-2);
                            }).join(' '));
                    }
                } catch (e) {
                    log('capture failed: ' + e);
                }
            }
        });
        log('hooked ' + name + ' @ ' + sym);
    });
}

function main() {
    const t = setInterval(function () {
        const base = Module.findBaseAddress('libUE4.so');
        if (base === null) return;
        clearInterval(t);
        log('libUE4.so at ' + base);
        try { hookInsecureGetter(); } catch (e) { log('getter hook: ' + e); }
        try { hookAddressGetters(); } catch (e) { log('string getter hook: ' + e); }
        hookSockets();
        log('ready');
    }, 300);
}
setImmediate(main);

rpc.exports = {
    stats: function () { return { captured: captured, frames: seq }; }
};
