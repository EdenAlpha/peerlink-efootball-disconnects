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
const KEY_INSECURE    = 'Def_Online_gRPC_insecure';
const KEY_INSECURE_VA = 0xc023be;     // its literal, for a cheap pre-filter

const DUMP_DIR = '/data/local/tmp/kgs';
const MAX_CAPTURE = 4 * 1024 * 1024;

let captured = 0;
let seq = 0;
let hookInstalled = false;

function log(s) { console.log('[kgs] ' + s); }

// ------------------------------------------------------------ hook the getter
function hookInsecureGetter() {
    const base = Module.findBaseAddress('libUE4.so');
    const target = base.add(GETTER_INT);
    // The key literal lives in the module's read-only segment. If libUE4.so is
    // PIE it is relocated, so the absolute VA is wrong; compare against the
    // relocated address, and fall back to reading the string itself.
    const keyAddr = base.add(KEY_INSECURE_VA);
    log('hooking Def_ int getter at ' + target);
    log('key literal expected at ' + keyAddr);
    try {
        log('key literal reads: ' + keyAddr.readUtf8String(KEY_INSECURE.length));
    } catch (e) {
        log('key literal not readable at that address (' + e + ')');
    }
    let matched = 0;
    Interceptor.attach(target, {
        onEnter(args) {
            this.hit = false;
            // cheap path: identical pointer
            if (args[0].equals(keyAddr)) { this.hit = true; }
            else {
                // safe path: compare the actual key text
                try {
                    const k = args[0].readUtf8String(args[1].toInt32());
                    if (k === KEY_INSECURE) { this.hit = true; log('key text matched: ' + k); }
                } catch (e) { /* not a readable key, ignore */ }
            }
            if (this.hit) matched++;
        },
        onLeave(retval) {
            if (this.hit) {
                if (matched <= 3) log(KEY_INSECURE + ' -> forcing 1 (plaintext gRPC)');
                retval.replace(ptr(1));
            }
        }
    });
    rpc.exports.getterHits = function () { return matched; };
}

// ------------------------------------------------- capture plaintext frames
// With the channel in plaintext, every send() on the konami socket carries
// HTTP/2 frames: the connection preface, SETTINGS, HEADERS, DATA.
function hookSockets() {
    if (hookInstalled) return;
    hookInstalled = true;

    ['send', 'sendto', 'sendmsg', 'write', 'writev'].forEach(function (name) {
        const sym = Module.findExportByName(null, name) ||
                    Module.findExportByName('libc.so', name);
        if (!sym) return;
        Interceptor.attach(sym, {
            onEnter(args) {
                if (captured > MAX_CAPTURE) return;
                let buf, len, isSend = true;
                switch (name) {
                    case 'send':    buf = args[1]; len = args[2].toInt32(); break;
                    case 'sendto':  buf = args[1]; len = args[2].toInt32(); break;
                    case 'sendmsg': return;                     // msghdr, skip
                    case 'write':   buf = args[1]; len = args[2].toInt32(); break;
                    case 'writev':  return;                     // iovec, skip
                    default: return;
                }
                if (len <= 0 || len > 262144) return;
                // only plaintext HTTP/2: the preface, or a frame header
                const head = buf.readByteArray(Math.min(len, 24));
                if (head === null) return;
                const b = new Uint8Array(head);
                const isPreface = b[0] === 0x50 && b[1] === 0x52 && b[2] === 0x49; // "PRI"
                let isFrame = false;
                if (len >= 9) {
                    const t = b[0];
                    // DATA/CONTROL frame types have the high bit set
                    isFrame = (t & 0x80) !== 0;
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
                    log('captured ' + len + ' B  ' + name + '  ' +
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
        hookSockets();
        log('ready');
    }, 300);
}
setImmediate(main);

rpc.exports = {
    stats: function () { return { captured: captured, frames: seq }; }
};
