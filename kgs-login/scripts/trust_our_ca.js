// Make eFootball trust OUR certificate, so mitmproxy can read the gRPC
// request in cleartext.
//
// Decoded from libUE4.so 11.0.1 (identical to the build on the phone):
//
//   0x7b101f8  the gRPC config loader:
//        bl 0x2f0eaf0("Def_Online_gRPC_insecure",      0x18)
//        bl 0x2f0eaf0("Def_Online_gRPC_debug_root_ca",  0x1d)
//        if (debug_root_ca != 0) {
//            read std::string at 0xa4a8480            <-- the CA file path
//            ... put it into the grpc channel args
//        }
//
//   0x2f0eaf0  int getter, called as (x0 = key bytes, x1 = key length).
//
// So: return 1 for that one key, and point the global string at our CA.
// Both are tiny, and neither needs the APK to be re-signed.

'use strict';

const GETTER_INT      = 0x2f0eaf0;   // int Def_ lookup
const G_ROOT_CA_STR   = 0xa4a8480;   // std::string: root CA path
const KEY_DEBUG_CA    = 'Def_Online_gRPC_debug_root_ca';
const CA_PATH         = '/data/local/tmp/mitm-ca.pem';

// ---------------------------------------------------------------- helpers
function readCString(ptr) {
    try {
        if (ptr.isNull()) return '';
        return ptr.readCString() || '';
    } catch (e) { return ''; }
}

// libc++ std::string in the game's memory: flag byte then inline data
// (bit0 of byte0 set => long form: {size@+8, ptr@+0x10}).
function writeStdString(addr, text) {
    const raw = Array.from(text).map(c => c.charCodeAt(0));
    if (raw.length <= 22) {
        addr.writeU8(raw.length << 1);
        for (let i = 0; i < raw.length; i++) addr.add(1 + i).writeU8(raw[i]);
        for (let i = raw.length; i < 23; i++) addr.add(1 + i).writeU8(0);
        addr.add(8).writeU64(0);
        addr.add(0x10).writeU64(0);
        return;
    }
    // long form: allocate a buffer via the game's own allocator
    const buf = Memory.alloc(raw.length + 1);
    for (let i = 0; i < raw.length; i++) buf.add(i).writeU8(raw[i]);
    buf.add(raw.length).writeU8(0);
    addr.writeU8(1);
    addr.add(8).writeU64(raw.length);
    addr.add(0x10).writePointer(buf);
}

function hookGetter() {
    const target = Module.findBaseAddress('libUE4.so').add(GETTER_INT);
    console.log('[def] hooking int getter at', target);
    Interceptor.attach(target, {
        onEnter(args) {
            // x0 = key bytes, x1 = key length (NOT NUL-terminated)
            const key = args[0].readUtf8String(args[1].toInt32());
            this.key = key;
            if (key === KEY_DEBUG_CA) {
                console.log('[def] ' + KEY_DEBUG_CA + ' -> forcing 1');
                this.force = 1;
            }
        },
        onLeave(retval) {
            if (this.force) {
                console.log('[def] overriding return: 0 -> 1');
                retval.replace(ptr(1));
            }
        }
    });
}

function setRootCa() {
    const base = Module.findBaseAddress('libUE4.so');
    const strAddr = base.add(G_ROOT_CA_STR);
    console.log('[def] writing root CA path to', strAddr, '->', CA_PATH);
    writeStdString(strAddr, CA_PATH);
    console.log('[def] verify byte0 =', strAddr.readU8());
}

function main() {
    // wait for the real libUE4.so to be mapped (it is loaded late)
    const timer = setInterval(() => {
        const base = Module.findBaseAddress('libUE4.so');
        if (base === null) return;
        clearInterval(timer);
        console.log('[def] libUE4.so at', base);
        setRootCa();
        hookGetter();
        console.log('[def] ready - the game should now trust ' + CA_PATH);
    }, 500);
}

rpc.exports = {
    status() {
        const base = Module.findBaseAddress('libUE4.so');
        return {
            libue4: base ? base.toString() : null,
            root_ca_flag: base ? base.add(G_ROOT_CA_STR).readU8() : null
        };
    }
};

setImmediate(main);
