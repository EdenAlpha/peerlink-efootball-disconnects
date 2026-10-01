// Read every gate request in plaintext, and the AES key, from inside the app.
//
// Loaded by frida-jdwp-loader over JDWP, in `-i script` mode, so it runs
// autonomously inside the target process with no frida-server and no ptrace.
// Output goes to logcat via __android_log_write, which the live loop reads with
// `adb logcat -d -s KGSHOOK`.
//
// Why JDWP and not frida-server: frida-server injects by ptrace, and on this
// redroid image that aborts -- "Aborted (core dumped)" on both 17.19.0 and
// 16.7.19, on spawn and attach. JDWP loads the gadget over the app's debug
// socket instead, and the APK already ships android:debuggable=true.
//
// The app's own memory names the pipeline:
//
//     SendRequest(uri, useGzip, cookie, data, isPost)
//       useGzip = true
//       setRequestProperty pes-custom-encrypt:AES256
//
// so `data` is the form-urlencoded plaintext BEFORE gzip and BEFORE AES. Hooking
// that one method is the whole capture; the cipher hooks are there to recover
// the key and to catch anything that does not go through it.

'use strict';

var TAG = 'KGSHOOK';

function emit(msg) {
    try {
        var Log = Java.use('android.util.Log');
        Log.e(TAG, String(msg));
    } catch (e) {
        // logcat unavailable; swallow rather than break the hook
    }
}

function hex(bytes) {
    var out = '';
    for (var i = 0; i < bytes.length && i < 512; i++) {
        var h = (bytes[i] & 0xff).toString(16);
        out += h.length === 1 ? '0' + h : h;
    }
    return out;
}

function asText(bytes) {
    try {
        var S = Java.use('java.lang.String');
        return S.$new(bytes, 'UTF-8').toString();
    } catch (e) {
        return '<binary ' + bytes.length + ' bytes>';
    }
}

Java.perform(function () {
    emit('=== KGSHOOK attached, pid ' + Process.id + ' ===');

    // ---- 1. the AES key, taken at the moment it is handed to the cipher ----
    try {
        var SKS = Java.use('javax.crypto.spec.SecretKeySpec');
        SKS.getEncoded.implementation = function () {
            var b = this.getEncoded();
            emit('KEY alg=' + this.getAlgorithm() + ' len=' + b.length + ' hex=' + hex(b));
            return b;
        };
        emit('hooked SecretKeySpec.getEncoded');
    } catch (e) {
        emit('KEY hook failed: ' + e);
    }

    // ---- 2. cipher input/output, as a cross-check on the key ----
    try {
        var Cipher = Java.use('javax.crypto.Cipher');
        var of = Cipher.doFinal.overload('[B');
        of.implementation = function (input) {
            var res = of.call(this, input);
            try {
                emit('CIPHER in=' + (input ? input.length : 0) +
                     ' out=' + (res ? res.length : 0) +
                     ' cipher=' + this.getAlgorithm());
            } catch (e2) {}
            return res;
        };
        emit('hooked Cipher.doFinal([B)');
    } catch (e) {
        emit('CIPHER hook failed: ' + e);
    }

    // ---- 3. the request itself: this is the plaintext we want ----
    var hooked = 0;
    var targets = [
        'jp.konami.android.common.HttpImpl',
        'jp.konami.android.common.HttpRequest',
        'jp.konami.android.common.Cronet'
    ];
    targets.forEach(function (name) {
        var cls;
        try {
            cls = Java.use(name);
        } catch (e) {
            return;
        }
        ['SendRequest', 'sendRequest', 'Post', 'post'].forEach(function (m) {
            if (!cls[m]) return;
            var ovl = cls[m].overloads;
            for (var i = 0; i < ovl.length; i++) {
                (function (o) {
                    o.implementation = function () {
                        var parts = [];
                        for (var a = 0; a < arguments.length; a++) {
                            var v = arguments[a];
                            if (v === null || v === undefined) {
                                parts.push('null');
                            } else if (v.$className === '[B') {
                                parts.push('bytes[' + v.length + ']');
                            } else {
                                try { parts.push(String(v)); } catch (e3) { parts.push('?'); }
                            }
                        }
                        emit('REQ ' + name + '.' + m + '(' + parts.join(', ') + ')');
                        // The byte[] argument is the plaintext body. Dump it.
                        for (var b = 0; b < arguments.length; b++) {
                            var x = arguments[b];
                            if (x && x.$className === '[B' && x.length > 0) {
                                emit('BODY[' + b + '] len=' + x.length +
                                     ' text=' + asText(x).slice(0, 1200));
                                emit('BODYHEX[' + b + '] ' + hex(x).slice(0, 1024));
                            }
                        }
                        return o.apply(this, arguments);
                    };
                    hooked++;
                })(ovl[i]);
            }
        });
        emit('hooked into ' + name);
    });
    emit('=== ' + hooked + ' method hooks installed ===');

    // ---- 4. device identity, which the login payload carries ----
    try {
        var GDH = Java.use('jp.konami.GetDeviceHash');
        GDH.getHashedWidevineId.implementation = function () {
            var v = this.getHashedWidevineId();
            emit('WIDEVINE ' + v);
            return v;
        };
        emit('hooked GetDeviceHash.getHashedWidevineId');
    } catch (e) {
        emit('WIDEVINE hook skipped: ' + e);
    }
});
