// Fallback capture: if forcing plaintext does not take effect, read the
// command `path` straight out of the game's memory instead.
//
// Why this exists, and why it is now the PRIMARY route: the plan was to hook
// the Def_ getter for Def_Online_gRPC_insecure and make the gRPC channel
// plaintext so a send() hook could read the HTTP/2 frames. That hook is wrong.
// The offsets recorded for the int and string getters (0x2f0eaf0 and
// 0x2f0e18c) are *both* std::string constructors -- each has the libc++ SSO
// compare at 0x17, the `2*len|is_long` size byte, an `operator new` for the
// long form and a {size, ptr} store. Neither can be overriding an int config
// value, and there are seven copies of the same string getter, so the accessors
// look inlined at their call sites rather than shared, which leaves no single
// int getter to hook. Forcing plaintext that way is not going to work.
//
// This route does not care about TLS or about any of those offsets.
// CommandRequest is a protobuf with `path` as field 4, and the game builds it
// in its own heap before handing it to TLS. So: scan the writable ranges of the
// game process for byte sequences that decode as a CommandRequest, and report
// the `path` of any that parse cleanly.
//
// A valid candidate ends at field 4 (tag 0x22) holding a short printable ASCII
// string. That is specific enough to search for directly, and every candidate
// is fully decoded before being reported, so a false positive has to survive a
// real parse.

'use strict';

const CMD_REQ_PATH_TAG = 0x22;      // field 4, wire type 2 (length-delimited)
const MIN_PATH = 2;
const MAX_PATH = 96;

function uvarint(p) {
    let v = 0, shift = 0, i = 0;
    for (; i < 10; i++) {
        const b = p.add(i).readU8();
        v |= (b & 0x7f) << shift;
        if (!(b & 0x80)) return { value: v, length: i + 1 };
        shift += 7;
    }
    return null;
}

// Fully decode a candidate CommandRequest. Returns {id, packMode, req, path} or
// null if it does not parse cleanly as one.
function decodeCommandRequest(p, len) {
    const out = { id: null, packMode: null, req: null, path: null };
    let i = 0;
    while (i < len) {
        const k = uvarint(p.add(i));
        if (!k) return null;
        i += k.length;
        const fn = k.value >> 3, wt = k.value & 7;
        if (fn < 1 || fn > 4) return null;
        if (wt === 2) {
            const l = uvarint(p.add(i));
            if (!l) return null;
            i += l.length;
            if (i + l.value > len) return null;
            const bytes = p.add(i).readByteArray(l.value);
            if (bytes === null) return null;
            const s = latin(bytes);
            if (fn === 1) out.id = s;
            else if (fn === 3) out.req = s;
            else if (fn === 4) out.path = s;
            i += l.value;
        } else if (wt === 0) {
            const v = uvarint(p.add(i));
            if (!v) return null;
            if (fn === 2) out.packMode = v.value;
            i += v.length;
        } else {
            return null;
        }
    }
    return out.path !== null ? out : null;
}

function latin(buf) {
    const a = new Uint8Array(buf);
    let s = '';
    for (let i = 0; i < a.length; i++) {
        const c = a[i];
        if (c < 0x20 || c > 0x7e) return null;
        s += String.fromCharCode(c);
    }
    return s;
}

function looksLikePath(s) {
    // Deliberately does NOT require a leading '/'. The one route confirmed so
    // far is "/", but a route need not be slash-prefixed, and rejecting
    // candidates on that assumption would discard the thing being hunted.
    return s !== null && s.length >= MIN_PATH && s.length <= MAX_PATH
        && s.indexOf('\u0000') === -1;
}

const found = Object.create(null);
let bytesScanned = 0;
let passes = 0;

function scan() {
    const ranges = Process.enumerateRanges('rw-');
    let hits = 0;
    ranges.forEach(function (r) {
        let addr = r.base;
        const end = r.base.add(r.size);
        // read in chunks so a huge range does not blow up
        const CHUNK = 1024 * 512;
        while (addr.compare(end) < 0) {
            const remain = end.sub(addr).toInt32();
            const n = Math.min(CHUNK, remain);
            if (n <= 0) break;
            let buf;
            try {
                buf = addr.readByteArray(n);
            } catch (e) {
                addr = addr.add(n);
                continue;
            }
            if (buf) {
                const a = new Uint8Array(buf);
                for (let i = 0; i + 2 < a.length; i++) {
                    if (a[i] !== CMD_REQ_PATH_TAG) continue;
                    const cand = addr.add(i);
                    // the length byte follows the tag
                    const plen = a[i + 1];
                    if (plen < MIN_PATH || plen > MAX_PATH) continue;
                    // walk back over the preceding fields to find the start
                    for (let back = 2; back <= 96; back++) {
                        if (i - back < 0) break;
                        const start = addr.add(i - back);
                        const cr = decodeCommandRequest(start, back + 2 + plen);
                        if (cr && looksLikePath(cr.path)) {
                            const key = cr.path;
                            if (!found[key]) {
                                found[key] = { packMode: cr.packMode,
                                               req: cr.req, id: cr.id, n: 1 };
                                hits++;
                                console.log('[scan] path=' + JSON.stringify(cr.path)
                                    + '  packMode=' + cr.packMode
                                    + '  id=' + JSON.stringify(cr.id)
                                    + '  req=' + JSON.stringify(cr.req));
                            } else {
                                found[key].n++;
                            }
                            break;
                        }
                    }
                }
            }
            addr = addr.add(n);
        }
    });
    return hits;
}

function main() {
    const base = Module.findBaseAddress('libUE4.so');
    const total = Process.enumerateRanges('rw-')
        .reduce(function (a, r) { return a + r.size; }, 0);
    console.log('[scan] libUE4.so at ' + base);
    console.log('[scan] rw- ranges: ' + total + ' bytes total');
    // Keep re-scanning: the serialized request only exists for the moment it
    // takes to hand it to the transport, so a single pass can easily miss the
    // bootstrap commands. A heartbeat per pass makes an empty result
    // distinguishable from a scanner that never ran at all.
    const t = setInterval(function () {
        passes++;
        const t0 = Date.now();
        scan();
        console.log('[scan] pass ' + passes + ' in ' + (Date.now() - t0)
            + ' ms, ' + (bytesScanned / 1048576).toFixed(1)
            + ' MB scanned, ' + Object.keys(found).length + ' distinct path(s)');
        if (passes >= 24) {
            clearInterval(t);
            console.log('[scan] finished; paths: '
                + JSON.stringify(Object.keys(found)));
        }
    }, 1500);
}

setImmediate(main);
