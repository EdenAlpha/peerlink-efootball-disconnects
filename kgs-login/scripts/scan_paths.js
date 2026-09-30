// Fallback capture: if forcing plaintext does not take effect, read the
// command `path` straight out of the game's memory instead.
//
// Why this exists: the primary path in capture_insecure.js hooks the Def_
// getters to set Def_Online_gRPC_insecure = 1, which makes the gRPC channel
// plaintext so a send() hook can read the HTTP/2 frames. If that hook misses --
// wrong offset, relocated module, or the key never looked up -- nothing is
// captured, because the frames are inside TLS.
//
// The fallback does not care about TLS. CommandRequest is a protobuf with
// `path` as field 4, and the game builds it in its own heap before handing it
// to TLS. So: scan the writable ranges of the game process for byte sequences
// that decode as a CommandRequest, and report the `path` of any that look real.
//
// A valid CommandRequest ends with field 4 (tag 0x22) holding an ASCII path
// that starts with '/'. That signature is specific enough to search for
// directly, and it is checked by fully decoding the candidate before reporting
// it, so a false positive has to survive a real parse.

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
    return s !== null && s.length >= MIN_PATH && s.length <= MAX_PATH
        && s.charAt(0) === '/' && s.indexOf('\u0000') === -1;
}

const found = Object.create(null);

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
    if (base === null) {
        console.log('[scan] libUE4.so not loaded yet');
        return;
    }
    console.log('[scan] libUE4.so at ' + base + ' - scanning rw- ranges');
    const t0 = Date.now();
    const hits = scan();
    console.log('[scan] done in ' + (Date.now() - t0) + ' ms, ' + hits
        + ' distinct path(s)');
    rpc.exports.scanPaths = function () {
        return Object.keys(found);
    };
    // keep re-scanning, since the path only exists briefly at request time
    let n = 0;
    const t = setInterval(function () {
        n++;
        scan();
        if (n >= 30) clearInterval(t);
    }, 2000);
}

setImmediate(main);
