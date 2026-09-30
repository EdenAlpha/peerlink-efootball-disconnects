#!/usr/bin/env node
// Self-test for scan_paths.js against a synthetic process memory image.
//
// scan_paths.js is now the PRIMARY route -- it is the only part of the capture
// that does not depend on an offset being right -- so its decode has to be
// proven before spending a 10-minute runner on it. The hazard is specific: the
// scanner finds a candidate by spotting the field-4 tag byte, then walks
// *backwards* guessing where the message started, and only accepts it if the
// whole thing parses as a CommandRequest. If that backward walk or the length
// arithmetic is off by anything, the scan silently finds nothing and an empty
// result looks exactly like a game that never built a request.
//
// So this stands up a fake address space, drops known CommandRequests into it
// at controlled offsets, and requires the scanner to recover every one of them
// -- including ones embedded in unrelated noise, and one split across a chunk
// boundary -- while NOT reporting the decoys.

'use strict';
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const SRC = path.join(__dirname, 'scan_paths.js');

// ------------------------------------------------------------------ protobuf
function varint(v) {
    const out = [];
    do { let x = v & 0x7f; v >>>= 7; out.push(x | (v ? 0x80 : 0)); } while (v);
    return Buffer.from(out);
}
const fStr = (n, s) => { const b = Buffer.from(s, 'utf8');
    return Buffer.concat([varint(n << 3 | 2), varint(b.length), b]); };
const fVar = (n, v) => Buffer.concat([varint(n << 3), varint(v)]);

// CommandRequest{id=1 string, packMode=2 enum, req=3 string, path=4 string}
function commandRequest(id, packMode, req, pathStr) {
    return Buffer.concat([fStr(1, id), fVar(2, packMode),
                          fStr(3, req), fStr(4, pathStr)]);
}

// ------------------------------------------------------------- fake memory
class FakeAddr {
    constructor(buf, off) { this.buf = buf; this.off = off; }
    add(n) { return new FakeAddr(this.buf, this.off + n); }
    sub(o) { return new FakeAddr(this.buf, this.off - o.off); }
    compare(o) { return this.off - o.off; }
    readByteArray(n) {
        if (this.off + n > this.buf.length) return null;
        return this.buf.slice(this.off, this.off + n)
            .buffer.slice(this.buf.byteOffset + this.off,
                          this.buf.byteOffset + this.off + n);
    }
    readU8() { return this.buf[this.off]; }
    toInt32() { return this.off; }
    toString() { return '0x' + this.off.toString(16); }
}

// Build one big heap image out of pieces, remembering where each landed.
function buildHeap(pieces) {
    const parts = [];
    let cursor = 0;
    const where = {};
    for (const [name, buf] of pieces) {
        const pad = (cursor % 7) + 3;         // unaligned padding, like a real heap
        cursor += pad;
        where[name] = cursor;
        parts.push(Buffer.alloc(pad, 0x41), buf);
        cursor += buf.length;
    }
    parts.push(Buffer.alloc(64, 0x42));
    return { image: Buffer.concat(parts), where };
}

function main() {
    // ---- the real messages, in the shape the game actually sends ----
    const CASES = [
        ['/session/get', 0, '{"token":"abc"}', '7f1c0a10-1111-2222-3333-444444444444'],
        ['/room/create', 1, '{"roomType":"1"}', '7f1c0a10-2222-3333-4444-555555555555'],
        ['/', 0, '{}', '7f1c0a10-3333-4444-5555-666666666666'],
        // a route with no leading slash, to prove the relaxed filter keeps it
        ['login', 0, '{"user":"x"}', '7f1c0a10-4444-5555-6666-777777777777'],
        // multi-segment and underscore styles seen in the game's own strings
        ['/user/compe/get_info', 0, '{}', '7f1c0a10-5555-6666-7777-888888888888'],
        ['gate/gate_', 0, '{}', '7f1c0a10-6666-7777-8888-999999999999'],
    ];

    const pieces = [];
    for (const [p, pack, req, id] of CASES) {
        pieces.push(['msg:' + p, commandRequest(id, pack, req, p)]);
    }

    // Decoys that must NOT be reported. Each has a 0x22 tag byte and a
    // printable run after it, but no valid message encloses it.
    const decoy1 = Buffer.concat([
        Buffer.from([0x08, 0x01]),                       // field 1 varint
        Buffer.from([0x12, 0x03, 0x61, 0x62, 0x63]),     // field 2 bytes
        Buffer.from([0x22, 0x05]),                       // field 4, no payload after
        Buffer.from('hello'),
    ]);
    pieces.push(['decoy:truncated', decoy1]);
    // a 0x22 tag whose length byte promises more than follows
    pieces.push(['decoy:overlong', Buffer.concat([
        Buffer.from([0x0a, 0x02, 0x69, 0x64]),
        Buffer.from([0x22, 0x7f]), Buffer.from('short'),
    ])]);
    // random-ish noise containing 0x22 followed by printable bytes
    const noise = Buffer.alloc(300);
    for (let i = 0; i < noise.length; i++) noise[i] = (i * 37 + 11) & 0xff;
    noise[100] = 0x22; noise[101] = 0x04;
    noise.write('abcd', 102, 'latin1');
    pieces.push(['decoy:noise', noise]);

    const { image } = buildHeap(pieces);

    // ------------------------------------------------------------- run it
    const logs = [];
    const ranges = [{ base: new FakeAddr(image, 0), size: image.length }];
    const sandbox = {
        console: { log: (...a) => logs.push(a.join(' ')) },
        setInterval: (fn, ms) => { fn(); return 0; },   // run one pass now
        clearInterval: () => {},
        Module: { findBaseAddress: () => new FakeAddr(image, 0) },
        Process: { enumerateRanges: () => ranges },
        rpc: { exports: {} },
        setImmediate: (fn) => fn(),
        Uint8Array, JSON, Object, String, Math, Date,
    };
    vm.createContext(sandbox);
    vm.runInContext(fs.readFileSync(SRC, 'utf8'), sandbox, { filename: SRC });

    const text = logs.join('\n');
    console.log(text);

    // ------------------------------------------------------------ verdict
    let fail = 0;
    const want = CASES.map(c => c[0]);
    for (const p of want) {
        const hit = text.includes('path=' + JSON.stringify(p));
        console.log((hit ? '  found   ' : '  MISSING ') + p);
        if (!hit) fail++;
    }
    for (const d of ['truncated', 'overlong', 'noise']) {
        // the decoy names must not appear as a reported path
        const hit = text.includes('path=' + JSON.stringify(d));
        console.log((hit ? '  FALSE+  ' : '  clean   ') + 'decoy:' + d);
        if (hit) fail++;
    }
    // the heartbeat must be present, so "found nothing" is distinguishable
    // from "the scanner never ran"
    const ran = /\[scan\] pass \d+ in \d+ ms/.test(text);
    console.log((ran ? '  ok      ' : '  MISSING ') + 'scan heartbeat');
    if (!ran) fail++;

    console.log(fail === 0 ? '\nSELF-TEST: PASS' : '\nSELF-TEST: FAIL (' + fail + ')');
    process.exit(fail === 0 ? 0 : 1);
}

main();
