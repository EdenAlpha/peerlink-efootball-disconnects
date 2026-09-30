/**
 * PeerLink M19 frida agent — the non-UI puppet layer.
 *
 * Attach to the RUNNING genuine eFootball process (jp.konami.pesam) on
 * YOUR emulator/device via frida-server. The app keeps doing 100% of
 * its own networking, auth, room creation and match traffic — this agent
 * only READS the flow and (later) writes engine-level inputs.
 *
 * Everything below is offset-driven against libUE4.so v11.0.1 — the
 * exact build the peerlink RE tree maps (FINDINGS.md M1-M17). Offsets
 * are vaddrs; the agent resolves the module base at runtime.
 *
 *   0x74e38c4  KGS request submit   — every outbound Cmd*.php funnels
 *                                      here (328 builders share it).
 *                                      Reading the msgid = the flow
 *                                      state machine, no vision needed.
 *   0x74e3510  KGS response parser  — response document reconstruction
 *                                      (room code discovery, guest-join
 *                                      detection, match lifecycle).
 *   0x2f92514  std::map insert-by-name (response window filter)
 *   0x2f913c8  string variant wrap     \  logged during the response
 *   0x2f9135c  int variant wrap        /  window => full doc rebuild
 *   0x69917d8  MatchMain state machine — in-match state byte [obj+0x139]
 *   0x813fe80 / 0x81604f4  singleton candidates holding MatchMain obj
 *   0xa417188  input bank singleton *(ptr) — 0x1C070 bytes: 1200-frame
 *                                      input history ring, .trep-format
 *                                      records (24 x 0x3A) + analog +
 *                                      camera; command pool at +0xD488.
 *   0x6a00e50  110-command dispatcher  — match-setup lane (M9/M10 proofs)
 *
 * DISCOVERY vs PINNED (honest state of the RE):
 *   pinned:  submit/response hook points, dispatcher, input bank
 *            singleton, state machine entry + state-byte offset.
 *   discovery (this agent does it on the first real run):
 *            - the exact response field carrying the 6-digit room code
 *            - which singleton actually holds the live MatchMain obj
 *            - the input-bank write slot (diff tooling included: dump
 *              while a human plays, diff consecutive dumps)
 *
 * Messages to host (send()):  {type:...} on the 'peerlink' channel:
 *   kgs_req      {msgid}
 *   kgs_doc      {msgid, doc}            (reconstructed response doc)
 *   state        {singleton, value}      (MatchMain state byte)
 *   bank_diff    {slot, prev, cur}      (input-bank write-point hunt)
 *   log          {msg}
 */
'use strict';

const OFF = {
  kgsSubmit:      0x74e38c4,
  kgsRespParse:   0x74e3510,
  mapInsert:      0x2f92514,
  strVariant:     0x2f913c8,
  intVariant:     0x2f9135c,
  matchMainSM:    0x69917d8,
  singletonA:    0x813fe80,
  singletonB:    0x81604f4,
  inputBankPtr:   0xa417188,
  dispatcher:     0x6a00e50,
};

const BANK_SIZE = 0x1c070;

let mod = null;          // Module for libUE4.so
let inResponseWindow = false;
let responseDoc = null;  // {key: value} being rebuilt
let lastMsgid = null;
const stateWatchers = [];
const bankWatch = { last: null, watching: false, slotLen: 8, span: 0x400 };

function log(m) { send({ type: 'log', msg: m }); }

// --- libc++ SSO string read (for map keys / msgid) --------------------
function readSSO(p) {
  // libc++ short-string: byte0 = len<<1 (low bit 0), data at p+1
  // long form: byte0 low bit 1 -> {cap,sz,ptr} — handle both
  const b0 = p.readU8();
  if ((b0 & 1) === 0) {
    const len = b0 >> 1;
    if (len === 0 || len > 22) return null;
    try { return p.add(1).readUtf8String(len); } catch (e) { return null; }
  }
  try {
    const sz = p.add(8).readULong();
    if (sz === 0 || sz > 4096) return null;
    const data = p.add(16).readPointer();
    return data.readUtf8String(sz);
  } catch (e) { return null; }
}

// Scan a std::map<string,variant>'s node region for the msgid value:
// any SSO string matching /^Cmd[A-Za-z]+\.php$/. Map layout discovery
// aid only — after the first run we pin the exact node offset.
function scanForMsgid(mapObj) {
  try {
    const out = [];
    const buf = mapObj.readByteArray(0x180);
    if (!buf) return null;
    const u8 = new Uint8Array(buf);
    let i = 0;
    while (i < u8.length - 4) {
      // candidate SSO string "Cmd..." : len byte = 2*len, then 'C','m','d'
      if (u8[i] >= 8 && u8[i] <= 44 && (u8[i] & 1) === 0 &&
          u8[i+1] === 0x43 && u8[i+2] === 0x6d && u8[i+3] === 0x64) {
        const len = u8[i] >> 1;
        if (i + 1 + len <= u8.length) {
          let s = '';
          for (let k = 0; k < len; k++) s += String.fromCharCode(u8[i + 1 + k]);
          if (/^Cmd[A-Za-z]+\.php$/.test(s)) out.push({ off: i, msgid: s });
        }
      }
      i++;
    }
    return out.length ? out[out.length - 1] : null; // last = the value, not the "msgid" key
  } catch (e) { return null; }
}

// --- hooks --------------------------------------------------------------
function installKgsHooks(base) {
  // outbound: every request passes through the shared submit
  Interceptor.attach(base.add(OFF.kgsSubmit), {
    onEnter(args) {
      const m = scanForMsgid(args[0]);
      if (m && m.msgid !== lastMsgid) {
        lastMsgid = m.msgid;
        send({ type: 'kgs_req', msgid: m.msgid });
      } else if (m) {
        send({ type: 'kgs_req', msgid: m.msgid });  // repeats matter (polling)
      }
    }
  });

  // inbound: response parse; open a window during which map inserts are
  // logged => full response document reconstruction
  Interceptor.attach(base.add(OFF.mapInsert), {
    onEnter(args) {
      if (!inResponseWindow) return;
      const key = readSSO(args[1]);
      if (!key) return;
      if (!responseDoc) responseDoc = {};
      responseDoc[key] = '<pending>';
      this.key = key;
    },
    onLeave(rv) {
      if (!inResponseWindow || !this.key) return;
      // value land: try to read it back from the tree after insert —
      // best-effort; ints come via the int-variant hook instead
    }
  });

  Interceptor.attach(base.add(OFF.strVariant), {
    onEnter(args) {
      if (!inResponseWindow) return;
      const s = readSSO(args[0]);
      if (s && responseDoc) {
        for (const k of Object.keys(responseDoc)) {
          if (responseDoc[k] === '<pending>') { responseDoc[k] = s; break; }
        }
      }
    }
  });

  Interceptor.attach(base.add(OFF.intVariant), {
    onEnter(args) {
      if (!inResponseWindow) return;
      if (responseDoc) {
        for (const k of Object.keys(responseDoc)) {
          if (responseDoc[k] === '<pending>') {
            responseDoc[k] = args[1].toInt32(); break;
          }
        }
      }
    }
  });

  Interceptor.attach(base.add(OFF.kgsRespParse), {
    onEnter(args) {
      inResponseWindow = true;
      responseDoc = null;
    },
    onLeave(rv) {
      inResponseWindow = false;
      if (responseDoc && lastMsgid) {
        send({ type: 'kgs_doc', msgid: lastMsgid, doc: responseDoc });
      }
      responseDoc = null;
    }
  });
}

// --- state byte ----------------------------------------------------------
function readMatchStateFrom(singletonOff) {
  try {
    const obj = mod.base.add(singletonOff).readPointer();
    if (obj.isNull() || obj.equals(ptr(0))) return null;
    const v = obj.add(0x139).readU8();
    if (v > 10) return null;           // 11 states (0..10) — sanity filter
    return { addr: obj.toString(), value: v };
  } catch (e) { return null; }
}

// --- input bank -----------------------------------------------------------
function bankObj() {
  try {
    const p = mod.base.add(OFF.inputBankPtr).readPointer();
    if (p.isNull()) return null;
    return p;
  } catch (e) { return null; }
}

// --- rpc ------------------------------------------------------------------
rpc.exports = {
  ping() {
    return { module: mod !== null, base: mod ? mod.base.toString() : null,
             app: 'eFootball 11.0.1 (jp.konami.pesam)' };
  },

  // MatchMain state candidates — discovery: run during a real match,
  // the one that counts 0..10 and transitions is the live singleton.
  stateCandidates() {
    const a = readMatchStateFrom(OFF.singletonA);
    const b = readMatchStateFrom(OFF.singletonB);
    return { A: a, B: b };
  },

  // raw dump of the input bank head region (write-point hunt)
  bankHead() {
    const b = bankObj();
    if (!b) return null;
    return b.add(0).readByteArray(0x100);
  },

  // diff tooling: hexdump the first `span` of the bank; the host diffs
  // consecutive dumps while a human plays — the churn region is the
  // live write slot; then bankWrite() targets it.
  bankWatchDump() {
    const b = bankObj();
    if (!b) return null;
    return b.readByteArray(bankWatch.span);
  },

  bankWatchConfig(span, slotLen) {
    if (span) bankWatch.span = span;
    if (slotLen) bankWatch.slotLen = slotLen;
  },

  // engine-level input injection (post-discovery): write raw bytes at a
  // bank-relative offset. Host validates the .trep record format.
  bankWrite(off, hex) {
    const b = bankObj();
    if (!b) return false;
    const bytes = [];
    for (let i = 0; i < hex.length; i += 2)
      bytes.push(parseInt(hex.substr(i, 2), 16));
    b.add(off).writeByteArray(bytes);
    return true;
  },

  // dispatcher call (match-setup lane, M9-proven): cmd id 0..0x6c
  dispatch(cmd, a1, a2) {
    const fn = new NativeFunction(mod.base.add(OFF.dispatcher),
                                  'void', ['pointer', 'int', 'pointer']);
    // NOTE: arg shape from M9 driver — refined after first on-device run.
    fn(ptr(0), cmd, ptr(a2 || 0));
    return true;
  },
};

// --- main ------------------------------------------------------------------
function main() {
  mod = Process.findModuleByName('libUE4.so');
  if (!mod) {
    // some builds expose it under the app dir — retry once
    for (const m of Process.enumerateModules()) {
      if (m.name.indexOf('libUE4') !== -1) { mod = m; break; }
    }
  }
  if (!mod) { log('FATAL: libUE4.so not found in process'); return; }
  log('libUE4.so base = ' + mod.base + ' size=' + mod.size);
  if (Math.abs(mod.size - 160 * 1024 * 1024) > 40 * 1024 * 1024) {
    log('WARN: module size ' + mod.size + ' differs from the mapped build '
        + '(~160MB) — offsets are for v11.0.1, verify the app version');
  }
  installKgsHooks(mod.base);
  log('hooks installed: kgs submit/response + variant capture');

  // periodic state-byte beacon
  setInterval(() => {
    const a = readMatchStateFrom(OFF.singletonA);
    const b = readMatchStateFrom(OFF.singletonB);
    if (a) send({ type: 'state', singleton: 'A', value: a.value });
    if (b) send({ type: 'state', singleton: 'B', value: b.value });
  }, 1000);
}

main();
