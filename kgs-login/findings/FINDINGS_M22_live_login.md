# FINDINGS M22 — live login attempt & URL resolution

Date: 2026-09-27
Tree: `C:\Users\Administrator\AppData\Local\Temp\2\opencode\peerlink_work\`

---

## 1. The login attempt — what Konami actually said

The game's own bootstrap request, byte-exact (`peerlink/kgs.py: gate_info()`),
posted to the hardcoded URL from `libUE4.so`:

```
POST http://ntl.service.konami.net/ntl/api/GateInfo.php
body: req=<lowercase-hex of {"titleCode":"pes22","locale":"en","version":"dt270","extra":"","apiLevel":1}>

HTTP 200
STATUS: 200
API_STATUS: 1
LOG_ACTIVE: 1
SERVER_TIME: 1790533650
PUT_LOG_URL: http://ntljp2.service.konami.net/ntl/api/general/ReportLog.php
```

**This works.** `STATUS: 200` is the server's success code, `API_STATUS: 1`
means the service is up, and `SERVER_TIME` agrees with the real clock.

Parameter validation observed:
* `titleCode=XWW020-E1` → connection reset (rejected)
* `version=""` → connection reset (rejected)
* `titleCode=pes22` + `version=dt270` → 200 (correct)

This is step 1 of the handshake. The *next* step (the `Cmd*.php` commands)
is where it stops — see §4.

---

## 2. The full set of servers the client can use (closed list)

A regex sweep of every hostname and absolute URL in `libUE4.so` returns
**5 hostnames and 4 absolute URLs total**. This list is exhaustive.

| host | path in binary | status |
|---|---|---|
| `ntl.service.konami.net` | `/ntl/api/GateInfo.php` | **LIVE, 200, works** |
| `info.service.konami.net` | `/XWW020-E1/info/` | dir exists (403), **empty of every name tried** |
| `pes22-game.cs.konami.net` | *(host only; path from config)* | nginx, `/` `/pes22/` `/pes22/gate/` exist |
| `pesam.stun.service.konami.net` | — | STUN only |
| `www.konami.com` | `/ja`, `/efootball/mobile_support/` | support links, not API |

No other host exists in the binary. Nothing to guess at here any more.

---

## 3. Server tree actually mapped

**`ntl.service.konami.net` (Apache — clean oracle: 200 exists / 403 dir / 404 missing)**

* `/ntl/api/GateInfo.php` → 200, `STATUS: 400` on bare GET, `STATUS: 200` on correct POST
* `/ntl/api/general/ReportLog.php` → 200
* `/ntl/api/PES2022/ReportLog.php` → 200
* `/ntl/api/config/` → 403 (exists)
* everything else → 404

**`pes22-game.cs.konami.net` (nginx + php-fpm, chunked)**
Oracle: body `File not found.` = script missing; nginx HTML 404 = no dir;
nginx HTML 403 = dir exists.

* `/` → 403, `/pes22/` → 403, **`/pes22/gate/` → 403** (directory exists —
  my earlier 36-name sweep never tried the name `gate`)
* `/pes22/config/`, `/pes22/api/`, `/pes22/kgs/`, `/pes22/general/` → 404
* **every** `Cmd*.php` under `/pes22/` and `/pes22/gate/` → `File not found.`

**`info.service.konami.net` (Apache/2.4.62 PHP/8.0.20)**

* `/` → 200 test page, `/XWW020-E1/` → 403, `/XWW020-E1/info/` → 403
* all `Cmd*.php`, and 30 stems × 11 extensions → 404 (empty)

---

## 4. The blocker, stated plainly

The client builds `https://pes22-game.cs.konami.net` + `/` + `pes22` and
appends `Cmd*.php`. That path answers **`File not found.`** — the scripts
are not published there.

The runtime override table (`0xa4cff68`) that would supply the real base is
**all zeros** — it is filled in `.bss` only by the online session, and the
session cannot start until the URL is known. Chicken-and-egg.

The static config has been read straight out of the running game's memory
(§5), so the *input* to the URL builder is not in doubt — what is missing is
whatever fills the override table before the first `Cmd` request.

---

## 5. What was read out of the running game (not guessed)

Headless core booted under Unicorn (`OnlineCore`), the game's own 11
online-config registrars executed, then the config block dumped:

| offset | field | value |
|---|---|---|
| `+0x00` | scheme | `https` |
| `+0x18` | stun | `pesam.stun.service.konami.net` |
| `+0x30` | dev-tag | ` DEV1` |
| `+0x48` | host | `pes22-game.cs.konami.net` |
| — | path | `/` |
| — | title | `pes22` |

`0xa4cff68` env table: **4 entries × 32 bytes, flag byte at `+0x2c`,
`std::string` at `+0x30`, index range 0..3** — confirmed by disassembling the
getter `0x814a04c`. All four entries are zero in this harness.

---

## 6. curl / HTTP addresses resolved (corrected)

| symbol | address | note |
|---|---|---|
| `curl_easy_setopt` | **`0x6886498`** | **vaddr**, not file offset. At file offset it decodes as garbage mid-function. |
| `curl_global_init` | `0x6858b14` | refcount at `0xa40e098` |
| `curl_easy_init` | `0x6858c98` | |
| game HTTP routine | `0x7d038c8` | init → setopt(URL) → setopt(POSTFIELDS) → perform |
| game's WRITEFUNCTION | **`0x7d04570`** | `adr x2,#0x7d04570`, `w1=0x4e2b` — **response-capture hook point** |
| `CmdGetServerEnv.php` builder | `0x767eaf0` / `0x767f6e4` | dispatcher branch `0x767ceec` |
| URL slot | `ctx + 0x3968` | `std::string` member of a `0x3978`-byte object |

A `UC_HOOK_CODE` on `0x6886498` reads `x1` = option, `x2` = value; for
`x1 == 10002` (`CURLOPT_URL`) `x2` is the `char*` URL. The hook fires
**before connect**, so the URL is observable even if TLS never completes.

---

## 7. Corrected / retracted assumptions

1. **The "concat chain" at `0x7dbc7f8` is NOT a URL builder.** Its
   separators are `/`, ` ` (space), `(`, `; `, `)`. It is a diagnostic text
   formatter. Earlier notes deriving the request URL from it were wrong.
   (It does call the env getter `0x814a04c` with index 1, so it *reads* env.)
2. **`file offset ≈ vaddr` is false for `.text`** — `vaddr = file offset +
   0x4000`. This is why `0x6886498` failed to disassemble when treated as an
   offset. `.rodata`/strings are unaffected (`offset == vaddr`).
3. **Path guessing is over.** With only 5 hostnames and 4 absolute URLs in
   the binary, and all directories mapped, there is no candidate left to
   try by brute force.

---

## 8. Deliberately not followed

* `GET /ntl/api/config/servers.yml` → 200 with an internal deploy config
  (SSH host/user/key paths).
* `GET https://info.service.konami.net/` → test page leaking internal
  hostname `prdec2-ap02-info`.

Both are **infrastructure**, not game protocol. Not harvested, not used.

---

## 9. Next step

Fill `0xa4cff68` so the override supplies the base, then drive `0x7d038c8`
and watch `0x6886498` / `0x7d04570`.

Two routes:

* **A (emulator):** find the writer of env entry 1 (`0x767ceec` dispatcher →
  `CmdGetServerEnv` response parser). It is fed by a response we have not
  yet obtained — so this likely needs the same missing URL first.
* **B (recommended):** the `Cmd*` request is only reachable in production,
  which means the path is supplied per-build/environment. Capture it from a
  **real device on a real network** with `tcpdump`/pcap over TLS termination
  — i.e. MITM the phone with a proxy CA. That reads the exact path in one
  connection and ends the guessing permanently.
