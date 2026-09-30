# M25 — the gate endpoint is solved; the 500 is server-side

## The endpoint (closed)

The game's own URL composer is a single function:

    0x7b099d0  (out, a, b)  ->  scheme + "://" + host + "/pes22" + "/gate/gate_" + a + ".php"

`a` is the **msgid** (`CMD_LOGIN`, `CMD_GET_SERVER_ENV`, …), taken from offset
**+0x70 of the request object** — proved by the gate builder:

    0x7afd364 (self, task, state)
        0x7afd454  x1 = task + 0x70          <- `a`  (the msgid)
        0x7afd458  x2 = self + 0x18e0        <- fallback
        0x7afd468  bl 0x7b099d0               <- compose
        0x7afd474  bl 0x74e6d10  (size of task+8)   } the task's own
        0x7afd480  bl 0x74e6d24  (data of task+8)  } MessagePack body
        0x7afd494  bl 0x7b2e334  (req, url, size, data)

Live confirmation (GET, oracle = 404 `File not found.` vs 500 `script ran`):

    /pes22/gate/gate_CMD_LOGIN.php                 500   <- exists
    /pes22/gate/gate_CMD_GET_SERVER_ENV.php        500   <- exists
    /pes22/gate/gate_CMD_GET_KGS_GUEST_LOGIN_TOKEN.php  500
    /pes22/gate/gate_CMD_CREATEJOIN_ROOM.php       500
    /pes22/gate/gate_CMD_BOGUS_DOES_NOT_EXIST.php  404   <- control
    /pes22/gate/gate_CmdLogin.php                  404   <- filename form is wrong
    /pes22/gate/                                   403   <- directory is real
    /pes22/                                        403
    pes22-game.cs.konami.net -> 8 ALB addresses, all identical

So the earlier note in `peerlink/kgs.py` ("the exact production path is the one
remaining unknown") is now closed: it is
`https://pes22-game.cs.konami.net/pes22/gate/gate_<msgid>.php`.

## The two POST senders (sub-request vtable 0x98225a0)

    [ 2] 0x7d03b68  GET   (url, out_body, out_len, cb, arg)
    [ 3] 0x7d03c68  POST  — sets CURLOPT_URL / WRITEDATA / WRITEFUNCTION /
                             POSTFIELDS / POSTFIELDSIZE / HEADERFUNCTION only
                             -> no custom headers, curl therefore sends
                                Content-Type: application/x-www-form-urlencoded
    [ 7] 0x7d03e10  header list builder (used by [8])
    [ 8] 0x7d04148  POST with CURLOPT_HTTPHEADER from that list
    [10] 0x7d042f0  cleanup      [11] 0x7d04350  pump      [12] 0x7d04444  init

Header list built by 0x7d03e10 (all strings are the binary's own literals):

    Content-Type: text/xml; charset="utf-8"
    M-POST                                   (custom request method)
    MAN: "http://schemas.xmlsoap.org/soap/envelope/"; ns=01
    SoapAction: "<a5>#<a6>"                  (from a5/a6)
    Host: <host taken from the URL>
    Content-Length: <len>
    User-Agent: Mozilla/4.0 (compatible; UPnP/1.0; KONAMI)
    Connection: Keep-Alive
    Cache-Control: no-cache
    Pragma: no-cache

0x7b2e334 additionally builds the game's **own** User-Agent with 0x7dbc430 and
pushes it onto the sub-request before attaching URL and body. Executed live it
produces:

    PES/1.0 ( ; 0; ; 6597086477512; ; ; ; )

(empty fields are device info the headless boot never fills).

A second sub-request vtable exists at **0x9822628** (slots 7 and 12 point at the
same builder/init).

## The IP theory — tested and DISPROVEN

It was hypothesised that the 500 was an IP-reputation block because the machine
sits on an AWS address while the phone is on a mobile network. Tested by
installing Cloudflare WARP and repeating every request through it:

    before:  34.226.211.195   ec2-34-226-211-195.compute-1.amazonaws.com  (AS14618)
    after:   104.28.196.79 / 2a09:bac5:c82e:166e::23c:38  (Cloudflare WARP)

Result: **byte-identical 500, empty body, every case** — raw msgpack, `req=`
hex, five content types, both methods, HTTP/2, game User-Agent, on both
`CMD_GET_SERVER_ENV` and `CMD_LOGIN`. Control in the same run: NTL GateInfo
still returned `200 STATUS: 200` through WARP.

So the failure is **not** about the source address. A second, completely
different network produces exactly the same result, which means the PHP is
failing on something intrinsic to the request we send, not on who sends it.

This kills the "run it from your home connection" workaround as a *fix*. It may
still be worth doing for other reasons, but it will not by itself make the gate
answer.

## The wall (retested through WARP — unchanged)

Every request to an existing `gate_*.php` returns

    HTTP/1.1 500 Internal Server Error
    Server: nginx
    Content-Type: text/html; charset=UTF-8
    Transfer-Encoding: chunked
    0

— an empty body, i.e. PHP started and died with display_errors off. Tried, all
identical 500:

* body: raw game MessagePack, `req=<hex>`, `req=<base64>`, 15 other field names
* Content-Type: form-urlencoded, octet-stream, x-msgpack, text/xml, none
* method: POST, M-POST, GET; HTTP/1.0 and HTTP/1.1
* User-Agent: the NTL one and the game's own `PES/1.0 (...)`
* HTTP/2 via ALPN (server prefers h2; the real client uses it)
* all 8 ALB addresses, and port 80 (which times out entirely)

`/pes22/gate.php` fatals the same way, so the shared `gate.php` dispatcher is
the likely failure point, and it dies **before** it reads any input. Nothing the
client sends changes the outcome, which points at a server-side precondition
rather than at our request.

## Why static analysis stalls here

All 397 `CMD_*` literals (and the info URL, and `ChangeServer.bin`) have **zero**
`ADRP+ADD` references in `.text` — they are reached through relocated pointer
tables that are all-zero in the file. Only after the image is loaded do they
exist, which is why the runtime vtable scan (`map_vtables.py`) had to be used
to locate the sub-request tables at all.

## Also confirmed dead ends

* `https://info.service.konami.net/XWW020-E1/info/` — 403 on the directory;
  `ChangeServer.bin` 404s. The literal sits next to it in .rodata but the file
  is not served at that path.
* Only five Konami hostnames exist in the binary; `pes22-game.cs.konami.net` is
  the only game host, so there is no alternate login host to try.
* `gate.php` as a literal (0x9d9a1b) is not the path — `/pes22/gate/gate.php`
  is 404; only `/pes22/gate.php` exists (and fatals).
