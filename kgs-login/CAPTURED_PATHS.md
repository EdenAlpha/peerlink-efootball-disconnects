# Captured KGS command paths

Source: live capture on the GApps redroid container, mitmproxy transparent mode,
addon `kgs-login/scripts/mitm_addon.py` (`targets=konami.net,konami.jp`).

Host: `pes22-game.cs.konami.net`
Prefix: `POST /pes22/gate/gate_CMD_<VERB>_<NOUN>.php`

These are the `CommandRequest.path` values, read out of the game's own TLS
traffic after MITM -- not assembled by hand.

## Captured 2026-10-01, in the order the game issued them

| # | path |
|---|---|
| 1 | `gate_CMD_CHECK_STRING.php` |
| 2 | `gate_CMD_CREATE_USER.php` |
| 3 | `gate_CMD_GET_AGE_GATE_REQUIREMENTS.php` |
| 4 | `gate_CMD_GET_COUNTRY_LIST.php` |
| 5 | `gate_CMD_GET_GAMERELAY_QUALITYCHECK_LIST.php` |
| 6 | `gate_CMD_GET_KID_USER_AGE_KIND.php` |
| 7 | `gate_CMD_GET_PRODUCT_LIST.php` |
| 8 | `gate_CMD_GET_SERVER_ENV.php` |
| 9 | `gate_CMD_GET_STADIUM_DATA.php` |
| 10 | `gate_CMD_GET_SURVEY_INFO.php` |
| 11 | `gate_CMD_SEND_ADJUST_PARAM.php` |
| 12 | `gate_CMD_SET_TRACKRECORD.php` |

Sample response frame, captured verbatim:

```
### RESP POST /pes22/gate/gate_CMD_SET_TRACKRECORD.php -> 200
RESPLEN: 96
RESPHEX: 2f8d94c9baa052143e86005ab97f4c6ad1d680f8743610d3b6abff71c5293ecf7d1bc02ac34b63881e7b7944064131a4a0b3070adceee26b289b7dc0da8dbca3be213b9ed0fecb3566043b7a955c649b313229edcb8bf92fbb23ba6e104b9a89
```

## What this settles

The naming convention is now **measured, not assumed**: `gate_CMD_` + SCREAMING_SNAKE
verb/noun pairs, `.php`, all under `/pes22/gate/`. Earlier notes speculated that
paths were slash-prefixed routes like `/room/create`; they are not. The whole
vocabulary is enumerable by pattern, so the room commands we still need are
predictable: `gate_CMD_CREATE_ROOM.php`, `gate_CMD_JOIN_ROOM.php`,
`gate_CMD_SEARCH_ROOM.php`, `gate_CMD_GET_ROOM_LIST.php` and similar. Those
remain **unverified** until the game actually issues them.

## Hosts seen in the same session

```
pes22-game.cs.konami.net      the KGS gate
www.konami.com
legal.konami.com
d1ln4m3c7n87ju.cloudfront.net game assets
app.adjust.com               analytics
*.googleapis.com, connectivitycheck.gstatic.com
```

## Open bug in the addon

`mitm_addon.py` raises on gzip-encoded request bodies:

```
ValueError: ValueError when decoding b'\xbb\xba with 'gzip':
  Decompression failed: incorrect header check
```

`flow.request.content` decompresses eagerly and throws when the declared
`Content-Encoding: gzip` is wrong or the body is not actually gzipped. It should
read `flow.request.raw_content`, which never decompresses, so a malformed
advertised encoding cannot take out the whole flow. Traffic is still captured
around the failure -- the traceback is caught -- but any flow that trips it logs
no body, so `analyse_capture.py` would be decoding a hole.
## Second capture, 2026-10-01 07:55-08:30 (run 36827075563)

A live session from a genuine Play install, driven through onboarding by
hand. 56 flows, 28 responses, every one `200`. 14 distinct routes, one of them
not previously recorded:

```
gate_CMD_GET_USER_EULA_INFO.php
```

A real `CREATE_USER` exchange is in the capture, 12368-byte response, for
`User ID ASKH-124-394-950`. Raw bodies are in
`captures/2026-10-01-gate/gate-resp.txt`; the verdict is in `README.txt` there.

### The bodies are encrypted, and compression is ruled out

Every response body reads as uniformly random bytes. `decode_gate_flows.py`
reports printable ratios of 37-44 percent on all 20 bodies regardless of
whether the body is 96 bytes or 12368, and entropy from 6.07 to 7.98 bits per
byte.

Compression was the obvious alternative explanation and it was tested rather
than assumed, because `mitm_addon.py` has a documented `Content-Encoding:
gzip` defect and compressed JSON looks almost exactly like ciphertext:

```
gate_CMD_GET_SERVER_ENV.php         4c04e35e   NOT COMPRESSED
gate_CMD_GET_COUNTRY_LIST.php       a5ae9786   NOT COMPRESSED
gate_CMD_GET_AGE_GATE_REQUIREMENTS  1cc5c728   NOT COMPRESSED
gate_CMD_GET_KID_USER_AGE_KIND      51564e04   NOT COMPRESSED
gate_CMD_GET_SURVEY_INFO.php        716d4128   NOT COMPRESSED
gate_CMD_CHECK_STRING.php           1d0117c0   NOT COMPRESSED
```

No `1f 8b` gzip magic on any of them, and `zlib` fails at every window width
tried. It is also not an encoding: base64 or hex would be almost entirely
printable, and these are 38 percent, which is `(95 printable + 3 whitespace)
/ 256`.

So the layer order is:

```
game encrypts body  ->  TLS encrypts that  ->  network
        ^                       ^
 our CA cannot help      our CA works here
```

The certificate is doing its job -- it is the only reason the method, path,
host and status code are readable at all. It cannot reach the inner layer,
because the game encrypted the payload before handing it to TLS. Any claim
that the capture is "not decrypted" has to be specific about which layer: the
transport is fully decrypted, the payload is not, and no certificate changes
that.

### What is deliberately NOT committed

`flows.log` on the runner is 141 KB and `flows.mitm` is 65 MB. The mitm file
is left on the runner and comes back through the run artifact rather than git,
which is the wrong store for it. The raw `flows.log` is also withheld once the
Konami login runs, because that leg is an ordinary browser form post: with TLS
terminated, the account password would sit in the log in plaintext, and
`live-cmd`/`live-res` are public branches. Only the `/pes22/gate/` responses
are committed, which is both the useful part and the safe part.

### Two further routes, and the User-Agent, from the same session

Driving past the team-selection wizard produced two routes not previously
recorded, both `200`:

```
gate_CMD_SET_MYCLUB_ENTRY_INFO.php
gate_CMD_GET_MAINMENU_INFO.php
```

`GET_MAINMENU_INFO` is the point at which the main menu is reached, which makes
it a useful marker for "onboarding is finished".

The game's memory also yields its own User-Agent verbatim:

```
PES/1.0 (ANDROID 14; ASKH124394950; redroid14_arm64_only; 1790844937; 6.0.1; ; 11.0.1; )
```

Field by field: platform and OS version, the User ID with its dashes stripped
(`ASKH-124-394-950` from the title screen), the device model, a numeric token
that behaves like a build or session epoch, then two version fields. This lines
up with the `ReportLog.php` line in the passthrough capture taken from the zip
earlier, which carried `libVer 1.17.1-Android-15` in the same positional
arrangement, so the client identifies itself the same way in both places.
