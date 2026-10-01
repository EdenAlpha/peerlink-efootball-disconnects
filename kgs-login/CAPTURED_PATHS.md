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