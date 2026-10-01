# Lane `h`, 2026-10-01 — complete flow record

The complete, unredacted record for GitHub Actions run `36851667352` (lane `h`),
recovered from the run artifact before it expired.

| File | Size | What it is |
|---|---|---|
| `flows.log` | 586 KB | The decoded flow log: 18 flows, request/response hex, lengths, headers |
| `flows.mitm` | 1.8 MB | mitmproxy's raw dumpfile for the same session |

`flows.log` is the human-readable record. `flows.mitm` is mitmproxy's native
format and can be replayed directly with `mitmdump -nr flows.mitm`.

## The 18 flows

Eight distinct routes, all previously known -- these are rows 3, 4 and 6 and the
five pre-existing ones in the table in `../../CAPTURED_PATHS.md`. Nothing new was
discovered route-wise this lane:

| Route | Req (B) | Resp (B) | SHA1 (from `CAPTURED_PATHS.md`) |
|---|---|---|---|
| `POST /pes22/gate/gate_CMD_GET_SERVER_ENV.php` | 86 | 224 | |
| `POST /pes22/gate/gate_CMD_GET_USER_EULA_INFO.php` | 86 | 512 | |
| `POST /pes22/gate/gate_CMD_GET_KONAMIID_TRANSITION_URL.php` | 86 | 320 | |
| `POST /pes22/gate/gate_CMD_DATA_TRANSITION.php` | 86 | 224 | |
| `POST /pes22/gate/gate_CMD_GET_AGE_GATE_REQUIREMENTS.php` | 86 | 160 | `1cc5c728` |
| `POST /pes22/gate/gate_CMD_GET_COUNTRY_LIST.php` | 86 | 2,352 | `a5ae9786` |
| `POST /pes22/gate/gate_CMD_GET_KID_USER_AGE_KIND.php` | 86 | 128 | `51564e04` |
| `GET /account-link/introduction?lt=...` | 0 | 224 | the blocked portal |

The three age-gate routes are the useful part: they are captured here as a
*self-consistent set*, all from one session and one app state, with the same
86-byte request shape. `CAPTURED_PATHS.md` had them recorded but not captured
together in a single recoverable flow log.

`COUNTRY_LIST` at 2,352 bytes of response is the largest single body in the
project, and it is a country list -- so it is the body most likely to yield
structure the moment the app-layer encryption is broken. Best target on hand.

Every request body here is 86 bytes and app-layer encrypted (form-urlencode →
gzip → AES-256), so none is readable yet. The request length being *identical*
across all three age-gate routes points to a fixed-shape request with only the
endpoint name varying.

## Replaying this file

```bash
mitmdump -nr flows.mitm -w replayed.flows
```

## Why this run stopped where it did

Not a capture failure. `pes22-game.cs.konami.net` served every gate request all
session (this host carries a permissive policy). The account-linking host
`my.konami.net` returned `403 awselb/2.0` — an AWS Elastic Load Balancer
refusing a datacenter address range before any application logic. From the
user's residential address the same host and path return `404`, i.e. accepted and
processed. The address is the wall; no browser or TLS change gets past it.