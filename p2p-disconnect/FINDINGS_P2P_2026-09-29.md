# P2P disconnect — what the exports actually show

Analysis of all 14 `peerlink_match_*.zip` exports the tool produced, using
`scripts/scan_exports.py`, `scripts/analyze_match.py` and
`scripts/dir_timeline.py`.

## Baseline: 12 of 14 exports are healthy

Representative: `1790619339531`

| measure | value |
|---|---|
| duration | 230.1 s |
| packet rate | steady 52–55 pkt/s, no decay |
| low-rate seconds | 2 (kickoff at t=6 s, capture stop at t=230 s) |
| worst in-session gap | 374 ms inbound, 123 ms outbound |
| direction split | 6054 in / 5919 out (50.6 / 49.4) |
| `rx_kernel_to_user` | p50 0.1 ms, p99 2.5 ms, max 31.3 ms |
| `rx_enqueue_to_write` | p50 0.2 ms, p99 3.8 ms, max 37.3 ms |
| packet classification | 100% `stun\|tunnel\|stableKnown` — no fallback path ever used |

**These exports contain no disconnect.** The session was cut off by the export,
not by the network, so they cannot be used to diagnose a disconnect. Worth
saying plainly, because it means the earlier assumption that this particular
capture showed a failing session was wrong.

## The anomaly: one match is one-directional for its whole duration

`1790283191028` and `1790283204171` are the same match captured from both ends.

| export | out | in | in:out |
|---|---|---|---|
| `1790283191028` | 79 | 10 843 | **137 : 1** |
| `1790283204171` | 10 844 | 79 | mirror |

- Duration 400 s — the longest in the set; every healthy export is 199–230 s.
- Overall rate 27.3 pkt/s, exactly half the healthy ~54 pkt/s.
- The asymmetry is **not** a late collapse. It is present from t=0 s to t=399 s,
  without interruption:

```
     t_s    out     in          t_s    out     in
       0      0     28          200      1     28
      60      1     27          260      1     28
     120      1     28          320      1     28
     180      1     27          380      1     28
```

- The single outbound packet every ~5 s is the signature of a control/keepalive
  tick, not gameplay data.
- **Both ends independently record the same asymmetry.** That rules out a
  capture artefact: each phone saw the other's traffic fine, and each saw
  almost none of its own being delivered.

So in this match one peer's **outbound** P2P path carried no gameplay data at
all, for the entire session. That is the shape of a one-way failure, and it is
the only such case in the 14 exports.

## What this does and does not establish

Established from the data:

- 12 exports are healthy; the P2P path is normally symmetric at ~54 pkt/s.
- 1 match (2 exports) is one-directional at 137:1 for its full 400 s.
- Latency in the healthy exports is sub-millisecond, so this is not a latency
  or queueing problem.
- No fallback path (`adb`, direct, or any non-`tunnel` flag) ever appears, in
  any export — so the tunnel was the only path in use throughout.

Not established, and deliberately not guessed:

- **Whether 27:1 could be normal for this netcode in some game state.** If the
  game is authoritative on one side for a period, some asymmetry is expected.
  The claim that this is a *failure* rests on it being 137:1 and sustained,
  not on the asymmetry existing at all. Confirming it needs a match that
  visibly desyncs, or the game's own view of the session.
- **Which side broke.** `1790283191028`'s phone is the one whose outbound was
  starved, but the export does not record a cause.
- **Whether the kill-and-relaunch test on the phone changes it** — still
  unanswered, and it is the cheapest thing that would separate "the tunnel
  breaks" from "the game stops using it".

## Next step

The most useful next capture is one taken **at the moment the screen visibly
desyncs**, with the export left running through the failure rather than stopped
before it. The tool already records everything needed — `status`, `flags`,
per-packet `rel_ms`, and the kernel/user timing columns — so a capture that
actually contains the failure should be directly readable with
`scripts/dir_timeline.py`.

## Tooling

| script | purpose |
|---|---|
| `scripts/scan_exports.py` | scores every export for a disconnect signature |
| `scripts/analyze_match.py` | full per-export breakdown: rate, gaps, direction balance, latency percentiles, flag and status histograms |
| `scripts/dir_timeline.py` | per-second outbound/inbound timeline for a chosen export |

Note on the first version of `scan_exports.py`: it reported "0 of 14 exports
show a disconnect-like signature" because its one-sided test required a
direction to be **exactly** zero. The anomalous exports are 79 vs 10 843, not
0 vs N, so the raw numbers were unmistakable and the threshold was wrong. The
ratio-based test in `dir_timeline.py` catches it.
