# 2026-10-01, lane `h`: real-browser test of the Konami portal 403

Two screenshots, in the order they were taken. Both are from Google Chrome
installed via Play on the redroid device, made the browser role holder.

## `ic.png` -- Chrome, recorder still in the path

Chrome's own **certificate error** interstitial:

> Your connection is not private
> Attackers may be trying to steal your passwords

Cause: Chrome does not trust the recorder's MITM CA. The URL bar shows the red
`x` and `my.k...`.

**This is not a Konami response and is not a 403.** It is a statement about our
own interception. Reading it as "the portal blocks the browser" would have been a
second wrong conclusion drawn from the same screen.

## `id.png` -- Chrome, recorder removed from the path

The DNAT rule was deleted first, so the request went straight to Konami over a
genuine TLS session (`flows.log` did not advance, which is how that was
confirmed on-device).

The result is Konami's own page:

- real KONAMI ID logo and header
- normal padlock -- no certificate warning
- `403 Forbidden`
- `申し訳ありませんが、このページにはアクセスできません。`
  ("Sorry, this page cannot be accessed.")

## What this establishes

A real browser, a full browser header set, a real TLS fingerprint, from this
runner's egress address, is refused by Konami's edge. The earlier conclusion --
that `my.konami.net` blocks this runner's address -- stands, but it now rests on
evidence that actually answers the question, rather than on a `curl`
User-Agent sweep.