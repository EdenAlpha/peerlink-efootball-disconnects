# PeerLink M24 — getting the game's own HTTP stack onto the wire

Everything below was found by running the untouched `libUE4.so` under Unicorn
and reading what it actually did. No request is ever assembled by hand: the
URL is handed to the game's own sender, the game's own pump drives the libcurl
built into the binary, and the answer is read back out of the game's own
sub-request object.

## The chain of blockers

Each one was a stub that returned `0`, which the game's code correctly read
as "this failed".

| # | Symptom | Real cause |
|---|---------|-----------|
| 1 | `CURLE_URL_MALFORMAT (3)` / `URL rejected: Malformed input to a URL function` | curl does `strcspn(url, reject)` and requires it to equal `strlen(url)`. The `strcspn` stub returned `0`, so every character looked illegal. |
| 2 | `sa_addr inet_ntop() failed with errno 97`, `CURLE_FAILED_INIT (2)` | `__strlen_chk(s, n)` returned `0`, so the address formatter believed the formatted `a.b.c.d` string was empty. |
| 3 | Transfer never finished, `select` called thousands of times | `__FD_SET_chk(fd, set, n)` never set the bit, so `select()` never saw the socket as ready. |
| 4 | Request sent, `recv` timed out forever, HTTP code stayed `-1` | `socket(2)` was passed `type = 0x801` (`SOCK_NONBLOCK \| SOCK_STREAM`). The mask stripped `0x40000`/`0x80000` but not `0x800`, so `0x801 != SOCK_STREAM` and a **UDP** socket was created. The HTTP request went out over UDP and nothing could ever come back. |

### Bug 4, verbatim from the trace

```
net socket(fd=10) fam=2  rawtype=1    proto=6 -> 1
net socket(fd=11) fam=10 rawtype=2    proto=0 -> 2
net socket(fd=12) fam=2  rawtype=2049 proto=6 -> 2      <-- 2049 = 0x801 = UDP by mistake
net connect(fd=12) -> ('35.174.175.11', 80)
net send(fd=12, 81B) -> 81                               <-- request left, over UDP
net recv(fd=12,n=16384) -> TIMEOUT                       <-- and could never come back
```

Linux/bionic fold these into `socket()`'s `type`:

```
SOCK_NONBLOCK  00004000 oct = 0x800
SOCK_CLOEXEC   02000000 oct = 0x80000
```

`_h_socket` now masks with `typ & 0xF`, keeps `want_nb`, and sets the Python
socket non-blocking up front. `O_NONBLOCK` in the harness is `0o4000` = `0x800`,
so `_net_flags` and `F_GETFL`/`F_SETFL` agree with it.

Also confirmed: this build has **no `send`/`recv` imports at all** — curl's
data path is `sendto`/`recvfrom`, and there is **no `socketpair`** either.

`inet_ntop` in this build is **not** an import — it is a static function at
`0x68740f8` that formats the address itself and calls `__strlen_chk` on the
result. That is why no `inet_ntop` import ever appeared in the trace.

## Where the rejection is decided

* `"URL rejected: %s"` lives at file/vaddr `0x9c49fc` (`.rodata` offset == vaddr).
* The single `ADRP+ADD` reference is at `0x688bee0`.
* The call before it:

```
0x688bea0  ldrh w8, [x28, #4]
0x688bea4  mov  x0, x23            ; Curl_URL handle
0x688bea8  ldr  w9, [x28]
0x688beac  mov  w1, wzr            ; CURLUPART_URL == 0
0x688beb0  ldr  x2, [x19, #0xe90]  ; the URL string
0x688bec8  orr  w3, w9, w8         ; flags
0x688becc  bl   0x6891f80          ; curl_url_set
0x688bed0  cbz  w0, success
0x688bed8  bl   0x6888ffc          ; curl_url_strerror
0x688beec  bl   0x68593f0          ; failf(easy, "URL rejected: %s", ...)
```

`curl_url_set` is `0x6891f80`. Even with `flags = 0` and a byte-perfect URL it
returned `3` until `strcspn` was implemented.

* The address formatter is `0x685da04(sa, dst, port_out)` — reads the family
  from `*(uint16*)sa`, returns `0` when it is neither `AF_INET` nor `AF_INET6`.
  Its failure path calls `failf` with the format at `0xa5c460`
  (`"sa_addr inet_ntop() failed with errno %d: %s"`).

## The senders, precisely

Sub-request vtable `0x98225a0`. Layout of a sub-request (`self`):

```
+0x0000  vtable
+0x0008  HTTP status code        (starts at -1, set from CURLINFO_RESPONSE_CODE)
+0x001c  response body buffer    (0x10001 bytes, zeroed by init)
+0x10020 body length             (s32, written by the WRITEFUNCTION)
+0x10024 write error
+0x10028 out_body slot           (init x1)
+0x10030 out_len slot            (init x2)
+0x10038 completion callback     (init x3)
+0x10040 callback argument       (init x4)
+0x10048 sender status
+0x1004c done flag
+0x10060 easy handle             (curl_easy_init)
+0x10068 multi handle            (curl_multi_init)
+0x10070 header slist            (POST only)
```

**GET sender `0x7d03b68`**

```
x0 = self   x1 = url   x2 = out_body   x3 = out_len   x4 = cb   x5 = cb_arg
-> init(self, x2, x3, x4, x5)
   curl_global_init(0); curl_easy_init() -> +0x10060
   setopt URL / WRITEDATA(self) / WRITEFUNCTION(0x7d04570)
   curl_multi_init() -> +0x10068 ; multi_add_handle
   returns 0xe000001 when [self+0x10048] == 0, else 0xe000009
   returns 0xe000000 if url == NULL
```

**POST sender `0x7d04148`**

```
x0=self  x1=url  x2=postdata  x3=postlen  x4=a4  x5=a5  x6=a6
x7 = out_body
[sp+0x00] = out_len
[sp+0x08] = cb
[sp+0x10] = cb_arg
-> init(self, x7, [sp+0], [sp+8], [sp+16])
   then vtable[7] = 0x7d03e10(self, url, body, len, a4, a5, a6)  -- header builder
   then setopt POSTFIELDS / POSTFIELDSIZE(0x3c) / HTTPHEADER(+0x10070)
   setopt DEBUGFUNCTION(0x7d04594) and VERBOSE=0
```

`0x7d03e10` bails out immediately if **any** of `a4`, `a5`, `a6` is NULL — so
those three are what the game's own command builder supplies. They have to be
captured from a real game-driven POST, not invented.

**Cleanup `0x7d042f0(self)`** — `multi_remove_handle`, `easy_cleanup`,
`multi_cleanup`, `slist_free_all`, each NULLed after the call, then tail-jumps
`0x6858c78`.

## What runs on the wire now

```
getaddrinfo -> socket(fd=12) -> connect -> 34.193.147.150:80
sendto x1, recvfrom x5, select x11, getsockopt x1
```

## Harness changes made for this

* `scripts/uc_loader2.py` — real `strcspn`, `strspn`, `strpbrk`, `strstr`,
  `strrchr`, `strchrnul`, `memcmp`, `strcasecmp`, `strncasecmp`, `atoi`,
  `atol`, `atoll`, `strtol`, `strtoul`, `time`, `getenv`, `sysconf`,
  `sysinfo`, `__strlen_chk`, `__strchr_chk`, `__strrchr_chk`,
  `__strcpy_chk`, `__strncpy_chk`, `__strcat_chk`, `__strncat_chk`,
  `__memcpy_chk`, `__memmove_chk`, `__memset_chk`, `__stack_chk_fail`.
  `strchr`/`strrchr` now stop at the NUL instead of scanning past it.
* `peerlink/netsplice.py` — `getsockname`, `getpeername`, `inet_ntop`,
  `inet_pton`, `inet_addr`, `strerror`, `gai_strerror`,
  `__FD_SET_chk`, `__FD_ISSET_chk`, `__FD_CLR_chk`.
* `scripts/uc_loader.py` — `call()` now accepts `x6`, `x7` and a `stack=[...]`
  list (AAPCS stack arguments starting at the caller's SP), which is what the
  POST sender needs.
* `peerlink/game_http.py` — **the reusable transport**: `GameHttp(core).get(url)`
  and `.post(url, body, a4, a5, a6)` run one request through the game's own
  stack and return `(status, code, body, error, curl_result)`.
