# M26 — why the game's own code cannot run: vtable slots are zero in the file

## The mechanism, proven

`0x767eaf0` (the CMD_GET_SERVER_ENV constructor) begins:

    0x767eb00  add   x0, x0, #8
    0x767eb04  adrp  x8, #0x97a2000
    0x767eb08  add   x8, x8, #0x600        ->  x8 = 0x97a2600
    0x767eb0c  str   x8, [x19]              ->  obj->vtable = 0x97a2600

So the vtable address *is* in the file. What is not in the file is its
contents. Reading `0x97a2600` straight out of the ELF:

    [ 0] 0x0000000000000000
    [ 1] 0x0000000000000000
    ... all zero ...

Every slot is zero. A whole-image scan for vtable-shaped runs (>= 3 consecutive
pointers into the executable segment `0x28293c0..0x8b75140`) finds only three
tables in the entire 160 MB binary:

    0x98dcd38   15345 slots   <- the GOT/PLT (rebuilt from .rela.plt)
    0x9951090      12 slots   <- one class
    0xc0            4 slots

Consequence in the Unicorn harness: every C++ virtual call loads a zero
function pointer and branches to address 0. This is the
`UC_ERR_FETCH_UNMAPPED addr=0x0 pc=0x0` fault, and it is why the game's own
code could never get past its first few non-virtual functions.

## Why the file looks like this

The ELF is missing both relocation sources that could express these values:

    DT_RELA / DT_RELASZ   absent   (no .rela.dyn section at all)
    DT_RELR / DT_RELRENT  absent
    .rela.plt             present, 15,345 entries (imports only)
    DT_RELACOUNT          absent

The dynamic section has 33 entries and none of them is a relative-relocation
table. So the R_AARCH64_RELATIVE entries that would normally write
`base + addend` into those vtable slots are not in the file.

This is not a detail of how *we* loaded it — the bytes are zero on disk, so
this is how the file was published. Whatever produced it (extraction,
decompilation of a protected build, or a repack) dropped the relative
relocations. The two copies in the repo are byte-identical
(SHA256 2ac4ff17ac8ad713d9531c2601e38a3c8335e02ea882ba2dc4445c191c1298cd), so
they share the defect.

## What this invalidates

Everything inferred from "reading the game's code" is suspect, because the
code that was read is only reachable through those zeroed pointers.  The
login path (TaskLogin, the state machine at 0x7dc7164, the request builders)
cannot be executed or decompiled reliably without recovering the vtables
first.  That is why the earlier hypotheses -- that the block was IP-based, then
a missing client certificate, then a separate relay host -- all failed: none
of them were derived from code we could actually run.

## The two viable ways forward

1. **Recover the vtables.** For each class, Ghidra's analysis can infer
   virtual methods from the constructor's stores and from `this`-relative
   call sites (`blr` after `ldr xN,[xM,#slot]`).  Tedious but mechanical.
   Alternatively, dump the relocations from a *running* process: on a
   non-rooted phone `adb shell` cannot read another process's memory, so this
   needs root or an emulator image.

2. **Get a copy of the binary that still has its relocations.** This is the
   cheap path if it exists.  The 57 MB `config.arm64_v8a.apk` contains a
   byte-identical `libUE4.so`, so it is not a different build.  A build pulled
   straight from the device, or a version predating the stripping, would fix
   this immediately.

## Honest status of the login work

Established and independent of the above:
  * the endpoint `https://pes22-game.cs.konami.net/pes22/gate/gate_<msgid>.php`
    is real and unique (404 for invented names, 500 for real ones)
  * the request body is produced by the game's own serializer
  * the network is not the cause -- the same 500 appears from AWS, from
    Cloudflare WARP, and from the phone's own mobile connection
  * gRPC is not involved (only linked-in boilerplate, no service definitions)

Still unknown: why the PHP fatals before reading any input.
