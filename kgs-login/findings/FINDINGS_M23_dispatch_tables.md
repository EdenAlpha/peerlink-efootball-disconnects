# M23 — Headless login: the dispatch tables, and driving the state machine

## The discovery that explains every dead end

**This Android binary stores its pointer tables in a compressed relocation
format.** `.rela.dyn` has `sh_type = 0x60000002` (`SHT_ANDROID_RELA`, the
"APS2" packed format) and `sh_entsize = 1` — *not* linear 24-byte
`Elf64_Rela` records.

Consequence: **every pointer table (vtables, dispatch tables, handler
registries) is zero-filled in the file.** Static scans for a pointer to a
function return nothing — not because the function is unreferenced, but
because the reference only exists after the loader applies the packed
relocations.

This is why all of these came back empty, and none of it meant "wrong path":
- `BL` call-graph ascent from the login functions
- raw 8-byte scans of the whole file for the function address
- `.rela.dyn` addend scans (parsed as RELA -> garbage)
- `ADRP+ADD` / `ADR` materialisation scans
- `B` / `CBZ` / `TBZ` / `B.cond` target scans

## What actually works: read the tables out of the running game

`find_dispatch.py` — boot the headless core, run the 11 online-config
registrars, then scan emulated memory for `base + fn_addr`. Every target
resolved to exactly **one** pointer, inside a populated table.

## What the login flow actually is

`bootstrap_SM` @ `0x7dc7164` (size 0xce0, confirmed by `.eh_frame`) is a
**12-state task runner**, not a function you call:

    ldr  w8, [x0, #0x2a0]          ; state
    cmp  w8, #0xb ; b.hi default
    adrp x9, #0xc90000 ; add x9, x9, #0x5b8   ; jump table @ 0xc900b8
    ldrh w11, [x9, x8, lsl #1]
    br   x10                       ; 12 x u16 offsets from 0x7dc71b4

State map (from the jump table):

  state  address      state  address
  -----  -----------  ----- -----------
    0    0x7dc71b4      6    0x7dc7428
    1    0x7dc71d0      7    0x7dc7444
    2    0x7dc720c      8    0x7dc746c
    3    0x7dc7348      9    0x7dc747c
    4    0x7dc7380     10    0x7dc7860   <-- the task runner
    5    0x7dc73a4     11    0x7dc71d0   (== state 1)

**State 10 is the network state.** It is driven entirely by a task object
held at `ctx+0x288`:

    ldr x0, [x19, #0x288]   ; task
    cbz x0 -> give up
    ldr x8, [x0]            ; task->vtable
    ldr x8, [x8, #0x38]     ; vtable[7]
    blr x8                  ; task->vtable[7](task)
    tbz w0, #0 -> done      ; needs (ret & 1) to continue
    ldrb w8, [x0, #0x88]    ; second gate
    ... blr x8 again ...
    bl  0x7b1cf34           ; completion

States 3-9 call a family of task-factory helpers in `0x7cdaxxx`
(`0x7cda280`, `0x7cda454`, `0x7cda4c0`, `0x7cda534`, `0x7cda5cc`,
`0x7cdaf90`, `0x7cda78c`, `0x7cda808`, `0x7cda3b8`) — these build the real
task objects.

## The command structure

Each KGS command is an object with three parts, all confirmed in the
disassembly of the `CmdGetServerEnv` builder @ `0x767eaf0`:

| part | where | value |
|------|-------|-------|
| vtable | static `0x97d4448` | 3 sub-vtables at +0, +0x48, +0x78 |
| name | `0xaf6dad` | `"CMD_GET_SERVER_ENV"` |
| path | `0xa0026e` | `"CmdGetServerEnv.php"` |

The builder appends the path to a base read from a static global
(`0x97d4448`), so **the URL is just memory — no protocol to reverse.**

Command-name string table @ `0xaf6dad` (contiguous, NUL-separated):
`CMD_GET_SERVER_ENV`, `GET_STADIUM_DATA`, `CMD_GET_USER_INQUIRY`,
`CMD_GET_VOICE`, `CMD_JOIN_GAME_MODE`, ...

Path table @ `0xa0026e`: `CmdGetServerEnv.php`, `GET_STADIUM_DATA`, ...

## Proof that the state machine can be driven

`drive_sm.py` — fabricate a context + task, set `ctx->state = 10`, put a
`mov w0,#1; ret` stub at `task->vtable[7]`, call the SM:

    stub (mov w0,#1; ret) at 0xa4000000000
    calling bootstrap_SM at state 10 ...
    returned: {'error': None, 'x0': 0}

**It ran cleanly to completion.** The SM accepted the fabricated task,
called vtable[7], and unwound. So the "fabricate a context and drive the
game's own state machine" approach — the same one already proven for the
match state machine — works for login too.

Executable arena for guest stubs: `EXEC_BASE = 0xA4000000000`, 0x100000,
`UC_PROT_ALL` (same trick as `scripts/matchmain_run.py`).

## Key addresses

| what | address |
|------|---------|
| bootstrap SM | `0x7dc7164` |
| SM jump table | `0xc905b8` (12 x u16, base `0x7dc71b4`) |
| SM state field | `ctx+0x2a0` |
| SM task field | `ctx+0x288` |
| command class vtable | `0x97d4448` |
| command name | `0xaf6dad` |
| command path | `0xa0026e` |
| URL builder | `0x767eaf0` |
| command dispatcher | `0x767cecc` |
| curl_easy_setopt | `0x6886498` |
| http_post_routine | `0x7d038c8` |
| gateinfo_sender | `0x7d0c06c` |
| task factory helpers | `0x7cda280` .. `0x7cda808` |

## Fixed this session

`peerlink/netsplice.py` had a hardcoded Linux path
(`/home/z/my-project/apk_lab/analysis/plt_map.json`) as its fallback for
`plt_map.json`. It now resolves relative to the package. Without this the
socket wiring crashed and **no network code could run at all.**

## Also established

- `.eh_frame` (20 MB) parses to **542,309 real function boundaries** in
  `.text`; validated by 84.6% agreement with `.dynsym` function starts and
  by prologue bytes at `vaddr - 0x4000` for every address we care about.
  Written to `funcs_eh.txt`.
- Address model confirmed: `file offset = vaddr - 0x4000` for `.text`;
  `.rodata`/strings have `offset == vaddr`.
- The env table at `0xa4cff68` is **still all zeros** after the registrars
  — so the URL does not come from there. The builder gets its base from the
  static at `0x97d4448`.

## The session object -- created on demand

`0x7cda280` is a **get-or-create** for the session:

    if (*(0xa4ab6a8)) return it;
    obj = new(0x68); obj->vtable = 0x9821500;
    *(0xa4ab6a8) = obj;  *(0xa4ab6a0) = 3 or 4;

`0x7cda184` and `0x7cda1f8` are the matching **destructors** (they set the
session global back to NULL). Calling `0x7cda280` gives a live session with
**28 real methods** (vtable `0x9821500`), all resolved.

## The task factory

`0x7dc91d8(name, a1, a2, a3, a4)` allocates a **0x460-byte task**, builds
it, and gives it vtable `0x9828a90`. Calling it with `"CmdGetServerEnv"`
produces a real task with the command name embedded at `+0x10`.

Task vtable `0x9828a90` (24 entries). The important ones:

| idx | addr | what it does |
|-----|------|--------------|
| 0 | `0x745aae0` | thunk -> vtable[24] |
| 1 | `0x66d1cd4` | return 1 |
| 2 | `0x7b1f37c` | command-ID dispatch (checks 0x1030007 / 0x1030005) |
| 3 | `0x7dc8fbc` | destructor (frees sub-objects) |
| 4 | `0x7dc9248` | destructor |
| 7 | `0x745aaec` | **return `task->[0xf8]`** -- the state byte the SM checks |
| 8 | `0x7dc911c` | copies 3 param strings (+0x410/+0x428/+0x440) into a request object |
| 10/11 | `0x7dc91c8` / `0x7dc91d0` | return 1 |

## How state 10 gets its task

State 10's prologue reads a **std::string global at `0xa4b2648`** (the
current command name) and calls `0x7dc91d8` on it:

    adrp x8, #0xa4b2000 ; add x8, x8, #0x648
    ldrb w9, [x8] ; ldr x10, [x8, #0x10]   ; std::string SSO unpack
    csinc x0, x10, x8, ne
    bl   0x7dc91d8                         ; -> task
    str  x0, [x19, #0x288]                 ; ctx->task

So the command name is just a string in memory, and the task is built by the
game's own factory. Nothing is fabricated.

## Proof it all works end to end

`create_session.py` / `run_task.py`:

    session = 0xa900003d0010          (28 real methods)
    task    = 0xa900003f0080          ("CmdGetServerEnv" embedded)
    SM at state 10 -> err=None, runs cleanly

## The remaining gap

`curl_easy_setopt` is still never called. Findings:

- **No session method calls the HTTP stack.** All 28 were called directly;
  none reached curl. The session is state/connection management, not transport.
- **No task method calls the HTTP stack either.**
- Backward BFS from the HTTP seeds reaches `0x7cdd628`, `0x7cdbf70`,
  `0x7cdd458`, `0x7d1e358`, `0x7cdbe4c` -- but **no session method**.
- The task's parameter strings (`+0x410` etc.) contain `0x722e1f0a35092110`,
  the invalid pointer that shows up in every MEM FAULT -- so the task was
  built without its parameters. The factory's 4 pointer args are the SM's
  stack addresses, i.e. output parameters the SM fills in before calling.

So the missing link is: **what fills in the task's parameters and sends the
request.** That is the next thing to find.

## Next step

The task's parameters come from the session. Find the session method that
takes a built task and dispatches it -- likely by scanning the session
methods for one that reads a task argument and calls `0x7dc911c` (build) /
`0x7dc91d8` (create) / the transport. Alternatively, unpack the APS2 packed
relocations to recover every pointer table statically, which would give the
full command -> handler -> transport map in one pass.
