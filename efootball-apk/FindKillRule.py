# Ghidra Jython script: find kill-rule strings, xrefs, decompile callers
# @category: Analysis
import os
targets = [
    "E_TURN_ALLOCATION_MISSMATCH",
    "MATCH_STOP_COUNT_SELF_BUF_EMPTY",
    "TurnReconnectWaitTimeMs",
    "NTL_PEER_KEEPALIVE_COUNT",
    "KeepAliveTimerUs",
    "reflexive_address",
    "CmdGetTurnServerList",
    "DETECT_NAT_ABORTED",
    "MatchAbortTimerCoefficient",
    "is_cheat_user",
    "OnlineModeTaskCheckCheat",
    "CHECK_STUN_RTT_TIMEOUT",
    "NTL_PEER_KEEPALIVE",
    "MultiplaySessionRecvThreadReceiveTimeoutUs",
]
out_path = os.path.join(str(getGhidraHome() if False else ""), "")
# output next to script via environment? use fixed path passed as arg
out_file = None
try:
    args = getScriptArgs()
    if args and len(args) > 0:
        out_file = args[0]
except:
    pass
if out_file is None:
    out_file = "/tmp/ghidra_killrule.txt"
lines = []
def log(s):
    lines.append(s)
    print(s)
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
decomp = DecompInterface()
decomp.openProgram(currentProgram)
listing = currentProgram.getListing()
mem = currentProgram.getMemory()
fm = currentProgram.getFunctionManager()
for t in targets:
    log("="*80)
    log("TARGET: " + t)
    tbytes = t.encode()
    found = []
    for block in mem.getBlocks():
        if not block.isInitialized():
            continue
        try:
            addr = findBytes(block.getStart(), tbytes, 1, ConsoleTaskMonitor())
        except Exception as e:
            continue
        while addr is not None and len(found) < 5:
            found.append(addr)
            try:
                addr = findBytes(addr.add(1), tbytes, 1, ConsoleTaskMonitor())
            except:
                break
    if not found:
        log("  no hits")
        continue
    for a in found:
        log("  string @ " + str(a))
        refs = getReferencesTo(a)
        n = 0
        for r in refs:
            if n >= 8:
                break
            fa = getFunctionContaining(r.getFromAddress())
            log("    xref from " + str(r.getFromAddress()) + " (" + r.getReferenceType().toString() + ") func=" + (str(fa) if fa else "None"))
            if fa is not None:
                try:
                    res = decomp.decompileFunction(fa, 60, ConsoleTaskMonitor())
                    if res and res.getDecompiledFunction():
                        code = res.getDecompiledFunction().getC()
                        for i, l in enumerate(code.split("\n")[:120]):
                            log("      |" + l[:220])
                    else:
                        log("      (decompile failed: " + str(res.getErrorMessage() if res else "?") + ")")
                except Exception as e:
                    log("      (decompile exception: " + str(e) + ")")
            n += 1
        if n == 0:
            log("    (no xrefs)")
try:
    open(out_file, "w").write("\n".join(lines))
    print("WROTE " + out_file + " lines=" + str(len(lines)))
except Exception as e:
    print("WRITE FAIL " + str(e))
