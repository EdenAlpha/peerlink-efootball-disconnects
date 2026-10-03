// Find kill-rule strings, xrefs, decompile callers (Java port of FindKillRule.py).
// .py Ghidra scripts do NOT run under analyzeHeadless (needs PyGhidra);
// this Java version runs natively headless. Output goes to stdout, which
// the kgs-ghidra workflow tees into ghidra_run.log (uploaded always), and
// is also written to OUT for the artifact.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.task.ConsoleTaskMonitor;
import java.io.FileWriter;
import java.util.*;

public class FindKillRule extends GhidraScript {

    private List<String> lines = new ArrayList<String>();
    private DecompInterface decomp;

    private void log(String s) {
        lines.add(s);
        println(s);
    }

    @Override
    public void run() throws Exception {
        String[] targets = {
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
        };
        decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        for (String t : targets) {
            log("================================================================================");
            log("TARGET: " + t);
            List<Address> found = new ArrayList<Address>();
            try {
                AddressSetView hits = findBytes(currentProgram.getMinAddress(), t, 5, 1);
                if (hits != null) {
                    AddressIterator ai = hits.getAddresses(true);
                    while (ai.hasNext() && found.size() < 5) found.add(ai.next());
                }
            } catch (Exception e) {
                log("  find error: " + e);
                continue;
            }
            if (found.isEmpty()) {
                log("  no hits");
                continue;
            }
            for (Address a : found) {
                log("  string @ " + a);
                Reference[] refs = getReferencesTo(a);
                int n = 0;
                for (Reference r : refs) {
                    if (n >= 8) break;
                    Function fa = getFunctionContaining(r.getFromAddress());
                    log("    xref from " + r.getFromAddress() + " ("
                            + r.getReferenceType() + ") func=" + fa);
                    if (fa != null) {
                        try {
                            DecompileResults res = decomp.decompileFunction(fa, 60, monitor);
                            if (res != null && res.getDecompiledFunction() != null) {
                                String[] code = res.getDecompiledFunction().getC().split("\n");
                                for (int i = 0; i < Math.min(code.length, 120); i++) {
                                    String l = code[i];
                                    log("      |" + (l.length() > 220 ? l.substring(0, 220) : l));
                                }
                            } else {
                                log("      (decompile failed)");
                            }
                        } catch (Exception e) {
                            log("      (decompile exception: " + e + ")");
                        }
                    }
                    n++;
                }
                if (n == 0) log("    (no xrefs)");
            }
        }
        String outPath = System.getenv("KILLRULE_OUT");
        if (outPath == null) outPath = "/tmp/killrule_out.txt";
        try {
            FileWriter w = new FileWriter(outPath);
            for (String l : lines) w.write(l + "\n");
            w.close();
            println("WROTE " + outPath + " lines=" + lines.size());
        } catch (Exception e) {
            println("WRITE FAIL " + e);
        }
    }
}
