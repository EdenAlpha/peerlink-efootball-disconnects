// Ghidra headless Java script: find kill-rule strings, xrefs, decompile callers
// Java port of FindKillRule.py (PyGhidra is not started by analyzeHeadless, .py cannot run)
//@category Analysis

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import ghidra.util.task.ConsoleTaskMonitor;

import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

public class FindKillRule extends GhidraScript {

	private static final String OUT =
		"C:\\Users\\Administrator\\Documents\\Default Project\\peerlink-efootball-disconnects\\efootball-apk\\killrule_out2.txt";

	private static final String[] TARGETS = {
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

	private final List<String> lines = new ArrayList<>();

	private void log(String s) {
		lines.add(s);
		println(s);
	}

	private static String hexPattern(String s) {
		StringBuilder sb = new StringBuilder();
		for (byte b : s.getBytes()) {
			if (sb.length() > 0) {
				sb.append(' ');
			}
			sb.append(String.format("%02x", b));
		}
		return sb.toString();
	}

	@Override
	public void run() throws Exception {
		DecompInterface decomp = new DecompInterface();
		decomp.openProgram(currentProgram);
		ConsoleTaskMonitor mon = new ConsoleTaskMonitor();

		for (String t : TARGETS) {
			log(repeat("=", 80));
			log("TARGET: " + t);
			String hexpat = hexPattern(t);
			Address[] found;
			try {
				found = findBytes(currentProgram.getMinAddress(), hexpat, 5);
			}
			catch (Exception e) {
				log("  find error: " + e);
				continue;
			}
			if (found == null || found.length == 0) {
				log("  no hits");
				continue;
			}
			for (Address a : found) {
				log("  string @ " + a);
				Reference[] refs = getReferencesTo(a);
				int n = 0;
				for (Reference r : refs) {
					if (n >= 8) {
						break;
					}
					Address from = r.getFromAddress();
					Function fa = getFunctionContaining(from);
					log("    xref from " + from + " (" + r.getReferenceType() + ") func=" +
						(fa != null ? fa.getName() : "None"));
					if (fa != null) {
						try {
							DecompileResults res = decomp.decompileFunction(fa, 60, mon);
							if (res != null && res.decompileCompleted() && res.getDecompiledFunction() != null) {
								DecompiledFunction df = res.getDecompiledFunction();
								String[] codeLines = df.getC().split("\n");
								int limit = Math.min(codeLines.length, 120);
								for (int i = 0; i < limit; i++) {
									String l = codeLines[i];
									log("      |" + (l.length() > 220 ? l.substring(0, 220) : l));
								}
							}
							else {
								log("      (decompile failed: " +
									(res != null ? res.getErrorMessage() : "?") + ")");
							}
						}
						catch (Exception e) {
							log("      (decompile exception: " + e + ")");
						}
					}
					n++;
				}
				if (n == 0) {
					log("    (no xrefs)");
				}
			}
		}

		try (PrintWriter pw = new PrintWriter(new FileWriter(OUT))) {
			for (String l : lines) {
				pw.println(l);
			}
			println("WROTE " + OUT + " lines=" + lines.size());
		}
		catch (Exception e) {
			println("WRITE FAIL " + e);
		}
	}

	private static String repeat(String s, int n) {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < n; i++) {
			sb.append(s);
		}
		return sb.toString();
	}
}
