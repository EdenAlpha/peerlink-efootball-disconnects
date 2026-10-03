// Recover vtables + decompile the gate request path with Ghidra headless.
//
// The APK ships with vtable slots zeroed (no .rela.dyn / DT_RELR), which is
// why every virtual call in our Unicorn harness jumps to 0.  Ghidra's ELF
// loader and its "Recovered Vtables" analysis can still infer class layouts
// from constructor stores, and its decompiler gives us the real login code
// without us having to hand-trace it.
//
// @category PeerLink
// @keyanalysis

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

import java.io.*;
import java.util.*;

public class RecoverVtables extends GhidraScript {

    private static final long TEXT_LO = 0x28293c0L;
    private static final long TEXT_HI = 0x8b75140L;

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        File out = new File(args.length > 0 ? args[0] : "vtables.txt");
        PrintWriter w = new PrintWriter(new BufferedWriter(new FileWriter(out)));

        Memory mem = currentProgram.getMemory();
        SymbolTable st = currentProgram.getSymbolTable();

        w.println("program: " + currentProgram.getName());
        w.println("image base: " + currentProgram.getImageBase());

        // ---- 1. how many functions did Ghidra define? ------------------
        int fns = 0;
        Iterator<Function> fi = currentProgram.getFunctionManager()
                .getFunctions(true);
        while (fi.hasNext()) { fi.next(); fns++; }
        w.println("functions defined: " + fns);
        w.println();

        // ---- 2. dump Ghidra's view of every vtable-shaped data run ------
        w.println("=== vtable-shaped runs (>=3 text pointers) ===");
        int found = 0;
        Address a = mem.getMinAddress();
        Address end = mem.getMaxAddress();
        long cur = -1, runLen = 0;
        long step = 8;
        for (Address p = a; p != null && p.compareTo(end) < 0;
             p = p.add(step)) {
            long v = readQ(p);
            boolean ok = (v >= TEXT_LO && v < TEXT_HI) && v != 0;
            if (ok) {
                if (cur < 0) { cur = p.getOffset(); runLen = 1; }
                else { runLen++; }
            } else {
                if (cur >= 0 && runLen >= 3) {
                    found++;
                    w.println(String.format("  vtable %s  slots=%d",
                            toAddr(cur), runLen));
                    for (long i = 0; i < Math.min(runLen, 16); i++) {
                        long slot = readQ(toAddr(cur + i * 8));
                        w.println(String.format("      [%2d] %s", i,
                                toAddr(slot)));
                    }
                }
                cur = -1; runLen = 0;
            }
        }
        w.println("total vtable-shaped runs: " + found);
        w.println();

        // ---- 3. the specific vtable the CMD_GET_SERVER_ENV ctor uses ---
        w.println("=== ctor vtable 0x97d4448 ===");
        for (int i = 0; i < 16; i++) {
            Address p = toAddr(0x97d4448L + i * 8L);
            long v = readQ(p);
            w.println(String.format("  [%2d] %#018x %s", i, v,
                    (v >= TEXT_LO && v < TEXT_HI) ? "TEXT" : ""));
        }
        w.println();

        // ---- 4. references INTO that vtable region (who installs it) ---
        w.println("=== refs to 0x97d4448 ===");
        for (Reference r : getReferencesTo(toAddr(0x97d4448L))) {
            w.println("  from " + r.getFromAddress() + "  " +
                      currentProgram.getListing().getInstructionAt(
                              r.getFromAddress()));
        }
        w.println();

        // ---- 5. decompile the gate request builder ---------------------
        for (long tgt : new long[] { 0x7afd364L, 0x7b099d0L, 0x767eaf0L,
                                     0x74e3374L, 0x767ec60L, 0x767edbcL }) {
            Address t = toAddr(tgt);
            Function f = getFunctionAt(t);
            w.println("=== " + t + " ===");
            if (f == null) { w.println("  (no function)"); continue; }
            w.println("  name: " + f.getName() + "  sig: " + f.getSignature());
            DecompInterface di = new DecompInterface();
            di.openProgram(currentProgram);
            DecompileResults dr = di.decompileFunction(f, 60, monitor);
            if (dr != null && dr.decompileCompleted()) {
                w.println(dr.getDecompiledFunction().getC());
            } else {
                w.println("  (decompile failed)");
            }
            di.dispose();
            w.println();
        }

        w.close();
        println("wrote " + out.getAbsolutePath());
    }

    private long readQ(Address p) {
        try {
            return currentProgram.getMemory().getLong(p);
        } catch (Exception e) {
            return 0;
        }
    }
}
