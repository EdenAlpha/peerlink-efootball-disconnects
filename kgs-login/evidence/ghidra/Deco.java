// Ghidra headless: decompile the URL composer + gate builder, and show who
// references the "gate/gate_" format string.
//
//   analyzeHeadless <projdir> <proj> -import libUE4.so -noanalysis
//       -postScript Deco.java
//
//@category PeerLink

import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.util.*;

public class Deco extends GhidraScript {

    static final String[][] FUNCS = {
        {"URL_COMPOSER",   "0x7b099d0"},   // builds "gate/gate_<a>.php"
        {"GATE_BUILDER",   "0x7afd364"},   // supplies `a` = arg1+0x70
        {"GATE_CALLER",    "0x7afe42c"},   // arg1 = obj+0x30
        {"SET_URL_ON_REQ", "0x7b2e334"},   // attaches url+body to request
        {"CMD_CTOR",       "0x767eaf0"},
        {"CMD_BIND",       "0x767ec60"},
        {"CMD_SERIAL",     "0x767edbc"},
    };

    // file VAs of the strings we want xrefs for (precomputed)
    static final String[][] STRS = {
        {"gate/gate_",            "0x9c69b6"},
        {"Insufficient randomness", "0xa1128f"},
    };

    DecompInterface dec;

    public void run() throws Exception {
        String outPath = System.getenv("DECO_OUT");
        if (outPath == null) outPath = "deco_out.txt";
        PrintWriter pw = new PrintWriter(new BufferedWriter(new FileWriter(outPath)));
        dec = new DecompInterface();
        dec.setOptions(new DecompileOptions());
        dec.openProgram(currentProgram);

        AddressSpace sp = currentProgram.getAddressFactory().getDefaultAddressSpace();

        for (String[] t : FUNCS) {
            Address a = sp.getAddress(Long.decode(t[1]));
            pw.println("\n\n########## " + t[0] + " " + t[1] + " ##########");
            Function f = getFunctionAt(a);
            if (f == null) {
                try { f = createFunction(a, "fn_" + t[1]); }
                catch (Exception e) { f = getFunctionContaining(a); }
            }
            if (f == null) { pw.println("  (no function)"); continue; }
            pw.println("// function " + f.getName() + " " + f.getEntryPoint());
            pw.println(decompile(f));
        }

        pw.println("\n\n########## STRING XREFS ##########");
        for (String[] s : STRS) {
            Address a = sp.getAddress(Long.decode(s[1]));
            pw.println("\n=== " + s[0] + " @ " + s[1] + " ===");
            ReferenceIterator it = currentProgram.getReferenceManager().getReferencesTo(a);
            int n = 0;
            while (it.hasNext()) {
                Reference r = it.next();
                n++;
                Address from = r.getFromAddress();
                pw.println("  from " + from);
                Function f = getFunctionContaining(from);
                if (f == null) {
                    try { f = createFunction(from, "fn_" + from); }
                    catch (Exception e) { }
                }
                if (f != null) {
                    pw.println("  in " + f.getName() + " " + f.getEntryPoint());
                    pw.println(decompile(f));
                }
            }
            pw.println("  xrefs: " + n);
        }
        pw.close();
        println("wrote " + outPath);
    }

    String decompile(Function f) {
        try {
            DecompileResults r = dec.decompileFunction(f, 120, monitor);
            if (r == null || !r.decompileCompleted()) {
                return "  (decompile failed)";
            }
            return r.getDecompiledFunction().getC();
        } catch (Exception e) {
            return "  (decompile exception: " + e + ")";
        }
    }
}
