// DecompPart2 - decompile the REMAINDER of libUE4.so's .text, picking up
// where the 200-minute FindFullDump DECOMP phase stopped (entry >= START).
//
// Same output format as FindFullDump's DECOMP section:
//   ==== <entry> <name>
//   <decompiled C>
// so the local indexer (work/fd.py) consumes both halves identically.
//
// Env:
//   FULLDUMP2_OUT      output path (default /tmp/fulldump2_out.txt)
//   FULLDUMP_DECOMP_START   hex start entry, default 7530000
//   FULLDUMP_DEADLINE_MIN   minutes from script start, default 200
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

import java.io.BufferedWriter;
import java.io.FileWriter;

public class DecompPart2 extends GhidraScript {

    private static final char[] HEXC = "0123456789abcdef".toCharArray();

    private BufferedWriter w;

    private String hex(long v) {
        StringBuilder sb = new StringBuilder(16);
        sb.append("0x");
        for (int i = 15; i >= 0; i--) {
            sb.append(HEXC[(int) ((v >>> (i * 4)) & 15)]);
        }
        return sb.toString();
    }

    private long countNl(String s) {
        long c = 0;
        for (int i = 0; i < s.length(); i++) {
            if (s.charAt(i) == '\n') c++;
        }
        return c;
    }

    @Override
    public void run() throws Exception {
        String outPath = System.getenv("FULLDUMP2_OUT");
        if (outPath == null || outPath.length() == 0) outPath = "/tmp/fulldump2_out.txt";
        long startAddr = 0x7530000L;
        String startStr = System.getenv("FULLDUMP_DECOMP_START");
        if (startStr != null && startStr.length() > 0) {
            try {
                startAddr = Long.parseLong(startStr.trim().replace("0x", "").replace("0X", ""), 16);
            } catch (NumberFormatException e) {
                println("bad FULLDUMP_DECOMP_START '" + startStr + "', using 7530000");
            }
        }
        long mins = 200L;
        String minStr = System.getenv("FULLDUMP_DEADLINE_MIN");
        if (minStr != null && minStr.length() > 0) {
            try {
                mins = Long.parseLong(minStr.trim());
            } catch (NumberFormatException e) {
                println("bad FULLDUMP_DEADLINE_MIN '" + minStr + "', using 200");
            }
        }
        long deadlineMs = System.currentTimeMillis() + mins * 60000L;
        println("DECOMP2 start path=" + outPath + " from=" + hex(startAddr) + " deadline=" + mins + "min");

        long n = 0;
        long fail = 0;
        long ntrunc = 0;
        long skipped = 0;
        int maxChars = 120000;
        DecompInterface di = new DecompInterface();
        try {
            di.setOptions(new DecompileOptions());
            if (!di.openProgram(currentProgram)) {
                println("openProgram failed");
                return;
            }
            w = new BufferedWriter(new FileWriter(outPath), 1048576);
            FunctionIterator fi = currentProgram.getFunctionManager().getFunctions(true);
            while (fi.hasNext()) {
                if (monitor.isCancelled()) break;
                if (System.currentTimeMillis() > deadlineMs) {
                    println("TRUNCATED DECOMP2: deadline reached after " + n + " functions");
                    break;
                }
                Function f = fi.next();
                if (f.isExternal()) continue;
                long entry = f.getEntryPoint().getOffset();
                if (entry < startAddr) {
                    skipped++;
                    continue;
                }
                DecompileResults res;
                try {
                    res = di.decompileFunction(f, 30, monitor);
                } catch (Exception e) {
                    fail++;
                    continue;
                }
                if (res == null || !res.decompileCompleted() || res.getDecompiledFunction() == null) {
                    fail++;
                    continue;
                }
                String c;
                try {
                    c = res.getDecompiledFunction().getC();
                } catch (Exception e) {
                    fail++;
                    continue;
                }
                if (c == null) { fail++; continue; }
                if (c.length() > maxChars) {
                    c = c.substring(0, maxChars);
                    ntrunc++;
                }
                w.write("==== " + f.getEntryPoint() + " " + f.getName() + "\n");
                w.write(c);
                if (c.length() == 0 || c.charAt(c.length() - 1) != '\n') w.write("\n");
                n++;
                if (n % 500L == 0L) {
                    w.flush();
                    println("DECOMP2 n=" + n + " fail=" + fail + " trunc=" + ntrunc
                            + " last=" + hex(entry));
                }
            }
        } finally {
            try {
                di.dispose();
            } catch (Exception ignore) {
            }
            try {
                if (w != null) {
                    w.write("DECOMP2_COUNT " + n + " fail=" + fail + " truncated=" + ntrunc
                            + " skipped_below_start=" + skipped + "\n");
                    w.flush();
                    w.close();
                }
            } catch (Exception ignore) {
            }
        }
        println("DECOMP2 done n=" + n + " fail=" + fail + " trunc=" + ntrunc
                + " skipped=" + skipped + " path=" + outPath);
    }
}
