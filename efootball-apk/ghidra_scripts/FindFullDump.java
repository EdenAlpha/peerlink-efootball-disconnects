// Full dump: every defined function + every rodata string with xrefs.
// Runs after full auto-analysis. Output is text (tens of MB), uploaded as
// artifact. Caps keep it artifact-sized; counts are always printed so a
// truncated section is visible, never silent.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.mem.*;
import java.io.FileWriter;
import java.util.*;

public class FindFullDump extends GhidraScript {

    private FileWriter w;
    private long wlines = 0;
    private static final int MAX_STRINGS = 200000;
    private static final int MAX_FUNCS = 200000;
    private static final int MAX_XREFS = 8;

    private void emit(String s) throws Exception {
        w.write(s + "\n");
        wlines++;
    }

    @Override
    public void run() throws Exception {
        String outPath = System.getenv("FULLDUMP_OUT");
        if (outPath == null) outPath = "/tmp/fulldump_out.txt";
        w = new FileWriter(outPath);
        Listing listing = currentProgram.getListing();
        Memory mem = currentProgram.getMemory();

        // ---- 1. all functions
        emit("=== FUNCTIONS ===");
        long nfunc = 0;
        FunctionIterator fits = currentProgram.getFunctionManager().getFunctions(true);
        while (fits.hasNext() && nfunc < MAX_FUNCS) {
            if (monitor.isCancelled()) break;
            Function f = fits.next();
            emit("FUNC " + f.getName() + " @ " + f.getEntryPoint()
                    + " size=" + f.getBody().getNumAddresses());
            nfunc++;
        }
        emit("FUNC_COUNT " + nfunc);

        // ---- 2. all printable strings in read-only blocks + xrefs
        emit("=== STRINGS ===");
        long nstr = 0;
        for (MemoryBlock b : mem.getBlocks()) {
            if (!b.isRead() || b.isWrite() || !b.isLoaded()) continue;
            if (monitor.isCancelled()) break;
            Address start = b.getStart();
            Address end = b.getEnd();
            long len = end.subtract(start);
            if (len <= 0 || len > 200000000L) continue;
            byte[] buf;
            try {
                buf = new byte[(int) Math.min(len, 67108864)];
            } catch (Exception e) {
                continue;
            }
            long off = 0;
            while (off < len && nstr < MAX_STRINGS) {
                if (monitor.isCancelled()) break;
                int chunk = (int) Math.min(buf.length, len - off);
                try {
                    mem.getBytes(start.add(off), buf, 0, chunk);
                } catch (Exception e) {
                    break;
                }
                int runStart = -1;
                for (int i = 0; i < chunk; i++) {
                    byte c = buf[i];
                    boolean printable = c >= 0x20 && c < 0x7f;
                    if (printable && runStart < 0) runStart = i;
                    if (!printable || i == chunk - 1) {
                        if (runStart >= 0) {
                            int runLen = (printable && i == chunk - 1)
                                    ? (i - runStart + 1) : (i - runStart);
                            if (runLen >= 4) {
                                int show = Math.min(runLen, 120);
                                String s = new String(buf, runStart, show);
                                Address sa = start.add(off + runStart);
                                StringBuilder sb = new StringBuilder();
                                sb.append("STR ").append(sa).append(" ");
                                sb.append(s.replace('\n', ' '));
                                Reference[] refs = getReferencesTo(sa);
                                int nr = 0;
                                for (Reference r : refs) {
                                    if (nr >= MAX_XREFS) break;
                                    Function fa = getFunctionContaining(r.getFromAddress());
                                    sb.append(" |").append(r.getFromAddress())
                                      .append("@").append(fa == null ? "null" : fa.getName());
                                    nr++;
                                }
                                emit(sb.toString());
                                nstr++;
                                if (nstr >= MAX_STRINGS) break;
                            }
                            runStart = -1;
                        }
                    }
                }
                off += chunk;
            }
        }
        emit("STR_COUNT " + nstr);
        w.close();
        println("WROTE " + outPath + " lines=" + wlines);
    }
}
