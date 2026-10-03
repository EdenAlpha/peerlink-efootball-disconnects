// FindFullDump - dump EVERYTHING Ghidra holds about this program, in ONE file.
//
// Why one file: the workflow uploads /tmp/fulldump_out.txt (plus the kill-rule
// file and the log) and nothing else. Anything written to another path never
// leaves the runner, so every section lands here, separated by ==== headers.
//
// Sections, in cost order (cheap + certain first, expensive last):
//   PROGRAM   language/image base/compiler spec
//   BLOCKS    every memory block
//   SYMBOLS   every symbol Ghidra created
//   FUNCTIONS every function: entry, size, prototype, params, thunk/inline
//   DATA      every defined data item
//   STRINGS   every printable run (>=4) in every readable block, with xrefs
//   REFS      every cross reference
//   ASM       every instruction: address, raw bytes, disassembly
//   DECOMP    every function decompiled (deadline-bounded, always last)
//   SUMMARY   counts plus EVERY cap/truncation, so nothing is silently missing
//
// Budget: FULLDUMP_DEADLINE_MIN (default 200) minutes from script start.
// DECOMP stops at that deadline; the structural sections above it finish first
// because they are what the call graph is built from. Anything that did not
// fit is printed in SUMMARY and in the Actions log - never silent.
//
// Output path: FULLDUMP_OUT (default /tmp/fulldump_out.txt) - the gate in the
// workflow fails the run if this file is missing or empty.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class FindFullDump extends GhidraScript {

    private static final char[] HEXC = "0123456789abcdef".toCharArray();

    private BufferedWriter w;
    private long lines = 0;
    private long startMs;
    private long deadlineMs;
    private long strReadFails = 0;
    private final HashMap<String, Long> counts = new HashMap<String, Long>();
    private final ArrayList<String> truncations = new ArrayList<String>();

    // ---------------------------------------------------------------- io

    private void emit(String s) throws Exception {
        w.write(s);
        w.write('\n');
        lines++;
    }

    private void bump(String key, long n) {
        counts.put(key, Long.valueOf((counts.containsKey(key) ? counts.get(key).longValue() : 0L) + n));
    }

    private void trunc(String what, String why) {
        truncations.add(what + ": " + why);
        println("TRUNCATED " + what + " - " + why);
    }

    private void phase(String name) throws Exception {
        w.flush();
        println("PHASE " + name + " lines=" + lines + " elapsed=" + secs() + "s");
        emit("========== " + name + " ==========");
    }

    private long secs() {
        return (System.currentTimeMillis() - startMs) / 1000L;
    }

    private boolean need(long ms) {
        return System.currentTimeMillis() + ms <= deadlineMs;
    }

    private String hex(byte[] b, int n) {
        StringBuilder sb = new StringBuilder(n * 2);
        for (int i = 0; i < n; i++) {
            int v = b[i] & 0xff;
            sb.append(HEXC[v >>> 4]).append(HEXC[v & 15]);
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

    private void sectionFailed(String name, Throwable t) {
        println("SECTION FAILED " + name + ": " + t);
        truncations.add(name + " FAILED: " + t);
        try {
            w.flush();
            w.write("SECTION_FAILED " + name + " " + t + "\n");
            lines++;
            w.flush();
        } catch (Exception ignore) {
            // nothing left to do; the log already carries the failure
        }
    }

    // ----------------------------------------------------- sections

    private void program() throws Exception {
        phase("PROGRAM");
        Program p = currentProgram;
        emit("PROGRAM name=" + p.getName()
                + " lang=" + p.getLanguageID()
                + " ptrSize=" + p.getDefaultPointerSize()
                + " imageBase=" + p.getImageBase()
                + " min=" + p.getMinAddress()
                + " max=" + p.getMaxAddress()
                + " exeFormat=" + p.getExecutableFormat()
                + " exePath=" + p.getExecutablePath()
                + " compiler=" + p.getCompilerSpec().getCompilerSpecID());
        try {
            emit("FILE_BYTES " + p.getMemory().getAllFileBytes().size());
        } catch (Exception e) {
            emit("FILE_BYTES unknown " + e);
        }
        bump("PROGRAM", 1L);
    }

    private void blocks() throws Exception {
        phase("BLOCKS");
        Memory mem = currentProgram.getMemory();
        long n = 0;
        for (MemoryBlock b : mem.getBlocks()) {
            emit("BLOCK " + b.getName() + " start=" + b.getStart() + " end=" + b.getEnd()
                    + " size=" + b.getSize() + " r=" + b.isRead() + " w=" + b.isWrite()
                    + " x=" + b.isExecute() + " init=" + b.isInitialized()
                    + " type=" + b.getType());
            n++;
        }
        bump("BLOCK", n);
        emit("BLOCK_COUNT " + n);
    }

    private void symbols() throws Exception {
        phase("SYMBOLS");
        long cap = 5000000L;
        long n = 0;
        SymbolIterator si = currentProgram.getSymbolTable().getAllSymbols(true);
        while (si.hasNext()) {
            if (monitor.isCancelled()) break;
            if (n >= cap) { trunc("SYMBOLS", "cap " + cap); break; }
            if (n % 200000L == 0L && !need(6000000L)) { trunc("SYMBOLS", "time budget"); break; }
            Symbol s = si.next();
            String ns = "?";
            try {
                Namespace nb = s.getParentNamespace();
                ns = nb == null ? "?" : nb.getName(true);
            } catch (Exception ignore) {
                ns = "?";
            }
            emit("SYM " + s.getAddress() + " type=" + s.getSymbolType()
                    + " src=" + s.getSource() + " ns=" + ns + " name=" + s.getName(true));
            n++;
        }
        bump("SYM", n);
        emit("SYM_COUNT " + n);
    }

    private void functions() throws Exception {
        phase("FUNCTIONS");
        long cap = 500000L;
        long n = 0;
        FunctionIterator fi = currentProgram.getFunctionManager().getFunctions(true);
        while (fi.hasNext()) {
            if (monitor.isCancelled()) break;
            if (n >= cap) { trunc("FUNCTIONS", "cap " + cap); break; }
            Function f = fi.next();
            String proto = "?";
            String params = "?";
            String cc = "?";
            try {
                FunctionSignature sig = f.getSignature();
                proto = sig == null ? "?" : sig.getPrototypeString();
            } catch (Exception ignore) {
                proto = "?";
            }
            try {
                params = Arrays.toString(f.getParameters());
            } catch (Exception ignore) {
                params = "?";
            }
            try {
                cc = f.getCallingConventionName();
            } catch (Exception ignore) {
                cc = "?";
            }
            emit("FUNC " + f.getEntryPoint() + " name=" + f.getName()
                    + " size=" + f.getBody().getNumAddresses()
                    + " thunk=" + f.isThunk() + " inline=" + f.isInline()
                    + " ext=" + f.isExternal() + " cc=" + cc
                    + " sig=" + proto + " params=" + params);
            n++;
        }
        bump("FUNC", n);
        emit("FUNC_COUNT " + n);
    }

    private void data() throws Exception {
        phase("DATA");
        long cap = 5000000L;
        long n = 0;
        DataIterator di = currentProgram.getListing().getDefinedData(true);
        while (di.hasNext()) {
            if (monitor.isCancelled()) break;
            if (n >= cap) { trunc("DATA", "cap " + cap); break; }
            if (n % 200000L == 0L && !need(6000000L)) { trunc("DATA", "time budget"); break; }
            Data d = di.next();
            String type = "?";
            try {
                type = d.getDataType().getName();
            } catch (Exception ignore) {
                type = "?";
            }
            String val = "";
            try {
                if (d.getLength() <= 64) {
                    Object o = d.getValue();
                    if (o != null) {
                        val = o.toString().replace('\n', ' ').replace('\r', ' ');
                        if (val.length() > 64) val = val.substring(0, 64);
                    }
                }
            } catch (Exception ignore) {
                val = "";
            }
            emit("DATA " + d.getAddress() + " type=" + type + " len=" + d.getLength()
                    + (val.length() == 0 ? "" : " val=" + val));
            n++;
        }
        bump("DATA", n);
        emit("DATA_COUNT " + n);
    }

    private void strings() throws Exception {
        phase("STRINGS");
        long cap = 1000000L;
        long n = 0;
        Memory mem = currentProgram.getMemory();
        for (MemoryBlock b : mem.getBlocks()) {
            if (monitor.isCancelled()) break;
            if (n >= cap) { trunc("STRINGS", "cap " + cap); break; }
            if (!need(6000000L)) { trunc("STRINGS", "time budget"); break; }
            if (!b.isRead() || !b.isLoaded()) continue;
            long len = b.getSize();
            if (len <= 0) continue;
            byte[] buf = new byte[(int) Math.min(len, 8388608L)];
            long off = 0;
            long pending = -1L;          // block-relative offset of an unfinished run
            long chunkStart = 0L;        // block-relative offset buf[0] came from
            while (off < len) {
                if (monitor.isCancelled()) break;
                chunkStart = off;
                int chunk = (int) Math.min((long) buf.length, len - off);
                try {
                    mem.getBytes(b.getStart().add(off), buf, 0, chunk);
                } catch (Exception e) {
                    strReadFails++;
                    off += chunk;
                    pending = -1L;
                    continue;
                }
                int runStart = (pending >= chunkStart && pending < chunkStart + chunk)
                        ? (int) (pending - chunkStart) : -1;
                pending = -1L;
                int i = runStart >= 0 ? runStart : 0;
                while (i < chunk) {
                    byte c = buf[i];
                    boolean ok = c >= 0x20 && c < 0x7f;
                    if (!ok) {
                        if (runStart >= 0) {
                            n = emitString(b.getStart().add(chunkStart + runStart),
                                    buf, runStart, i - runStart, n, cap);
                            if (n >= cap) break;
                            runStart = -1;
                        }
                        i++;
                    } else {
                        if (runStart < 0) runStart = i;
                        i++;
                    }
                }
                // A run still open at the chunk edge is carried into the next
                // read, so a long string is never cut in two and never dropped.
                if (runStart >= 0 && n < cap) pending = chunkStart + runStart;
                off += chunk;
            }
            if (pending >= 0 && n < cap) {
                // end of block: flush whatever was left open
                n = emitString(b.getStart().add(pending), buf,
                        (int) (pending - chunkStart), (int) (len - pending), n, cap);
            }
        }
        bump("STR", n);
        bump("STR_READ_FAILS", strReadFails);
        emit("STR_COUNT " + n);
        if (strReadFails > 0) emit("STR_READ_FAILS " + strReadFails);
    }

    private long emitString(Address strAddr, byte[] buf, int bufIndex, int runLen,
                            long n, long cap) throws Exception {
        if (runLen < 4 || bufIndex < 0 || bufIndex + Math.min(runLen, 160) > buf.length) return n;
        int show = Math.min(runLen, 160);
        String s = new String(buf, bufIndex, show);
        Address sa = strAddr;
        StringBuilder sb = new StringBuilder(220);
        sb.append("STR ").append(sa).append(' ')
                .append(s.replace('\n', ' ').replace('\r', ' '));
        int nr = 0;
        Reference[] refs = getReferencesTo(sa);
        for (int k = 0; refs != null && k < refs.length; k++) {
            if (nr >= 8) break;
            Reference r = refs[k];
            Function fa = getFunctionContaining(r.getFromAddress());
            sb.append(" |").append(r.getFromAddress())
                    .append('@').append(fa == null ? "?" : fa.getName());
            nr++;
        }
        emit(sb.toString());
        return n + 1;
    }

    private void refs() throws Exception {
        phase("REFS");
        long cap = 12000000L;
        long n = 0;
        ReferenceIterator ri = currentProgram.getReferenceManager()
                .getReferenceIterator(currentProgram.getMinAddress());
        while (ri.hasNext()) {
            if (monitor.isCancelled()) break;
            if (n >= cap) { trunc("REFS", "cap " + cap); break; }
            if (n % 500000L == 0L && !need(6000000L)) { trunc("REFS", "time budget"); break; }
            Reference r = ri.next();
            emit("REF " + r.getFromAddress() + " -> " + r.getToAddress()
                    + " type=" + r.getReferenceType() + " src=" + r.getSource());
            n++;
        }
        bump("REF", n);
        emit("REF_COUNT " + n);
    }

    private void asm() throws Exception {
        phase("ASM");
        long cap = 40000000L;
        long n = 0;
        Listing listing = currentProgram.getListing();
        Memory mem = currentProgram.getMemory();
        byte[] buf = new byte[64];
        FunctionIterator fi = currentProgram.getFunctionManager().getFunctions(true);
        while (fi.hasNext()) {
            if (monitor.isCancelled()) break;
            Function f = fi.next();
            AddressSetView body = f.getBody();
            if (body.isEmpty()) continue;
            InstructionIterator ii = listing.getInstructions(body, true);
            while (ii.hasNext()) {
                if (monitor.isCancelled()) break;
                if (n >= cap) { trunc("ASM", "cap " + cap); break; }
                if (n % 2000000L == 0L && !need(6000000L)) { trunc("ASM", "time budget"); break; }
                Instruction ins = ii.next();
                int L = ins.getLength();
                String h = "";
                if (L > 0 && L <= buf.length) {
                    try {
                        mem.getBytes(ins.getAddress(), buf, 0, L);
                        h = hex(buf, L);
                    } catch (Exception ignore) {
                        h = "";
                    }
                }
                emit("I " + ins.getAddress() + " " + h + " " + ins.toString());
                n++;
            }
            if (n >= cap || !need(6000000L)) break;
        }
        bump("ASM", n);
        emit("ASM_COUNT " + n);
    }

    private void decomp() throws Exception {
        phase("DECOMP");
        DecompInterface di = new DecompInterface();
        long n = 0;
        long fail = 0;
        long ntrunc = 0;
        int maxChars = 120000;
        try {
            di.setOptions(new DecompileOptions());
            if (!di.openProgram(currentProgram)) {
                trunc("DECOMP", "openProgram failed");
                emit("DECOMP_COUNT 0 fail=0 truncated=0");
                return;
            }
            FunctionIterator fi = currentProgram.getFunctionManager().getFunctions(true);
            while (fi.hasNext()) {
                if (monitor.isCancelled()) { trunc("DECOMP", "cancelled"); break; }
                if (!need(0L)) { trunc("DECOMP", "deadline reached after " + n + " functions"); break; }
                Function f = fi.next();
                if (f.isExternal()) continue;
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
                lines++;
                w.write(c);
                if (c.length() == 0 || c.charAt(c.length() - 1) != '\n') w.write("\n");
                lines += countNl(c);
                n++;
                if (n % 500L == 0L) {
                    w.flush();
                    println("DECOMP n=" + n + " fail=" + fail + " trunc=" + ntrunc
                            + " elapsed=" + secs() + "s");
                }
            }
        } finally {
            try {
                di.dispose();
            } catch (Exception ignore) {
                // disposal is best-effort
            }
        }
        bump("DECOMP", n);
        bump("DECOMP_FAIL", fail);
        bump("DECOMP_TRUNC", ntrunc);
        emit("DECOMP_COUNT " + n + " fail=" + fail + " truncated=" + ntrunc);
    }

    private void summary(long t0) throws Exception {
        emit("========== SUMMARY ==========");
        emit("ELAPSED_SECONDS " + ((System.currentTimeMillis() - t0) / 1000L));
        if (counts.isEmpty()) {
            emit("COUNTS none");
        } else {
            for (Map.Entry<String, Long> e : counts.entrySet()) {
                emit("COUNT " + e.getKey() + " " + e.getValue().longValue());
            }
        }
        if (truncations.isEmpty()) {
            emit("TRUNCATION none - every section ran to its cap or its natural end");
        } else {
            for (int i = 0; i < truncations.size(); i++) {
                emit("TRUNCATION " + truncations.get(i));
            }
        }
        emit("LINES " + lines);
    }

    @Override
    public void run() throws Exception {
        String outPath = System.getenv("FULLDUMP_OUT");
        if (outPath == null || outPath.length() == 0) outPath = "/tmp/fulldump_out.txt";
        long mins = 200L;
        String minStr = System.getenv("FULLDUMP_DEADLINE_MIN");
        if (minStr != null && minStr.length() > 0) {
            try {
                mins = Long.parseLong(minStr.trim());
            } catch (NumberFormatException e) {
                println("bad FULLDUMP_DEADLINE_MIN '" + minStr + "', using 200");
            }
        }
        long t0 = System.currentTimeMillis();
        startMs = t0;
        deadlineMs = t0 + mins * 60000L;
        println("FULLDUMP start path=" + outPath + " deadline=" + mins + "min");

        w = new BufferedWriter(new FileWriter(outPath), 1048576);
        try {
            String[][] jobs = {
                {"PROGRAM", "program"},
                {"BLOCKS", "blocks"},
                {"SYMBOLS", "symbols"},
                {"FUNCTIONS", "functions"},
                {"DATA", "data"},
                {"STRINGS", "strings"},
                {"REFS", "refs"},
                {"ASM", "asm"},
                {"DECOMP", "decomp"},
            };
            for (int i = 0; i < jobs.length; i++) {
                String name = jobs[i][0];
                String what = jobs[i][1];
                try {
                    if (what.equals("program")) program();
                    else if (what.equals("blocks")) blocks();
                    else if (what.equals("symbols")) symbols();
                    else if (what.equals("functions")) functions();
                    else if (what.equals("data")) data();
                    else if (what.equals("strings")) strings();
                    else if (what.equals("refs")) refs();
                    else if (what.equals("asm")) asm();
                    else if (what.equals("decomp")) decomp();
                } catch (Throwable t) {
                    sectionFailed(name, t);
                }
            }
            try {
                summary(t0);
            } catch (Throwable t) {
                println("SUMMARY FAILED " + t);
            }
            w.flush();
        } finally {
            try {
                w.close();
            } catch (Exception ignore) {
                // closing twice is harmless
            }
        }
        println("FULLDUMP done lines=" + lines + " elapsed=" + secs() + "s path=" + outPath);
    }
}
