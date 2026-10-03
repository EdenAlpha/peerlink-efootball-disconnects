// Find the code that builds the game's encrypted KGS body.
// We know the header literal "pes-custom-encrypt" exists at ~0xad120e.
// Find every function whose instructions reference a pointer into that region,
// then dump the string literals that function loads - the AES key and IV
// will be among them.
//
// Photocopier: read the key out of the game's own binary. Never guess it.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.mem.*;
import java.util.*;

public class FindEncryptKey extends GhidraScript {

    @Override
    public void run() throws Exception {
        Memory mem = currentProgram.getMemory();
        Listing listing = currentProgram.getListing();

        // 1. Locate the "pes-custom-encrypt" literal.
        Address hdr = find(mem, "pes-custom-encrypt");
        println("header literal at: " + hdr);
        if (hdr == null) { println("NOT FOUND"); return; }

        // 2. Image base, so we can convert the file offset we already know.
        Address imgBase = currentProgram.getImageBase();
        println("image base: " + imgBase);

        // 3. Scan all defined instructions for a reference into a window
        //    around the header string. AAD/ADR-style loads in AArch64
        //    typically point at the literal pool, so match a range.
        long hdrOff = hdr.getOffset();
        long lo = hdrOff - 0x4000;
        long hi = hdrOff + 0x4000;
        println("matching refs into 0x" + Long.toHexString(lo)
                + " - 0x" + Long.toHexString(hi));

        Set<Function> hits = new HashSet<>();
        InstructionIterator it = listing.getInstructions(true);
        long scanned = 0;
        while (it.hasNext() && !monitor.isCancelled()) {
            Instruction ins = it.next();
            scanned++;
            for (Reference r : ins.getReferencesFrom()) {
                long to = r.getToAddress().getOffset();
                if (to >= lo && to <= hi) {
                    Function f = getFunctionContaining(ins.getAddress());
                    if (f != null) hits.add(f);
                }
            }
        }
        println("instructions scanned: " + scanned);
        println("functions referencing the header region: " + hits.size());

        int n = 0;
        for (Function f : hits) {
            println("---------------------------------------------");
            println("FUNC " + f.getName() + " @ " + f.getEntryPoint());
            println("  size " + f.getBody().getNumAddresses());
            // dump every string constant this function's body can reach
            Set<String> lits = new LinkedHashSet<>();
            for (Instruction ins : listing.getInstructions(f.getBody(), true)) {
                for (Reference r : ins.getReferencesFrom()) {
                    Address to = r.getToAddress();
                    if (to == null) continue;
                    try {
                        String s = readAscii(mem, to, 96);
                        if (s != null && s.length() >= 4) lits.add(s);
                    } catch (Exception e) { /* unmapped */ }
                }
            }
            for (String s : lits) println("   LIT: " + s);
            if (++n >= 12) break;
        }
    }

    private Address find(Memory mem, String needle) {
        // GhidraScript.find returns the first Address holding the string.
        // (Memory.findBytes with null args risks NPEs; avoid it.)
        return find(currentProgram.getMinAddress(), needle);
    }

    private String readAscii(Memory mem, Address a, int max) throws Exception {
        byte[] buf = new byte[max];
        int got = 0;
        Address cur = a;
        while (got < max) {
            if (!mem.isDefined(cur)) break;
            byte b = mem.getByte(cur);
            if (b < 0x20 || b > 0x7e) break;
            buf[got++] = b;
            cur = cur.add(1);
        }
        if (got < 4) return null;
        return new String(buf, 0, got);
    }
}