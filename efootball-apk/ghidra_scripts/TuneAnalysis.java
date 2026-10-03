import ghidra.app.script.GhidraScript;
import ghidra.framework.options.Options;

/**
 * Pre-analysis tuning for the 160 MB stripped libUE4.so.
 *
 * Run #4 (37087695414) completed in ~71 min with all analyzers on.
 * Run 37098303440 wedged for 60+ minutes with zero log output, right
 * in the region where GccExceptionAnalyzer (the LSDACallSiteTable
 * error spam) and DecompilerAnalyzer run.
 *
 * Both are safe to disable here:
 *   - GccExceptionAnalyzer only builds exception tables; FindKillRule
 *     and FindEncryptKey need string xrefs and decompiles, not LSDA.
 *   - DecompilerAnalyzer pre-decompiles EVERY function. Our post-scripts
 *     call decompileFunction() on demand for the specific targets, so
 *     the pre-pass is pure wasted time on a 160 MB binary.
 *
 * Runs as -preScript: executes after import, before auto-analysis.
 */
public class TuneAnalysis extends GhidraScript {
    @Override
    public void run() throws Exception {
        Options analyzerOptions = currentProgram.getOptions("Analyzer");
        String[] disable = {
            "DecompilerAnalyzer",
            "GccExceptionAnalyzer"
        };
        for (String name : disable) {
            if (analyzerOptions.getBoolean(name, true)) {
                analyzerOptions.setBoolean(name, false);
                println("TuneAnalysis: DISABLED " + name);
            } else {
                println("TuneAnalysis: " + name + " already off");
            }
        }
        println("TuneAnalysis: remaining analyzers untouched");
    }
}
