// REMIX targeted headless function dossier exporter.
// @category REMIX
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

import java.io.File;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public class RemixFunctionDossier extends GhidraScript {
    private static String esc(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r");
    }

    private static long parseNum(String s) {
        s = s.trim().toLowerCase();
        if (s.startsWith("0x")) return Long.parseUnsignedLong(s.substring(2), 16);
        return Long.parseLong(s);
    }

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            printerr("usage: RemixFunctionDossier <output.jsonl> <off1,off2,...>");
            return;
        }
        File out = new File(args[0]);
        String[] offsets = args[1].split(",");
        DecompInterface decomp = new DecompInterface();
        decomp.toggleCCode(true);
        decomp.toggleSyntaxTree(true);
        decomp.setSimplificationStyle("decompile");
        decomp.openProgram(currentProgram);

        long imageBase = currentProgram.getImageBase().getOffset();
        try (PrintWriter pw = new PrintWriter(out, "UTF-8")) {
            for (String offText : offsets) {
                if (monitor.isCancelled()) break;
                long off;
                try { off = parseNum(offText); } catch (Exception e) { continue; }
                Address a = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(imageBase + off);
                Function fn = currentProgram.getFunctionManager().getFunctionContaining(a);
                if (fn == null) continue;

                List<String> callers = new ArrayList<>();
                ReferenceIterator it = currentProgram.getReferenceManager().getReferencesTo(fn.getEntryPoint());
                while (it.hasNext()) {
                    Reference r = it.next();
                    Function cf = currentProgram.getFunctionManager().getFunctionContaining(r.getFromAddress());
                    if (cf != null) callers.add("0x" + Long.toHexString(cf.getEntryPoint().getOffset() - imageBase));
                }
                List<String> callees = new ArrayList<>();
                Set<Function> called = fn.getCalledFunctions(monitor);
                for (Function cf : called) {
                    callees.add("0x" + Long.toHexString(cf.getEntryPoint().getOffset() - imageBase));
                }

                String pseudo = "";
                try {
                    DecompileResults res = decomp.decompileFunction(fn, 25, monitor);
                    if (res.decompileCompleted() && res.getDecompiledFunction() != null) {
                        pseudo = res.getDecompiledFunction().getC();
                    }
                } catch (Exception ignored) {}

                StringBuilder sb = new StringBuilder();
                sb.append("{\"offset\":\"0x").append(Long.toHexString(fn.getEntryPoint().getOffset() - imageBase)).append("\",");
                sb.append("\"address\":\"").append(fn.getEntryPoint()).append("\",");
                sb.append("\"name\":\"").append(esc(fn.getName())).append("\",");
                sb.append("\"callers\":[");
                for (int i=0;i<callers.size();i++) { if(i>0) sb.append(','); sb.append('\"').append(callers.get(i)).append('\"'); }
                sb.append("],\"callees\":[");
                for (int i=0;i<callees.size();i++) { if(i>0) sb.append(','); sb.append('\"').append(callees.get(i)).append('\"'); }
                sb.append("],\"pseudocode\":\"").append(esc(pseudo)).append("\"}");
                pw.println(sb.toString());
            }
        }
        decomp.dispose();
    }
}
