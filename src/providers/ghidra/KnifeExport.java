// Knife-owned fixed headless export; no target code is executed.
// @category Knife
import ghidra.app.util.headless.HeadlessScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.database.mem.AddressSourceInfo;
import com.google.gson.JsonObject;
import com.google.gson.JsonArray;

public class KnifeExport extends HeadlessScript {
    private String address(long value) { return "0x" + Long.toUnsignedString(value, 16); }
    private JsonObject function(Function function) {
        JsonObject row = new JsonObject();
        row.addProperty("address", address(function.getEntryPoint().getOffset()));
        row.addProperty("address_space", function.getEntryPoint().getAddressSpace().getName());
        AddressSourceInfo source = currentProgram.getMemory().getAddressSourceInfo(function.getEntryPoint());
        if (source != null && source.getFileOffset() >= 0) {
            row.addProperty("file_offset", source.getFileOffset());
        } else {
            row.add("file_offset", com.google.gson.JsonNull.INSTANCE);
        }
        row.addProperty("name", function.getName());
        row.addProperty("size", function.getBody().getNumAddresses());
        row.addProperty("signature", function.getSignature().toString());
        return row;
    }
    @Override public void run() throws Exception {
        String[] arguments = getScriptArgs();
        if (arguments.length < 1) throw new IllegalArgumentException("expected functions or decompile");
        JsonObject result = new JsonObject();
        result.addProperty("schema", 1);
        result.addProperty("provider", "ghidra");
        result.addProperty("language", currentProgram.getLanguageID().toString());
        result.addProperty("image_base", address(currentProgram.getImageBase().getOffset()));
        result.addProperty("analysis_timed_out", analysisTimeoutOccurred());
        if (arguments[0].equals("functions")) {
            int limit = arguments.length > 1 ? Integer.parseInt(arguments[1]) : 200;
            if (limit < 1 || limit > 400) throw new IllegalArgumentException("limit must be 1–400");
            JsonArray rows = new JsonArray();
            FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
            while (iterator.hasNext() && rows.size() < limit) {
                monitor.checkCancelled();
                rows.add(function(iterator.next()));
            }
            result.addProperty("total", currentProgram.getFunctionManager().getFunctionCount());
            result.addProperty("truncated", iterator.hasNext());
            result.add("functions", rows);
        } else if (arguments[0].equals("decompile")) {
            if (arguments.length != 2) throw new IllegalArgumentException("expected static address");
            Function target = currentProgram.getFunctionManager().getFunctionContaining(toAddr(arguments[1]));
            if (target == null) throw new IllegalArgumentException("no containing function");
            result.add("function", function(target));
            DecompInterface decompiler = new DecompInterface();
            try {
                if (!decompiler.openProgram(currentProgram)) throw new IllegalStateException("cannot open decompiler");
                DecompileResults output = decompiler.decompileFunction(target, 30, monitor);
                result.addProperty("decompile_completed", output.decompileCompleted());
                result.addProperty("error", output.getErrorMessage());
                if (output.decompileCompleted() && output.getDecompiledFunction() != null) {
                    String text = output.getDecompiledFunction().getC();
                    int end = Math.min(text.length(), 65536);
                    if (end < text.length() && end > 0 && Character.isHighSurrogate(text.charAt(end - 1))) end--;
                    result.addProperty("pseudocode_truncated", end < text.length());
                    result.addProperty("pseudocode", text.substring(0, end));
                }
            } finally { decompiler.dispose(); }
        } else throw new IllegalArgumentException("unsupported export mode");
        println("KNIFE_GHIDRA_JSON:" + result.toString());
    }
}
