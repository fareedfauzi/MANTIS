// Ghidra Headless Java Script for MANTIS Binary Lab
//
// Automatically decompiles functions, extracts symbols, imports, exports,
// strings, and metadata, and exports an AI workspace compatible with
// MANTIS Binary Analysis Lab.
//
// @category MANTIS

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class ExportGhidraWorkspace extends GhidraScript {

    private static String escapeJson(String s) {
        if (s == null) return "";
        StringBuilder sb = new StringBuilder();
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"':  sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\b': sb.append("\\b");  break;
                case '\f': sb.append("\\f");  break;
                case '\n': sb.append("\\n");  break;
                case '\r': sb.append("\\r");  break;
                case '\t': sb.append("\\t");  break;
                default:
                    if (c < 0x20 || c > 0x7E) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        return sb.toString();
    }

    private static void writeText(File file, String content) throws IOException {
        file.getParentFile().mkdirs();
        try (Writer writer = new OutputStreamWriter(new FileOutputStream(file), StandardCharsets.UTF_8)) {
            writer.write(content);
        }
    }

    private static String sanitizeName(String name) {
        if (name == null || name.isEmpty()) return "func";
        return name.replaceAll("[^A-Za-z0-9_.-]", "_");
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            printerr("ExportGhidraWorkspace error: Missing output workspace directory argument.");
            return;
        }

        File wsDir = new File(args[0]).getAbsoluteFile();
        File catalogDir = new File(wsDir, "catalog");
        File srcDir = new File(wsDir, "src");
        File asmDir = new File(wsDir, "asm");
        catalogDir.mkdirs();
        srcDir.mkdirs();
        asmDir.mkdirs();

        Program prog = currentProgram;
        if (prog == null) {
            printerr("ExportGhidraWorkspace error: No currentProgram loaded.");
            return;
        }

        // Parse configurable extraction limits (args[1]=maxDecompile, args[2]=maxStrings, or env vars)
        // A limit <= 0 means unlimited extraction.
        int maxDecompile = 0;
        int maxStrings = 0;
        if (args.length > 1) {
            try {
                maxDecompile = Integer.parseInt(args[1]);
            } catch (Exception ignored) {}
        }
        if (maxDecompile <= 0) {
            String envD = System.getenv("GHIDRA_MAX_DECOMPILE");
            if (envD != null && !envD.trim().isEmpty()) {
                try {
                    maxDecompile = Integer.parseInt(envD.trim());
                } catch (Exception ignored) {}
            }
        }

        if (args.length > 2) {
            try {
                maxStrings = Integer.parseInt(args[2]);
            } catch (Exception ignored) {}
        }
        if (maxStrings <= 0) {
            String envS = System.getenv("GHIDRA_MAX_STRINGS");
            if (envS != null && !envS.trim().isEmpty()) {
                try {
                    maxStrings = Integer.parseInt(envS.trim());
                } catch (Exception ignored) {}
            }
        }

        int limitDecompile = maxDecompile > 0 ? maxDecompile : Integer.MAX_VALUE;
        int limitStrings = maxStrings > 0 ? maxStrings : Integer.MAX_VALUE;

        println("OMNI_EVENT {\"kind\":\"sample_stage\",\"stage\":\"Ghidra Auto-Analysis Completed\"}");
        println(String.format("Exporting Ghidra AI Workspace to: %s (limits: max_decompile=%s, max_strings=%s)",
            wsDir.getAbsolutePath(),
            maxDecompile > 0 ? String.valueOf(maxDecompile) : "unlimited",
            maxStrings > 0 ? String.valueOf(maxStrings) : "unlimited"));

        // 1. Program metadata & assembly info
        String progName = prog.getName();
        String format = prog.getExecutableFormat();
        String langId = prog.getLanguage().getLanguageID().getIdAsString();
        String compId = prog.getCompilerSpec().getCompilerSpecID().getIdAsString();
        Address imageBase = prog.getImageBase();
        Address minAddr = prog.getMinAddress();
        Address maxAddr = prog.getMaxAddress();
        int funcTotal = prog.getFunctionManager().getFunctionCount();

        StringBuilder asmJson = new StringBuilder();
        asmJson.append("{\n");
        asmJson.append("  \"program_name\": \"").append(escapeJson(progName)).append("\",\n");
        asmJson.append("  \"executable_format\": \"").append(escapeJson(format)).append("\",\n");
        asmJson.append("  \"language_id\": \"").append(escapeJson(langId)).append("\",\n");
        asmJson.append("  \"compiler_spec\": \"").append(escapeJson(compId)).append("\",\n");
        asmJson.append("  \"image_base\": \"").append(imageBase != null ? imageBase.toString() : "0x0").append("\",\n");
        asmJson.append("  \"min_address\": \"").append(minAddr != null ? minAddr.toString() : "").append("\",\n");
        asmJson.append("  \"max_address\": \"").append(maxAddr != null ? maxAddr.toString() : "").append("\",\n");
        asmJson.append("  \"total_functions\": ").append(funcTotal).append(",\n");
        asmJson.append("  \"max_decompile_limit\": ").append(maxDecompile).append(",\n");
        asmJson.append("  \"max_strings_limit\": ").append(maxStrings).append(",\n");
        asmJson.append("  \"disassembler\": \"Ghidra (Headless)\"\n");
        asmJson.append("}\n");
        writeText(new File(catalogDir, "assembly.json"), asmJson.toString());
        writeText(new File(catalogDir, "metadata.json"), asmJson.toString());

        // 2. Extract Imports
        List<String> suspiciousTags = new ArrayList<>();
        Set<String> suspiciousApiPatterns = new HashSet<>(Arrays.asList(
            "virtualalloc", "writeprocessmemory", "createremotethread", "ntcreatethreadex",
            "setwindowshook", "queueuserapc", "loadlibrary", "getprocaddress", "internetopen",
            "internetconnect", "httpopenrequest", "httpsendrequest", "urldownloadtofile",
            "wsastartup", "connect", "send", "recv", "regsetvalue", "regcreatekey",
            "createprocess", "winexec", "shellexecute", "isdebuggerpresent", "checkremotedebuggerpresent",
            "cryptacquirecontext", "cryptencrypt", "cryptdecrypt"
        ));

        StringBuilder impJson = new StringBuilder("[\n");
        SymbolTable symTable = prog.getSymbolTable();
        SymbolIterator extSymbols = symTable.getExternalSymbols();
        boolean firstImp = true;
        int impCount = 0;
        while (extSymbols.hasNext()) {
            Symbol sym = extSymbols.next();
            String name = sym.getName();
            String parent = sym.getParentNamespace() != null ? sym.getParentNamespace().getName() : "EXTERNAL";
            Address addr = sym.getAddress();

            String lower = name.toLowerCase();
            for (String pattern : suspiciousApiPatterns) {
                if (lower.contains(pattern)) {
                    suspiciousTags.add("API: " + name + " (" + parent + ")");
                    break;
                }
            }

            if (!firstImp) impJson.append(",\n");
            firstImp = false;
            impJson.append("  {\"library\": \"").append(escapeJson(parent))
                   .append("\", \"name\": \"").append(escapeJson(name))
                   .append("\", \"address\": \"").append(addr != null ? addr.toString() : "")
                   .append("\"}");
            impCount++;
        }
        impJson.append("\n]\n");
        writeText(new File(catalogDir, "imports.json"), impJson.toString());

        // 3. Extract Exports
        StringBuilder expJson = new StringBuilder("[\n");
        AddressIterator entryPoints = symTable.getExternalEntryPointIterator();
        boolean firstExp = true;
        int expCount = 0;
        while (entryPoints.hasNext()) {
            Address ep = entryPoints.next();
            Symbol sym = symTable.getPrimarySymbol(ep);
            String name = sym != null ? sym.getName() : ep.toString();

            if (!firstExp) expJson.append(",\n");
            firstExp = false;
            expJson.append("  {\"name\": \"").append(escapeJson(name))
                   .append("\", \"address\": \"").append(ep.toString())
                   .append("\"}");
            expCount++;
        }
        expJson.append("\n]\n");
        writeText(new File(catalogDir, "exports.json"), expJson.toString());

        // 4. Extract Defined Strings
        StringBuilder strJson = new StringBuilder("[\n");
        Listing listing = prog.getListing();
        DataIterator dataIt = listing.getDefinedData(true);
        boolean firstStr = true;
        int strCount = 0;
        boolean stringsTruncated = false;
        while (dataIt.hasNext()) {
            if (strCount >= limitStrings) {
                stringsTruncated = true;
                break;
            }
            Data d = dataIt.next();
            if (d == null) continue;
            String dtName = d.getDataType() != null ? d.getDataType().getName().toLowerCase() : "";
            if (!dtName.contains("string") && !dtName.contains("unicode") && !dtName.contains("char")) {
                continue;
            }
            Object valObj = d.getValue();
            String val = valObj != null ? valObj.toString().trim() : d.getDefaultValueRepresentation();
            if (val == null) continue;
            val = val.trim();
            if (val.startsWith("\"") && val.endsWith("\"") && val.length() >= 2) {
                val = val.substring(1, val.length() - 1);
            }
            if (val.length() >= 4) {
                String lower = val.toLowerCase();
                if (lower.startsWith("http://") || lower.startsWith("https://") || lower.contains(".onion")) {
                    suspiciousTags.add("Network Indicator: " + val);
                } else if (lower.contains("powershell") || lower.contains("cmd.exe") || lower.contains("/bin/sh")) {
                    suspiciousTags.add("Command Execution Indicator: " + val);
                }

                if (!firstStr) strJson.append(",\n");
                firstStr = false;
                strJson.append("  {\"address\": \"").append(d.getAddress().toString())
                       .append("\", \"length\": ").append(val.length())
                       .append(", \"value\": \"").append(escapeJson(val))
                       .append("\"}");
                strCount++;
            }
        }
        strJson.append("\n]\n");
        writeText(new File(catalogDir, "strings.json"), strJson.toString());

        // 5. Triage Indicators
        StringBuilder triageJson = new StringBuilder("{\n  \"indicators\": [\n");
        for (int i = 0; i < suspiciousTags.size(); i++) {
            triageJson.append("    \"").append(escapeJson(suspiciousTags.get(i))).append("\"");
            if (i < suspiciousTags.size() - 1) triageJson.append(",");
            triageJson.append("\n");
        }
        triageJson.append("  ]\n}\n");
        writeText(new File(catalogDir, "triage_indicators.json"), triageJson.toString());

        // 6. Decompile Functions with DecompInterface
        println("OMNI_EVENT {\"kind\":\"sample_stage\",\"stage\":\"Decompiling in Ghidra\"}");
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(prog);

        StringBuilder fnJson = new StringBuilder("[\n");
        FunctionIterator fIt = prog.getFunctionManager().getFunctions(true);
        boolean firstFn = true;
        int decompCount = 0;
        boolean decompTruncated = false;

        while (fIt.hasNext()) {
            Function fn = fIt.next();
            String name = fn.getName();
            Address entry = fn.getEntryPoint();
            long size = fn.getBody().getNumAddresses();
            String proto = fn.getPrototypeString(true, false);
            boolean isThunk = fn.isThunk();

            if (!firstFn) fnJson.append(",\n");
            firstFn = false;
            fnJson.append("  {\"name\": \"").append(escapeJson(name))
                  .append("\", \"entry_point\": \"").append(entry.toString())
                  .append("\", \"size\": ").append(size)
                  .append(", \"signature\": \"").append(escapeJson(proto))
                  .append("\", \"is_thunk\": ").append(isThunk)
                  .append("}");

            // Decompile non-thunk functions up to limitDecompile
            if (!isThunk) {
                if (decompCount < limitDecompile) {
                    try {
                        DecompileResults res = decomp.decompileFunction(fn, 30, monitor);
                        if (res != null && res.decompileCompleted()) {
                            DecompiledFunction df = res.getDecompiledFunction();
                            if (df != null && df.getC() != null) {
                                String cCode = df.getC();
                                String safe = sanitizeName(name);
                                File cFile = new File(srcDir, safe + "_" + entry.toString().replace(":", "_") + ".c");
                                writeText(cFile, cCode);
                                decompCount++;
                            }
                        }
                    } catch (Exception ex) {
                        // Continue with next function
                    }
                } else {
                    decompTruncated = true;
                }
            }
        }
        fnJson.append("\n]\n");
        writeText(new File(catalogDir, "functions.json"), fnJson.toString());
        decomp.dispose();

        // 7. Generate AGENTS.md, CLAUDE.md, README.md
        StringBuilder agentsMd = new StringBuilder();
        agentsMd.append("# Binary Lab AI Workspace — Ghidra Binary Analysis: ").append(progName).append("\n\n");
        agentsMd.append("## Overview\n");
        agentsMd.append("- **Sample**: `").append(progName).append("`\n");
        agentsMd.append("- **Disassembler**: Ghidra (Headless Auto-Analysis + DecompInterface)\n");
        agentsMd.append("- **Format**: ").append(format).append("\n");
        agentsMd.append("- **Architecture / Language**: ").append(langId).append("\n");
        agentsMd.append("- **Total Functions**: ").append(funcTotal).append("\n");
        agentsMd.append("- **Decompiled Functions**: ").append(decompCount);
        if (maxDecompile > 0) {
            agentsMd.append(" (limit: ").append(maxDecompile).append(decompTruncated ? " — limit reached" : "").append(")");
        } else {
            agentsMd.append(" (unlimited)");
        }
        agentsMd.append("\n");
        agentsMd.append("- **Imports**: ").append(impCount).append("\n");
        agentsMd.append("- **Extracted Strings**: ").append(strCount);
        if (maxStrings > 0) {
            agentsMd.append(" (limit: ").append(maxStrings).append(stringsTruncated ? " — limit reached" : "").append(")");
        } else {
            agentsMd.append(" (unlimited)");
        }
        agentsMd.append("\n\n");
        agentsMd.append("## Structure\n");
        agentsMd.append("- `catalog/assembly.json`: Program format, architecture, and memory layout.\n");
        agentsMd.append("- `catalog/functions.json`: Complete function catalog and prototypes.\n");
        agentsMd.append("- `catalog/imports.json`: External dynamic library and Win32/POSIX imports.\n");
        agentsMd.append("- `catalog/exports.json`: Exported symbol entry points.\n");
        agentsMd.append("- `catalog/strings.json`: Defined string literals extracted from data sections.\n");
        agentsMd.append("- `catalog/triage_indicators.json`: High-priority suspicious behavioral indicators.\n");
        agentsMd.append("- `src/*.c`: High-level decompiled C source code for functions.\n\n");
        agentsMd.append("## Triage Findings\n");
        if (!suspiciousTags.isEmpty()) {
            for (String tag : suspiciousTags) {
                agentsMd.append("- ⚠ ").append(tag).append("\n");
            }
        } else {
            agentsMd.append("- No obvious high-risk triage flags triggered.\n");
        }
        if (decompTruncated) {
            agentsMd.append(String.format("- ℹ Decompilation capped at configured limit (%d functions).\n", maxDecompile));
        }
        if (stringsTruncated) {
            agentsMd.append(String.format("- ℹ Strings capped at configured limit (%d strings).\n", maxStrings));
        }
        agentsMd.append("\n## Autonomous Analysis Pipeline\n");
        agentsMd.append("- `run_analysis.md` — Investigation runbook and instructions.\n");
        agentsMd.append("- `render_report.py` — Report compiler for report.md -> report.html / report.pdf.\n");
        agentsMd.append("- `dump_ai_workspace.py` — Static artifact extractor for unpacker workflows.\n");

        String doc = agentsMd.toString();
        writeText(new File(wsDir, "AGENTS.md"), doc);
        writeText(new File(wsDir, "CLAUDE.md"), doc);
        writeText(new File(wsDir, "README.md"), doc);

        println(String.format("OMNI_EVENT {\"kind\":\"ghidra_limits\",\"max_decompile\":%d,\"max_strings\":%d,\"decompiled\":%d,\"strings\":%d,\"decomp_truncated\":%b,\"strings_truncated\":%b}",
            maxDecompile, maxStrings, decompCount, strCount, decompTruncated, stringsTruncated));
        println("OMNI_EVENT {\"kind\":\"sample_stage\",\"stage\":\"AI Workspace Exported\"}");
        println(String.format("Ghidra export complete: %d functions, %d imports, %d strings, %d C files",
            funcTotal, impCount, strCount, decompCount));
    }
}
