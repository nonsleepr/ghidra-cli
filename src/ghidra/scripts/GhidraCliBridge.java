// Ghidra CLI Bridge - TCP socket server for CLI commands
// @category Bridge
// @keybinding
// @menupath Tools.Start CLI Bridge
// @toolbar
//
// Single-file GhidraScript that runs a persistent TCP server inside Ghidra
// to serve CLI commands. Replaces the Python bridge.py with a pure Java
// implementation using Ghidra's bundled Gson for JSON serialization.

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.app.util.importer.AutoImporter;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.DomainObject;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.lang.Register;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;

import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.CommentType;

import java.io.*;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Iterator;

public class GhidraCliBridge extends GhidraScript {

    private Gson gson = new GsonBuilder().serializeNulls().create();
    private long startTime;
    private static final Pattern NAMED_HEX_ADDRESS_PATTERN =
        Pattern.compile("(?i)^(?:FUN|SUB|LAB|DAT)_([0-9a-f]+)$");

    @Override
    public void run() throws Exception {
        startTime = System.currentTimeMillis();
        // Get port file path from script arguments
        String[] scriptArgs = getScriptArgs();
        if (scriptArgs.length < 1) {
            printerr("Usage: GhidraCliBridge.java <port_file_path>");
            return;
        }
        String portFilePath = scriptArgs[0];

        // GhidraScript.execute() starts a transaction before calling run(). A
        // transaction spanning this server's lifetime makes command transactions
        // nested: aborts would remain visible until shutdown and poison earlier
        // edits. Each mutating handler must own its independent transaction.
        end(true);

        // Bind to dynamic port on localhost only.
        // Backlog of 50 lets many concurrent agents queue connections while one
        // is being served (the accept loop is intentionally single-threaded to
        // keep Ghidra API access serialized).
        ServerSocket serverSocket = new ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"));
        int port = serverSocket.getLocalPort();

        // Write port file
        File portFile = new File(portFilePath);
        portFile.getParentFile().mkdirs();
        try (PrintWriter pw = new PrintWriter(new FileWriter(portFile))) {
            pw.println(port);
        }

        // Write PID file
        String pidFilePath = portFilePath.replaceAll("\\.port$", ".pid");
        File pidFile = new File(pidFilePath);
        try (PrintWriter pw = new PrintWriter(new FileWriter(pidFile))) {
            pw.println(ProcessHandle.current().pid());
        }

        // Signal ready to parent process
        println("---GHIDRA_CLI_START---");
        JsonObject readyMsg = new JsonObject();
        readyMsg.addProperty("status", "ready");
        readyMsg.addProperty("port", port);
        println(gson.toJson(readyMsg));
        println("---GHIDRA_CLI_END---");
        System.out.flush();

        // Accept loop
        boolean running = true;
        while (running) {
            try {
                Socket client = serverSocket.accept();
                try (
                    BufferedReader in = new BufferedReader(new InputStreamReader(client.getInputStream()));
                    PrintWriter out = new PrintWriter(new OutputStreamWriter(client.getOutputStream()), true)
                ) {
                    String line;
                    while ((line = in.readLine()) != null) {
                        line = line.trim();
                        if (line.isEmpty()) continue;

                        HandleResult result = handleRequest(line);
                        out.println(gson.toJson(result.response));
                        out.flush();

                        if (result.shouldShutdown) {
                            running = false;
                            break;
                        }
                    }
                } catch (IOException e) {
                    printerr("Client error: " + e.getMessage());
                } finally {
                    client.close();
                }
            } catch (IOException e) {
                if (running) {
                    printerr("Accept error: " + e.getMessage());
                }
            }
        }

        // Cleanup: close the server socket but leave port/pid files for the
        // Rust CLI to clean up. Deleting them here creates a race: the JVM is
        // still unwinding (closing the Ghidra project, releasing locks) but
        // stop_bridge() can no longer find the PID to wait on, so it returns
        // early while the project lock is still held.
        serverSocket.close();
    }

    // --- Request Handling ---

    private static class HandleResult {
        JsonObject response;
        boolean shouldShutdown;

        HandleResult(JsonObject response, boolean shouldShutdown) {
            this.response = response;
            this.shouldShutdown = shouldShutdown;
        }
    }

    private HandleResult handleRequest(String line) {
        try {
            JsonObject req = JsonParser.parseString(line).getAsJsonObject();
            String command = req.has("command") ? req.get("command").getAsString() : null;
            JsonObject args = req.has("args") && !req.get("args").isJsonNull()
                ? req.getAsJsonObject("args") : new JsonObject();

            if ("shutdown".equals(command)) {
                JsonObject resp = new JsonObject();
                resp.addProperty("status", "shutdown");
                return new HandleResult(resp, true);
            }

            JsonObject result = dispatchCommand(command, args);
            if (result == null) {
                return new HandleResult(errorResponse("Unknown command: " + command), false);
            }

            // Check if the handler returned an error
            if (result.has("error")) {
                JsonObject response = errorResponse(result.get("error").getAsString());
                if (result.has("diagnostics")) response.add("data", result);
                return new HandleResult(response, false);
            }

            return new HandleResult(successResponse(result), false);

        } catch (Exception e) {
            return new HandleResult(errorResponse(e.getMessage()), false);
        }
    }

    private JsonObject dispatchCommand(String command, JsonObject args) {
        if (command == null) return null;
        switch (command) {
            case "ping":            return handlePing();
            case "program_info":    return handleProgramInfo();
            case "list_functions":  return handleListFunctions(args);
            case "get_function":    return handleGetFunction(args);
            case "rename_function": return handleRenameFunction(args);
            case "create_function": return handleCreateFunction(args);
            case "function_prepare": return handlePrepareFunction(args);
            case "delete_function": return handleDeleteFunction(args);
            case "decompile":
            case "decompile_v2":    return handleDecompile(args);
            case "list_strings":    return handleListStrings(args);
            case "list_imports":    return handleListImports(args);
            case "list_exports":    return handleListExports(args);
            case "memory_map":      return handleMemoryMap();
            case "xrefs_to":        return handleXrefsTo(args);
            case "xrefs_from":      return handleXrefsFrom(args);
            case "xrefs_list":      return handleXrefsList(args);
            case "import":          return handleImport(args);
            case "analyze":         return handleAnalyze(args);
            case "list_programs":   return handleListPrograms();
            case "open_program":    return handleOpenProgram(args);
            case "program_close":   return handleProgramClose();
            case "program_delete":  return handleProgramDelete(args);
            case "program_export":  return handleProgramExport(args);
            // Find commands
            case "find_string_v2":
            case "find_string":     return handleFindString(args);
            case "string_refs_v2":
            case "string_refs":     return handleStringRefs(args);
            case "function_candidates": return handleFunctionCandidates(args);
            case "vtable_inspect": return handleVtableInspect(args);
            case "find_bytes":      return handleFindBytes(args);
            case "find_function":   return handleFindFunction(args);
            case "find_calls":      return handleFindCalls(args);
            case "find_crypto":     return handleFindCrypto();
            case "find_interesting": return handleFindInteresting();
            // Symbol commands
            case "symbol_list":     return handleSymbolList(args);
            case "symbol_get":      return handleSymbolGet(args);
            case "symbol_create":   return handleSymbolCreate(args);
            case "symbol_delete":   return handleSymbolDelete(args);
            case "symbol_rename":   return handleSymbolRename(args);
            // Type commands
            case "type_list":       return handleTypeList(args);
            case "type_get":        return handleTypeGet(args);
            case "type_create":     return handleTypeCreate(args);
            case "type_apply":      return handleTypeApply(args);
            case "type_delete":     return handleTypeDelete(args);
            case "type_rename":     return handleTypeRename(args);
            case "type_create_enum": return handleTypeCreateEnum(args);
            case "type_typedef":    return handleTypeTypedef(args);
            case "type_add_field":  return handleTypeAddField(args);
            case "type_del_field":  return handleTypeDelField(args);
            // Function signature commands
            case "function_set_signature": return handleFunctionSetSignature(args);
            case "function_set_return_type": return handleFunctionSetReturnType(args);
            case "function_set_calling_convention": return handleFunctionSetCallingConvention(args);
            case "function_set_no_return": return handleFunctionSetNoReturn(args);
            case "function_body":   return handleFunctionBody(args);
            case "function_set_body": return handleFunctionSetBody(args);
            case "set_var_type":    return handleSetVarType(args);
            // Bookmark commands
            case "bookmark_list":    return handleBookmarkList(args);
            case "bookmark_add":     return handleBookmarkAdd(args);
            case "bookmark_delete":  return handleBookmarkDelete(args);
            // PCode commands
            case "pcode_at":         return handlePcodeAt(args);
            case "pcode_function":   return handlePcodeFunction(args);
            // Analysis commands
            case "analyzer_list":    return handleAnalyzerList(args);
            case "analyzer_set":     return handleAnalyzerSet(args);
            case "analyze_run":      return handleAnalyzeRun(args);
            // Comment commands
            case "comment_list":    return handleCommentList(args);
            case "comment_get":     return handleCommentGet(args);
            case "comment_set":     return handleCommentSet(args);
            case "comment_delete":  return handleCommentDelete(args);
            // Graph commands
            case "graph_calls":     return handleGraphCalls(args);
            case "graph_callers":   return handleGraphCallers(args);
            case "graph_callees":   return handleGraphCallees(args);
            case "graph_export":    return handleGraphExport(args);
            // Diff commands
            case "diff_programs":   return handleDiffPrograms(args);
            case "diff_functions":  return handleDiffFunctions(args);
            // Patch commands
            case "patch_bytes":     return handlePatchBytes(args);
            case "patch_nop":       return handlePatchNop(args);
            case "patch_export":    return handlePatchExport(args);
            // Other commands
            case "disasm_preview":
            case "disasm":          return handleDisasm(args);
            case "stats":           return handleStats();
            // Script commands
            case "script_run":      return handleScriptRun(args);
            case "script_java":     return handleScriptJava(args);
            case "script_python":   return handleScriptPython(args);
            case "script_list":     return handleScriptList();
            // Batch
            case "batch":           return handleBatch(args);
            // Bridge info
            case "bridge_info":     return handleBridgeInfo();
            // Memory read
            case "read_memory":     return handleReadMemory(args);
            default:                return null;
        }
    }

    // --- Response Helpers ---

    private JsonObject successResponse(JsonObject data) {
        JsonObject resp = new JsonObject();
        resp.addProperty("status", "success");
        resp.add("data", data);
        return resp;
    }

    private JsonObject errorResponse(String message) {
        JsonObject resp = new JsonObject();
        resp.addProperty("status", "error");
        resp.addProperty("message", message);
        return resp;
    }

    private JsonObject errorResult(String message) {
        JsonObject result = new JsonObject();
        result.addProperty("error", message);
        return result;
    }

    // --- Address Resolution ---

    private Address resolveAddress(String addrStr) {
        if (currentProgram == null || addrStr == null || addrStr.isEmpty()) {
            return null;
        }

        String target = addrStr.trim();
        AddressFactory af = currentProgram.getAddressFactory();

        // Try as hex address first (with and without 0x prefix)
        Address addr = af.getAddress(target);
        if (addr != null) {
            return addr;
        }
        if (target.startsWith("0x") || target.startsWith("0X")) {
            addr = af.getAddress(target.substring(2));
            if (addr != null) {
                return addr;
            }
        }

        // Parse common Ghidra auto names like FUN_00401234 as raw addresses.
        Matcher namedHex = NAMED_HEX_ADDRESS_PATTERN.matcher(target);
        if (namedHex.matches()) {
            String hexPart = namedHex.group(1);
            addr = af.getAddress(hexPart);
            if (addr == null) {
                addr = af.getAddress("0x" + hexPart);
            }
            if (addr != null) {
                return addr;
            }
        }

        // Try as symbol/function name via SymbolTable
        SymbolTable st = currentProgram.getSymbolTable();
        SymbolIterator syms = st.getSymbols(target);
        while (syms.hasNext()) {
            Symbol sym = syms.next();
            Address symAddr = sym.getAddress();
            // Skip external/fake addresses - prefer real addresses
            if (symAddr != null && !symAddr.isExternalAddress()) {
                return symAddr;
            }
        }

        // Try global symbols (may include exports)
        List<Symbol> globalSyms = st.getGlobalSymbols(target);
        for (Symbol sym : globalSyms) {
            Address symAddr = sym.getAddress();
            if (symAddr != null && !symAddr.isExternalAddress()) {
                return symAddr;
            }
        }

        // Fallback: scan functions by name (O(n) but handles edge cases)
        FunctionManager fm = currentProgram.getFunctionManager();
        FunctionIterator iter = fm.getFunctions(true);
        while (iter.hasNext()) {
            Function func = iter.next();
            if (func.getName().equals(target)) {
                return func.getEntryPoint();
            }
        }

        return null;
    }

    // --- Helper to safely get string from JsonObject ---

    private String getArgString(JsonObject args, String key) {
        if (args == null || !args.has(key) || args.get(key).isJsonNull()) return null;
        return args.get(key).getAsString();
    }

    private int getArgInt(JsonObject args, String key, int defaultVal) {
        if (args == null || !args.has(key) || args.get(key).isJsonNull()) return defaultVal;
        return args.get(key).getAsInt();
    }

    private boolean getArgBool(JsonObject args, String key, boolean defaultVal) {
        if (args == null || !args.has(key) || args.get(key).isJsonNull()) return defaultVal;
        return args.get(key).getAsBoolean();
    }

    // --- Command Handlers (M1: Core) ---

    private JsonObject handlePing() {
        JsonObject result = new JsonObject();
        result.addProperty("message", "pong");
        return result;
    }

    private JsonObject handleBridgeInfo() {
        JsonObject result = new JsonObject();
        result.addProperty("has_current_program", currentProgram != null);
        if (currentProgram != null) {
            result.addProperty("current_program", currentProgram.getName());
        }
        result.addProperty("uptime_ms", System.currentTimeMillis() - startTime);
        result.addProperty("protocol_version", 1);
        result.addProperty("script_hash", "@BRIDGE_SCRIPT_HASH@");
        result.addProperty("cli_build_id", "@CLI_BUILD_ID@");
        result.addProperty("pid", ProcessHandle.current().pid());
        result.addProperty("ghidra_version", ghidra.framework.Application.getApplicationVersion());
        result.addProperty("java_version", System.getProperty("java.version"));
        result.addProperty("java_home", System.getProperty("java.home"));

        Project project = state.getProject();
        if (project != null) {
            result.addProperty("project_name", project.getName());
            try {
                result.addProperty("project_path", new File(project.getProjectLocator().getLocation(), project.getName()).getCanonicalPath());
            } catch (IOException e) {
                result.addProperty("project_path_error", e.getMessage());
            }
            try {
                ProjectData projectData = project.getProjectData();
                DomainFolder rootFolder = projectData.getRootFolder();
                result.addProperty("program_count", rootFolder.getFiles().length);
            } catch (Exception e) {
                result.addProperty("program_count", 0);
            }
        }
        return result;
    }

    private JsonObject handleProgramInfo() {
        if (currentProgram == null) {
            return errorResult("No program loaded");
        }

        JsonObject result = new JsonObject();
        result.addProperty("name", currentProgram.getName());
        result.addProperty("executable_path", currentProgram.getExecutablePath());
        result.addProperty("executable_format", currentProgram.getExecutableFormat());
        String compiler = currentProgram.getCompiler();
        if (compiler != null && !compiler.isEmpty()) {
            result.addProperty("compiler", compiler);
        } else {
            result.add("compiler", JsonNull.INSTANCE);
        }
        result.addProperty("language", currentProgram.getLanguage().toString());
        result.addProperty("image_base", currentProgram.getImageBase().toString());
        result.addProperty("min_address", currentProgram.getMinAddress().toString());
        result.addProperty("max_address", currentProgram.getMaxAddress().toString());

        FunctionManager fm = currentProgram.getFunctionManager();
        result.addProperty("function_count", fm.getFunctionCount());

        return result;
    }

    private JsonObject handleListFunctions(JsonObject args) {
        if (currentProgram == null) {
            return errorResult("No program loaded");
        }

        int limit = getArgInt(args, "limit", 0);
        String nameFilter = getArgString(args, "filter");

        JsonArray functions = new JsonArray();
        FunctionManager fm = currentProgram.getFunctionManager();
        int count = 0;

        FunctionIterator iter = fm.getFunctions(true);
        while (iter.hasNext()) {
            if (limit > 0 && count >= limit) break;

            Function func = iter.next();
            String name = func.getName();

            if (nameFilter != null && !name.toLowerCase().contains(nameFilter.toLowerCase())) {
                continue;
            }

            functions.add(functionToJson(func));
            count++;
        }

        JsonObject result = new JsonObject();
        result.add("functions", functions);
        result.addProperty("count", functions.size());
        return result;
    }

    private JsonObject functionToJson(Function func) {
        JsonObject funcData = new JsonObject();
        funcData.addProperty("name", func.getName());
        funcData.addProperty("address", func.getEntryPoint().toString());
        funcData.addProperty("size", func.getBody().getNumAddresses());
        funcData.addProperty("entry_point", func.getEntryPoint().toString());

        String sig = null;
        try {
            sig = func.getPrototypeString(false, false);
        } catch (Exception e) {
            // ignore
        }
        if (sig != null) {
            funcData.addProperty("signature", sig);
        } else {
            funcData.add("signature", JsonNull.INSTANCE);
        }

        funcData.addProperty("calling_convention", func.getCallingConventionName());
        funcData.addProperty("no_return", func.hasNoReturn());

        String comment = func.getComment();
        if (comment != null) {
            funcData.addProperty("comment", comment);
        } else {
            funcData.add("comment", JsonNull.INSTANCE);
        }

        return funcData;
    }

    private String buildFunctionTargetHint(String target) {
        if (currentProgram == null || target == null || target.isEmpty()) {
            return "Function not found";
        }

        String query = target.toLowerCase();
        List<String> containsMatches = new ArrayList<>();
        List<String> fuzzyMatches = new ArrayList<>();
        FunctionIterator iter = currentProgram.getFunctionManager().getFunctions(true);

        while (iter.hasNext()) {
            Function func = iter.next();
            String name = func.getName();
            String lname = name.toLowerCase();

            if (lname.contains(query)) {
                containsMatches.add(name);
            } else if (query.length() >= 3 && levenshteinDistance(lname, query) <= 3) {
                fuzzyMatches.add(name);
            }
        }

        Collections.sort(containsMatches);
        Collections.sort(fuzzyMatches);

        List<String> suggestions = new ArrayList<>();
        for (String name : containsMatches) {
            suggestions.add(name);
            if (suggestions.size() >= 5) break;
        }
        if (suggestions.size() < 5) {
            for (String name : fuzzyMatches) {
                if (!suggestions.contains(name)) suggestions.add(name);
                if (suggestions.size() >= 5) break;
            }
        }

        StringBuilder hint = new StringBuilder();
        hint.append("Cannot resolve function target: ").append(target)
            .append(". Try: ghidra function list --filter ").append(target);
        if (!suggestions.isEmpty()) {
            hint.append(". Closest matches: ").append(String.join(", ", suggestions));
        }
        return hint.toString();
    }

    private int levenshteinDistance(String a, String b) {
        int n = a.length();
        int m = b.length();
        int[][] dp = new int[n + 1][m + 1];

        for (int i = 0; i <= n; i++) dp[i][0] = i;
        for (int j = 0; j <= m; j++) dp[0][j] = j;

        for (int i = 1; i <= n; i++) {
            for (int j = 1; j <= m; j++) {
                int cost = a.charAt(i - 1) == b.charAt(j - 1) ? 0 : 1;
                dp[i][j] = Math.min(
                    Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1),
                    dp[i - 1][j - 1] + cost
                );
            }
        }
        return dp[n][m];
    }

    private JsonObject handleGetFunction(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");

        String target = getArgString(args, "address");
        if (target == null || target.isEmpty()) {
            return errorResult("Function target required");
        }

        Address addr = resolveAddress(target);
        if (addr == null) {
            return errorResult(buildFunctionTargetHint(target));
        }

        Function func = currentProgram.getFunctionManager().getFunctionContaining(addr);
        if (func == null) {
            return errorResult("No function at target " + target + ". Try: ghidra function list --filter " + target);
        }
        return functionToJson(func);
    }

    private JsonObject handleRenameFunction(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");

        String oldTarget = getArgString(args, "old_name");
        String newName = getArgString(args, "new_name");
        if (oldTarget == null || newName == null || oldTarget.isEmpty() || newName.isEmpty()) {
            return errorResult("old_name and new_name required");
        }

        try {
            Function func = findFunctionByNameOrAddress(oldTarget);
            if (func == null) {
                return errorResult(buildFunctionTargetHint(oldTarget));
            }

            int txId = currentProgram.startTransaction("Rename function");
            try {
                String oldName = func.getName();
                func.setName(newName, SourceType.USER_DEFINED);
                currentProgram.endTransaction(txId, true);

                JsonObject result = new JsonObject();
                result.addProperty("status", "renamed");
                result.addProperty("old_name", oldName);
                result.addProperty("new_name", newName);
                result.addProperty("address", func.getEntryPoint().toString());
                return result;
            } catch (Exception e) {
                currentProgram.endTransaction(txId, false);
                throw e;
            }
        } catch (Exception e) {
            return errorResult("Failed to rename function: " + e.getMessage());
        }
    }

    private JsonObject handleCreateFunction(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");

        String target = getArgString(args, "address");
        String requestedName = getArgString(args, "name");
        if (target == null || target.isEmpty()) {
            return errorResult("Function target required");
        }

        try {
            Address addr = resolveAddress(target);
            if (addr == null) {
                return errorResult("Invalid function target: " + target + ". Expected address/symbol/FUN_<hex>.");
            }

            FunctionManager fm = currentProgram.getFunctionManager();
            if (fm.getFunctionContaining(addr) != null) {
                return errorResult("Function already exists at " + addr.toString());
            }

            String functionName = (requestedName == null || requestedName.isEmpty())
                ? ("FUN_" + addr.toString().replace(":", ""))
                : requestedName;

            int txId = currentProgram.startTransaction("Create function");
            try {
                Function created = fm.createFunction(functionName, addr, null, SourceType.USER_DEFINED);
                if (created == null) {
                    currentProgram.endTransaction(txId, false);
                    return errorResult("Failed to create function at " + addr.toString());
                }
                currentProgram.endTransaction(txId, true);

                JsonObject result = new JsonObject();
                result.addProperty("status", "created");
                result.addProperty("name", created.getName());
                result.addProperty("address", created.getEntryPoint().toString());
                return result;
            } catch (Exception e) {
                currentProgram.endTransaction(txId, false);
                throw e;
            }
        } catch (Exception e) {
            String hint = e.getMessage() != null && e.getMessage().contains("Function body must contain the entrypoint")
                ? ". Inspect the entry and overlaps, then use 'function prepare' with an explicit --end or --max-bytes bound; see docs/function-preparation.md. Discovery decoding does not create instructions." : "";
            return errorResult("Failed to create function: " + e.getMessage() + hint);
        }
    }

    private JsonArray addressRangesJson(ghidra.program.model.address.AddressSetView set) {
        JsonArray ranges = new JsonArray();
        for (ghidra.program.model.address.AddressRange range : set.getAddressRanges()) {
            JsonObject row = new JsonObject();
            row.addProperty("min_address", range.getMinAddress().toString());
            row.addProperty("max_address", range.getMaxAddress().toString());
            row.addProperty("length", range.getLength());
            ranges.add(row);
        }
        return ranges;
    }

    /** Explicit mutation: bounded, non-call control-flow walk with no auto-analysis. */
    private JsonObject handlePrepareFunction(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");
        int txId = -1;
        boolean commit = false;
        try {
            Address entry = resolveAddress(getArgString(args, "address"));
            if (entry == null || !entry.getAddressSpace().isMemorySpace()
                    || entry.getAddressSpace().getAddressableUnitSize() != 1)
                throw new IOException("A byte-addressable memory entry is required");
            String endText = getArgString(args, "end");
            boolean hasBytes = args.has("max_bytes") && !args.get("max_bytes").isJsonNull();
            if ((endText != null) == hasBytes)
                throw new IOException("Specify exactly one of --end or --max-bytes");
            Address end;
            if (hasBytes) {
                long count = args.get("max_bytes").getAsLong();
                if (count < 1 || count > 1048576) throw new IOException("--max-bytes must be 1 through 1048576");
                end = entry.addNoWrap(count - 1);
            } else {
                end = resolveAddress(endText);
            }
            if (end == null || !entry.getAddressSpace().equals(end.getAddressSpace()) || end.compareTo(entry) < 0)
                throw new IOException("End must be at or after the entry in the same address space");
            long distance = end.subtract(entry);
            if (distance < 0 || distance >= 1048576) throw new IOException("Preparation window exceeds 1 MiB");
            ghidra.program.model.address.AddressSet scope = new ghidra.program.model.address.AddressSet(entry, end);
            Memory memory = currentProgram.getMemory();
            if (!memory.getLoadedAndInitializedAddressSet().contains(scope))
                throw new IOException("Preparation window must be fully loaded and initialized");
            for (MemoryBlock block : memory.getBlocks()) {
                if (scope.intersects(block.getStart(), block.getEnd()) && !block.isExecute())
                    throw new IOException("Preparation window includes non-executable memory: " + block.getName());
            }
            int alignment = currentProgram.getLanguage().getInstructionAlignment();
            if (entry.getOffsetAsBigInteger().mod(java.math.BigInteger.valueOf(alignment)).signum() != 0)
                throw new IOException("Entry violates instruction alignment " + alignment);
            Listing listing = currentProgram.getListing();
            FunctionManager fm = currentProgram.getFunctionManager();
            Iterator<Function> existing = fm.getFunctionsOverlapping(scope);
            if (existing.hasNext()) throw new IOException("Preparation window overlaps existing function " + existing.next().getName());
            if (listing.getDefinedDataContaining(entry) != null || listing.getDefinedData(scope, true).hasNext())
                throw new IOException("Preparation window overlaps defined data");
            Instruction containing = listing.getInstructionContaining(entry);
            if (containing != null && !containing.getAddress().equals(entry))
                throw new IOException("Entry is inside an existing instruction");
            String name = getArgString(args, "name");
            if (name == null || name.isEmpty()) name = "FUN_" + entry.toString().replace(":", "");

            txId = currentProgram.startTransaction("Prepare bounded function");
            ghidra.program.model.address.AddressSet body = new ghidra.program.model.address.AddressSet();
            ghidra.program.model.address.AddressSet disassembled = new ghidra.program.model.address.AddressSet();
            java.util.ArrayDeque<Address> pending = new java.util.ArrayDeque<>();
            Set<Address> visited = new HashSet<>();
            pending.add(entry);
            int newInstructions = 0, reusedInstructions = 0;
            long deadline = System.nanoTime() + 30_000_000_000L;
            while (!pending.isEmpty()) {
                monitor.checkCancelled();
                if (System.nanoTime() - deadline >= 0) throw new IOException("30-second preparation budget exceeded");
                Address address = pending.removeFirst();
                if (!scope.contains(address)) throw new IOException("Control flow escapes preparation window at " + address);
                if (!visited.add(address)) continue;
                if (visited.size() > 65536) throw new IOException("Preparation exceeds 65536 instructions");
                Instruction instruction = listing.getInstructionAt(address);
                if (instruction == null) {
                    if (listing.getInstructionContaining(address) != null)
                        throw new IOException("Control flow enters the middle of an instruction at " + address);
                    // Restrict starts to a single address: no callees or fallthrough
                    // are decoded implicitly. Ghidra still decodes full instructions,
                    // so check the returned byte range before accepting any changes.
                    ghidra.app.cmd.disassemble.DisassembleCommand command =
                        new ghidra.app.cmd.disassemble.DisassembleCommand(address,
                            new ghidra.program.model.address.AddressSet(address), false);
                    command.enableCodeAnalysis(false);
                    boolean ok = command.applyTo(currentProgram, monitor);
                    ghidra.program.model.address.AddressSet decoded = command.getDisassembledAddressSet();
                    if (!scope.contains(decoded)) throw new IOException("Decoded instruction crosses preparation boundary at " + address);
                    disassembled.add(decoded);
                    instruction = listing.getInstructionAt(address);
                    if (!ok || instruction == null) throw new IOException("Cannot decode instruction at " + address + ": " + command.getStatusMsg());
                    newInstructions++;
                } else {
                    reusedInstructions++;
                }
                if (!scope.contains(instruction.getMinAddress(), instruction.getMaxAddress()))
                    throw new IOException("Instruction crosses preparation boundary at " + address);
                if (instruction.getDelaySlotDepth() != 0 || instruction.isInDelaySlot())
                    throw new IOException("Delay-slot instructions are not supported by bounded preparation");
                body.add(instruction.getMinAddress(), instruction.getMaxAddress());
                FlowType flow = instruction.getFlowType();
                if (flow.isJump() && (flow.isComputed() || instruction.getFlows().length == 0))
                    throw new IOException("Unresolved jump at " + address + "; bounded preparation cannot establish its body");
                if (!flow.isCall()) {
                    for (Address target : instruction.getFlows()) pending.addLast(target);
                }
                Address fallthrough = instruction.getFallThrough();
                if (fallthrough != null) pending.addLast(fallthrough);
            }
            if (!body.contains(entry)) throw new IOException("Prepared body does not contain the entry");
            Function created = fm.createFunction(name, entry, body, SourceType.USER_DEFINED);
            if (created == null) throw new IOException("Ghidra did not create the function");
            JsonObject result = new JsonObject();
            result.addProperty("status", "prepared");
            result.addProperty("name", created.getName());
            result.addProperty("address", entry.toString());
            result.addProperty("entry_point", entry.toString());
            result.add("ranges", addressRangesJson(created.getBody()));
            result.addProperty("range_count", created.getBody().getNumAddressRanges());
            result.addProperty("total_size", created.getBody().getNumAddresses());
            result.addProperty("is_contiguous", created.getBody().getNumAddressRanges() <= 1);
            result.add("disassembled_ranges", addressRangesJson(disassembled));
            result.addProperty("new_instruction_count", newInstructions);
            result.addProperty("reused_instruction_count", reusedInstructions);
            result.addProperty("analysis_run", false);
            JsonObject bounds = new JsonObject();
            bounds.addProperty("start", entry.toString());
            bounds.addProperty("end_inclusive", end.toString());
            bounds.addProperty("byte_limit", distance + 1);
            bounds.addProperty("instruction_limit", 65536);
            bounds.addProperty("time_limit_ms", 30000);
            result.add("scope", bounds);
            commit = true;
            return result;
        } catch (Exception e) {
            return errorResult("Failed to prepare function (no changes committed): " + e.getMessage());
        } finally {
            if (txId != -1) currentProgram.endTransaction(txId, commit);
        }
    }

    private JsonObject handleDeleteFunction(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");

        String target = getArgString(args, "address");
        if (target == null || target.isEmpty()) {
            return errorResult("Function target required");
        }

        try {
            FunctionManager fm = currentProgram.getFunctionManager();
            Function func = findFunctionByNameOrAddress(target);
            if (func == null) {
                return errorResult(buildFunctionTargetHint(target));
            }

            Address entry = func.getEntryPoint();
            String name = func.getName();
            int txId = currentProgram.startTransaction("Delete function");
            try {
                fm.removeFunction(entry);
                currentProgram.endTransaction(txId, true);
            } catch (Exception e) {
                currentProgram.endTransaction(txId, false);
                throw e;
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "deleted");
            result.addProperty("name", name);
            result.addProperty("address", entry.toString());
            return result;
        } catch (Exception e) {
            return errorResult("Failed to delete function: " + e.getMessage());
        }
    }

    // Database metadata is deliberately separate from the decompiler's recovered model.
    private JsonObject databaseParameterJson(Parameter parameter) {
        JsonObject result = new JsonObject();
        result.addProperty("ordinal", parameter.getOrdinal());
        result.addProperty("name", parameter.getName());
        result.addProperty("type", parameter.getDataType().getDisplayName());
        result.addProperty("storage", parameter.getVariableStorage().toString());
        result.addProperty("source", parameter.getSource().toString());
        result.addProperty("auto_parameter", parameter.isAutoParameter());
        result.addProperty("forced_indirect", parameter.isForcedIndirect());
        return result;
    }

    private JsonObject recoveredParameterJson(ghidra.program.model.pcode.HighSymbol symbol) {
        JsonObject result = new JsonObject();
        result.addProperty("ordinal", symbol.getCategoryIndex());
        result.addProperty("name", symbol.getName());
        result.addProperty("type", symbol.getDataType().getDisplayName());
        result.addProperty("size", symbol.getSize());
        result.addProperty("storage", symbol.getStorage().toString());
        result.addProperty("name_locked", symbol.isNameLocked());
        result.addProperty("type_locked", symbol.isTypeLocked());
        return result;
    }

    private JsonObject decompileDiagnostics(Function function, DecompileResults results, String openError, String code) {
        JsonObject diagnostics = new JsonObject();
        JsonObject decompiler = new JsonObject();
        decompiler.addProperty("status", results == null ? "open_failed" :
            results.decompileCompleted() ? "completed" : "failed");
        decompiler.addProperty("completed", results != null && results.decompileCompleted());
        if (results == null) {
            decompiler.add("timed_out", JsonNull.INSTANCE);
            decompiler.add("cancelled", JsonNull.INSTANCE);
            decompiler.add("failed_to_start", JsonNull.INSTANCE);
        } else {
            decompiler.addProperty("timed_out", results.isTimedOut());
            decompiler.addProperty("cancelled", results.isCancelled());
            decompiler.addProperty("failed_to_start", results.failedToStart());
        }
        decompiler.addProperty("code_available", code != null);
        JsonArray warningComments = new JsonArray();
        if (code != null) {
            // Markup splits a warning into word tokens. Preserve the rendered block instead.
            java.util.regex.Matcher comments = java.util.regex.Pattern.compile(
                "(?m)^\\h*/\\*\\h*WARNING:[\\s\\S]*?\\*/")
                .matcher(code);
            while (comments.find()) warningComments.add(comments.group().stripLeading());
        }
        decompiler.add("warning_comments", warningComments);
        String message = results == null ? openError : results.getErrorMessage();
        decompiler.addProperty("raw_message", message); // Preserve null vs empty, and whitespace.
        decompiler.addProperty("timeout_seconds", 30);
        diagnostics.add("decompiler", decompiler);
        diagnostics.addProperty("semantic_completeness", "not_established");

        JsonObject database = new JsonObject();
        database.addProperty("signature", function.getPrototypeString(false, false));
        database.addProperty("signature_source", function.getSignatureSource().toString());
        database.addProperty("calling_convention", function.getCallingConventionName());
        database.addProperty("custom_variable_storage", function.hasCustomVariableStorage());
        database.addProperty("no_return", function.hasNoReturn());
        database.addProperty("varargs", function.hasVarArgs());
        database.add("return", databaseParameterJson(function.getReturn()));
        JsonArray parameters = new JsonArray();
        for (Parameter parameter : function.getParameters()) parameters.add(databaseParameterJson(parameter));
        database.add("parameters", parameters);
        diagnostics.add("database", database);

        JsonObject body = new JsonObject();
        body.add("ranges", addressRangesJson(function.getBody()));
        body.addProperty("range_count", function.getBody().getNumAddressRanges());
        body.addProperty("total_size", function.getBody().getNumAddresses());
        body.addProperty("is_contiguous", function.getBody().getNumAddressRanges() <= 1);
        diagnostics.add("body", body);

        ghidra.program.model.pcode.HighFunction high = results == null ? null : results.getHighFunction();
        if (high == null) {
            diagnostics.add("recovered", JsonNull.INSTANCE);
        } else {
            ghidra.program.model.pcode.FunctionPrototype prototype = high.getFunctionPrototype();
            JsonObject recovered = new JsonObject();
            recovered.addProperty("calling_convention", prototype.getModelName());
            recovered.addProperty("return_type", prototype.getReturnType().getDisplayName());
            recovered.addProperty("return_storage", prototype.getReturnStorage() == null ? null : prototype.getReturnStorage().toString());
            recovered.addProperty("no_return", prototype.hasNoReturn());
            recovered.addProperty("varargs", prototype.isVarArg());
            JsonArray recoveredParameters = new JsonArray();
            for (int i = 0; i < prototype.getNumParams(); i++)
                recoveredParameters.add(recoveredParameterJson(prototype.getParam(i)));
            recovered.add("parameters", recoveredParameters);
            diagnostics.add("recovered", recovered);
        }
        String address = function.getEntryPoint().toString();
        JsonObject hints = new JsonObject();
        hints.addProperty("function", "function get " + address);
        hints.addProperty("body", "function body " + address);
        hints.addProperty("calls", "function calls " + address);
        hints.addProperty("disassembly", "function disasm " + address);
        diagnostics.add("inspection_hints", hints);
        return diagnostics;
    }

    private JsonObject decompileError(Function function, DecompileResults results, String message, String openError) {
        JsonObject result = errorResult(message);
        result.addProperty("name", function.getName());
        result.addProperty("address", function.getEntryPoint().toString());
        result.add("diagnostics", decompileDiagnostics(function, results, openError, null));
        return result;
    }

    private JsonObject handleDecompile(JsonObject args) {
        if (currentProgram == null) {
            return errorResult("No program loaded");
        }

        String addrStr = getArgString(args, "address");
        if (addrStr == null || addrStr.isEmpty()) {
            return errorResult("No address provided");
        }

        Address addr = resolveAddress(addrStr);
        if (addr == null) {
            return errorResult(buildFunctionTargetHint(addrStr));
        }

        FunctionManager fm = currentProgram.getFunctionManager();
        Function func = fm.getFunctionContaining(addr);
        if (func == null) {
            return errorResult("No function at address " + addrStr);
        }

        DecompInterface decompiler = new DecompInterface();
        try {
            if (!decompiler.openProgram(currentProgram)) {
                return decompileError(func, null, "Decompilation failed: openProgram failed: " + decompiler.getLastMessage(), decompiler.getLastMessage());
            }

            DecompileResults results = decompiler.decompileFunction(func, 30, TaskMonitor.DUMMY);

            // getDecompiledFunction() pretty-prints anew on every call; render once.
            ghidra.app.decompiler.DecompiledFunction decompiled = results.decompileCompleted()
                ? results.getDecompiledFunction() : null;
            String code = decompiled == null ? null : decompiled.getC();
            if (code != null) {
                JsonObject result = new JsonObject();
                result.addProperty("name", func.getName());
                result.addProperty("address", func.getEntryPoint().toString());
                String sig = null;
                try {
                    sig = func.getPrototypeString(false, false);
                } catch (Exception e) {
                    // ignore
                }
                if (sig != null) {
                    result.addProperty("signature", sig);
                } else {
                    result.add("signature", JsonNull.INSTANCE);
                }
                result.addProperty("code", code);
                result.add("diagnostics", decompileDiagnostics(func, results, null, code));

                // Decompilation can "complete" while still reporting non-fatal warnings
                // (e.g. partial type recovery, unreachable code, bad data flow). Surface
                // these as evidence; no message does not establish semantic completeness.
                String warningMsg = results.getErrorMessage();
                if (warningMsg != null && !warningMsg.isEmpty()) {
                    result.addProperty("warnings", warningMsg);
                }

                boolean withVars = getArgBool(args, "with_vars", false);
                boolean withParams = getArgBool(args, "with_params", false);

                if (withVars || withParams) {
                    ghidra.program.model.pcode.HighFunction highFunc = results.getHighFunction();
                    if (highFunc != null) {
                        ghidra.program.model.pcode.LocalSymbolMap lsm = highFunc.getLocalSymbolMap();

                        if (withParams) {
                            JsonArray params = new JsonArray();
                            Iterator<ghidra.program.model.pcode.HighSymbol> symIter = lsm.getSymbols();
                            while (symIter.hasNext()) {
                                ghidra.program.model.pcode.HighSymbol sym = symIter.next();
                                if (sym.isParameter()) {
                                    JsonObject paramObj = new JsonObject();
                                    paramObj.addProperty("name", sym.getName());
                                    paramObj.addProperty("type", sym.getDataType().getName());
                                    paramObj.addProperty("size", sym.getSize());
                                    paramObj.addProperty("storage", sym.getStorage().toString());
                                    params.add(paramObj);
                                }
                            }
                            result.add("params", params);
                        }

                        if (withVars) {
                            JsonArray vars = new JsonArray();
                            Iterator<ghidra.program.model.pcode.HighSymbol> symIter2 = lsm.getSymbols();
                            while (symIter2.hasNext()) {
                                ghidra.program.model.pcode.HighSymbol sym = symIter2.next();
                                if (!sym.isParameter()) {
                                    JsonObject varObj = new JsonObject();
                                    varObj.addProperty("name", sym.getName());
                                    varObj.addProperty("type", sym.getDataType().getName());
                                    varObj.addProperty("size", sym.getSize());
                                    varObj.addProperty("storage", sym.getStorage().toString());
                                    vars.add(varObj);
                                }
                            }
                            result.add("variables", vars);
                        }
                    }
                }

                return result;
            } else {
                return decompileError(func, results, "Decompilation failed: " + decompileFailureReason(results), null);
            }
        } finally {
            decompiler.dispose();
        }
    }

    /** Build a human-readable failure reason from DecompileResults. */
    private static String decompileFailureReason(DecompileResults r) {
        if (r.failedToStart()) return "decompiler process failed to start";
        if (r.isTimedOut())    return "decompiler timed out";
        if (r.isCancelled())   return "decompilation cancelled";
        String msg = r.getErrorMessage();
        if (msg != null && !msg.isEmpty()) return msg;
        return "unknown failure";
    }

    private JsonObject handleListStrings(JsonObject args) {
        if (currentProgram == null) {
            return errorResult("No program loaded");
        }

        int limit = getArgInt(args, "limit", 0);
        String nameFilter = getArgString(args, "filter");

        JsonArray strings = new JsonArray();
        Listing listing = currentProgram.getListing();
        DataIterator dataIter = listing.getDefinedData(true);
        int count = 0;

        while (dataIter.hasNext()) {
            if (limit > 0 && count >= limit) break;

            Data data = dataIter.next();
            if (data.hasStringValue()) {
                try {
                    String val = data.getValue().toString();

                    if (nameFilter != null && !val.toLowerCase().contains(nameFilter.toLowerCase())) {
                        continue;
                    }

                    JsonObject strData = new JsonObject();
                    strData.addProperty("address", data.getAddress().toString());
                    strData.addProperty("value", val);
                    strData.addProperty("length", val.length());
                    strings.add(strData);
                    count++;
                } catch (Exception e) {
                    // skip
                }
            }
        }

        JsonObject result = new JsonObject();
        result.add("strings", strings);
        result.addProperty("count", strings.size());
        return result;
    }

     private JsonObject handleListImports() {
         if (currentProgram == null) {
             return errorResult("No program loaded");
         }
         return handleListImports(new JsonObject());
     }

     private JsonObject handleListImports(JsonObject args) {
         if (currentProgram == null) {
             return errorResult("No program loaded");
         }

         int limit = getArgInt(args, "limit", 0);
         JsonArray imports = new JsonArray();
         SymbolTable symbolTable = currentProgram.getSymbolTable();
         ExternalManager extMgr = currentProgram.getExternalManager();

         SymbolIterator extSymbols = symbolTable.getExternalSymbols();
         int count = 0;
         while (extSymbols.hasNext()) {
             if (limit > 0 && count >= limit) break;
             Symbol symbol = extSymbols.next();
             ExternalLocation extLoc = extMgr.getExternalLocation(symbol);
             if (extLoc != null) {
                 JsonObject importData = new JsonObject();
                 importData.addProperty("name", symbol.getName());
                 importData.addProperty("address", symbol.getAddress().toString());
                 importData.addProperty("library", extLoc.getLibraryName());
                 imports.add(importData);
                 count++;
             }
         }

         JsonObject result = new JsonObject();
         result.add("imports", imports);
         result.addProperty("count", imports.size());
         return result;
     }

     private JsonObject handleListExports() {
         if (currentProgram == null) {
             return errorResult("No program loaded");
         }
         return handleListExports(new JsonObject());
     }

     private JsonObject handleListExports(JsonObject args) {
         if (currentProgram == null) {
             return errorResult("No program loaded");
         }

         int limit = getArgInt(args, "limit", 0);
         JsonArray exports = new JsonArray();
         SymbolTable symbolTable = currentProgram.getSymbolTable();

         SymbolIterator symIter = symbolTable.getSymbolIterator();
         int count = 0;
         while (symIter.hasNext()) {
             if (limit > 0 && count >= limit) break;
             Symbol symbol = symIter.next();
             if (symbol.isExternalEntryPoint()) {
                 JsonObject exportData = new JsonObject();
                 exportData.addProperty("name", symbol.getName());
                 exportData.addProperty("address", symbol.getAddress().toString());
                 exports.add(exportData);
                 count++;
             }
         }

         JsonObject result = new JsonObject();
         result.add("exports", exports);
         result.addProperty("count", exports.size());
         return result;
     }

    private JsonObject handleMemoryMap() {
        if (currentProgram == null) {
            return errorResult("No program loaded");
        }

        JsonArray blocks = new JsonArray();
        Memory memory = currentProgram.getMemory();

        for (MemoryBlock block : memory.getBlocks()) {
            StringBuilder perms = new StringBuilder();
            if (block.isRead()) perms.append("r");
            if (block.isWrite()) perms.append("w");
            if (block.isExecute()) perms.append("x");

            JsonObject blockData = new JsonObject();
            blockData.addProperty("name", block.getName());
            blockData.addProperty("start", block.getStart().toString());
            blockData.addProperty("end", block.getEnd().toString());
            blockData.addProperty("size", block.getSize());
            blockData.addProperty("permissions", perms.toString());
            blockData.addProperty("is_initialized", block.isInitialized());
            blockData.addProperty("is_loaded", block.isLoaded());
            blocks.add(blockData);
        }

        JsonObject result = new JsonObject();
        result.add("blocks", blocks);
        result.addProperty("count", blocks.size());
        return result;
    }

    private JsonObject handleXrefsTo(JsonObject args) {
        if (currentProgram == null) {
            return errorResult("No program loaded");
        }

        String addrStr = getArgString(args, "address");
        if (addrStr == null || addrStr.isEmpty()) {
            return errorResult("No address provided");
        }

        Address addr = resolveAddress(addrStr);
        if (addr == null) {
            return errorResult(buildFunctionTargetHint(addrStr));
        }

        JsonArray xrefs = new JsonArray();
        ReferenceManager refMgr = currentProgram.getReferenceManager();
        FunctionManager fm = currentProgram.getFunctionManager();

        for (Reference ref : refMgr.getReferencesTo(addr)) {
            Address fromAddr = ref.getFromAddress();
            Function fromFunc = fm.getFunctionContaining(fromAddr);
            Function toFunc = fm.getFunctionContaining(addr);

            JsonObject xrefData = new JsonObject();
            xrefData.addProperty("from", fromAddr.toString());
            xrefData.addProperty("to", addr.toString());
            xrefData.addProperty("ref_type", ref.getReferenceType().toString());
            if (fromFunc != null) {
                xrefData.addProperty("from_function", fromFunc.getName());
            } else {
                xrefData.add("from_function", JsonNull.INSTANCE);
            }
            if (toFunc != null) {
                xrefData.addProperty("to_function", toFunc.getName());
            } else {
                xrefData.add("to_function", JsonNull.INSTANCE);
            }
            xrefs.add(xrefData);
        }

        JsonObject result = new JsonObject();
        result.add("xrefs", xrefs);
        result.addProperty("count", xrefs.size());
        return result;
    }

    private JsonObject handleXrefsFrom(JsonObject args) {
        if (currentProgram == null) {
            return errorResult("No program loaded");
        }

        String addrStr = getArgString(args, "address");
        if (addrStr == null || addrStr.isEmpty()) {
            return errorResult("No address provided");
        }

        Address addr = resolveAddress(addrStr);
        if (addr == null) {
            return errorResult(buildFunctionTargetHint(addrStr));
        }

        JsonArray xrefs = new JsonArray();
        ReferenceManager refMgr = currentProgram.getReferenceManager();
        FunctionManager fm = currentProgram.getFunctionManager();

        // If address is a function entry point, scan the entire function body
        Function func = fm.getFunctionAt(addr);
        if (func != null) {
            ghidra.program.model.address.AddressSetView body = func.getBody();
            ghidra.program.model.address.AddressIterator addrIter = body.getAddresses(true);
            while (addrIter.hasNext()) {
                Address instrAddr = addrIter.next();
                Reference[] refs = refMgr.getReferencesFrom(instrAddr);
                for (Reference ref : refs) {
                    Address toAddr = ref.getToAddress();
                    Function toFunc = fm.getFunctionContaining(toAddr);

                    JsonObject xrefData = new JsonObject();
                    xrefData.addProperty("from", instrAddr.toString());
                    xrefData.addProperty("to", toAddr.toString());
                    xrefData.addProperty("ref_type", ref.getReferenceType().toString());
                    xrefData.addProperty("from_function", func.getName());
                    if (toFunc != null) {
                        xrefData.addProperty("to_function", toFunc.getName());
                    } else {
                        xrefData.add("to_function", JsonNull.INSTANCE);
                    }
                    xrefs.add(xrefData);
                }
            }
        } else {
            // Not a function entry point — just get refs from this single address
            Reference[] refs = refMgr.getReferencesFrom(addr);
            for (Reference ref : refs) {
                Address toAddr = ref.getToAddress();
                Function fromFunc = fm.getFunctionContaining(addr);
                Function toFunc = fm.getFunctionContaining(toAddr);

                JsonObject xrefData = new JsonObject();
                xrefData.addProperty("from", addr.toString());
                xrefData.addProperty("to", toAddr.toString());
                xrefData.addProperty("ref_type", ref.getReferenceType().toString());
                if (fromFunc != null) {
                    xrefData.addProperty("from_function", fromFunc.getName());
                } else {
                    xrefData.add("from_function", JsonNull.INSTANCE);
                }
                if (toFunc != null) {
                    xrefData.addProperty("to_function", toFunc.getName());
                } else {
                    xrefData.add("to_function", JsonNull.INSTANCE);
                }
                xrefs.add(xrefData);
            }
        }

        JsonObject result = new JsonObject();
        result.add("xrefs", xrefs);
        result.addProperty("count", xrefs.size());
        return result;
    }

    private JsonObject handleXrefsList(JsonObject args) {
        if (currentProgram == null) {
            return errorResult("No program loaded");
        }

        String addrStr = getArgString(args, "address");
        if (addrStr == null || addrStr.isEmpty()) {
            return errorResult("No address provided");
        }

        Address addr = resolveAddress(addrStr);
        if (addr == null) {
            return errorResult(buildFunctionTargetHint(addrStr));
        }

        JsonArray xrefs = new JsonArray();
        ReferenceManager refMgr = currentProgram.getReferenceManager();
        FunctionManager fm = currentProgram.getFunctionManager();

        // References TO the target address
        for (Reference ref : refMgr.getReferencesTo(addr)) {
            Address fromAddr = ref.getFromAddress();
            Function fromFunc = fm.getFunctionContaining(fromAddr);
            Function toFunc = fm.getFunctionContaining(addr);

            JsonObject xrefData = new JsonObject();
            xrefData.addProperty("from", fromAddr.toString());
            xrefData.addProperty("to", addr.toString());
            xrefData.addProperty("ref_type", ref.getReferenceType().toString());
            xrefData.addProperty("direction", "to");
            if (fromFunc != null) {
                xrefData.addProperty("from_function", fromFunc.getName());
            } else {
                xrefData.add("from_function", JsonNull.INSTANCE);
            }
            if (toFunc != null) {
                xrefData.addProperty("to_function", toFunc.getName());
            } else {
                xrefData.add("to_function", JsonNull.INSTANCE);
            }
            xrefs.add(xrefData);
        }

        // References FROM the target — if it's a function, scan the entire body
        Function func = fm.getFunctionAt(addr);
        if (func != null) {
            ghidra.program.model.address.AddressSetView body = func.getBody();
            ghidra.program.model.address.AddressIterator addrIter = body.getAddresses(true);
            while (addrIter.hasNext()) {
                Address instrAddr = addrIter.next();
                Reference[] refs = refMgr.getReferencesFrom(instrAddr);
                for (Reference ref : refs) {
                    Address toAddr = ref.getToAddress();
                    Function toFunc = fm.getFunctionContaining(toAddr);

                    JsonObject xrefData = new JsonObject();
                    xrefData.addProperty("from", instrAddr.toString());
                    xrefData.addProperty("to", toAddr.toString());
                    xrefData.addProperty("ref_type", ref.getReferenceType().toString());
                    xrefData.addProperty("direction", "from");
                    xrefData.addProperty("from_function", func.getName());
                    if (toFunc != null) {
                        xrefData.addProperty("to_function", toFunc.getName());
                    } else {
                        xrefData.add("to_function", JsonNull.INSTANCE);
                    }
                    xrefs.add(xrefData);
                }
            }
        } else {
            // Not a function entry — just get refs from this single address
            Reference[] refs = refMgr.getReferencesFrom(addr);
            for (Reference ref : refs) {
                Address toAddr = ref.getToAddress();
                Function fromFunc = fm.getFunctionContaining(addr);
                Function toFunc = fm.getFunctionContaining(toAddr);

                JsonObject xrefData = new JsonObject();
                xrefData.addProperty("from", addr.toString());
                xrefData.addProperty("to", toAddr.toString());
                xrefData.addProperty("ref_type", ref.getReferenceType().toString());
                xrefData.addProperty("direction", "from");
                if (fromFunc != null) {
                    xrefData.addProperty("from_function", fromFunc.getName());
                } else {
                    xrefData.add("from_function", JsonNull.INSTANCE);
                }
                if (toFunc != null) {
                    xrefData.addProperty("to_function", toFunc.getName());
                } else {
                    xrefData.add("to_function", JsonNull.INSTANCE);
                }
                xrefs.add(xrefData);
            }
        }

        JsonObject result = new JsonObject();
        result.add("xrefs", xrefs);
        result.addProperty("count", xrefs.size());
        return result;
    }

    private JsonObject handleImport(JsonObject args) {
        String binaryPath = getArgString(args, "binary_path");
        if (binaryPath == null || binaryPath.isEmpty()) {
            return errorResult("No binary_path provided");
        }

        String programName = getArgString(args, "program");
        File binaryFile = new File(binaryPath);
        if (programName == null || programName.isEmpty()) {
            programName = binaryFile.getName();
        }

        Project project = state.getProject();
        if (project == null) {
            return errorResult("No project open");
        }

        if (!binaryFile.exists()) {
            return errorResult("Binary file not found: " + binaryPath);
        }

        try {
            TaskMonitor mon = new ConsoleTaskMonitor();
            MessageLog log = new MessageLog();
            Object consumer = project;

            ghidra.app.util.opinion.LoadResults<Program> loadResults =
                AutoImporter.importByUsingBestGuess(
                    binaryFile, project, "/", consumer, log, mon
                );

            if (loadResults == null) {
                return errorResult("Failed to import binary");
            }

            try {
                loadResults.save(mon);
            } finally {
                loadResults.release(consumer);
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "success");
            result.addProperty("program", programName);
            return result;

        } catch (Exception e) {
            return errorResult("Import failed: " + e.getMessage());
        }
    }

    private JsonObject handleAnalyze(JsonObject args) {
        String programName = getArgString(args, "program");
        if (programName == null || programName.isEmpty()) {
            if (currentProgram == null) {
                return errorResult("No program loaded. Use 'open_program' or 'import' first.");
            }
            programName = currentProgram.getName();
        }

        if (currentProgram == null) {
            return errorResult("No program currently loaded");
        }

        // If requested program differs from current, switch to it
        if (!currentProgram.getName().equals(programName)) {
            JsonObject switchArgs = new JsonObject();
            switchArgs.addProperty("program", programName);
            JsonObject switchResult = handleOpenProgram(switchArgs);
            if (switchResult.has("error")) {
                return switchResult;
            }
        }

        try {
            TaskMonitor mon = new ConsoleTaskMonitor();

            // Analysis mutates options and listing data. Since the bridge no
            // longer keeps a session-wide transaction, analysis owns one too.
            int txId = currentProgram.startTransaction("Analyze program");
            boolean commit = false;
            try {
                analyzeAll(currentProgram);
                commit = true;
            } finally {
                currentProgram.endTransaction(txId, commit);
            }

            // Save the program
            try {
                currentProgram.save("Analysis complete", mon);
            } catch (Exception saveErr) {
                // Best effort
            }

            FunctionManager fm = currentProgram.getFunctionManager();
            JsonObject result = new JsonObject();
            result.addProperty("status", "success");
            result.addProperty("program", programName);
            result.addProperty("function_count", fm.getFunctionCount());
            return result;

        } catch (Exception e) {
            return errorResult("Analysis failed: " + e.getMessage());
        }
    }

    private JsonObject handleListPrograms() {
        Project project = state.getProject();
        if (project == null) {
            return errorResult("No project open");
        }

        try {
            ProjectData projectData = project.getProjectData();
            DomainFolder rootFolder = projectData.getRootFolder();
            JsonArray programs = new JsonArray();

            for (DomainFile domainFile : rootFolder.getFiles()) {
                boolean isCurrent = (currentProgram != null &&
                    domainFile.getName().equals(currentProgram.getName()));

                JsonObject prog = new JsonObject();
                prog.addProperty("name", domainFile.getName());
                prog.addProperty("path", domainFile.getPathname());
                prog.addProperty("type", domainFile.getContentType());
                prog.addProperty("version", domainFile.getVersion());
                prog.addProperty("current", isCurrent);

                // Add analysis metadata
                if (isCurrent && currentProgram != null) {
                    // For current program, use live data
                    FunctionManager fm = currentProgram.getFunctionManager();
                    int funcCount = fm.getFunctionCount();
                    prog.addProperty("function_count", funcCount);
                    prog.addProperty("analyzed", funcCount > 1);
                    prog.addProperty("executable_format", currentProgram.getExecutableFormat());
                } else {
                    // For other programs, use DomainFile metadata
                    try {
                        java.util.Map<String, String> metadata = domainFile.getMetadata();
                        if (metadata != null) {
                            String funcCountStr = metadata.get("# of Functions");
                            int funcCount = 0;
                            if (funcCountStr != null) {
                                try { funcCount = Integer.parseInt(funcCountStr.trim()); }
                                catch (NumberFormatException ignored) {}
                            }
                            prog.addProperty("function_count", funcCount);
                            prog.addProperty("analyzed", funcCount > 1);
                            String exeFmt = metadata.get("Executable Format");
                            if (exeFmt != null) {
                                prog.addProperty("executable_format", exeFmt);
                            }
                        }
                    } catch (Exception ignored) {
                        // metadata not available for this file
                    }
                }

                programs.add(prog);
            }

            JsonObject result = new JsonObject();
            result.add("programs", programs);
            result.addProperty("count", programs.size());
            result.addProperty("has_current_program", currentProgram != null);
            if (currentProgram != null) {
                result.addProperty("current_program_name", currentProgram.getName());
            }
            return result;

        } catch (Exception e) {
            return errorResult("Failed to list programs: " + e.getMessage());
        }
    }

    private JsonObject handleOpenProgram(JsonObject args) {
        String programName = getArgString(args, "program");
        if (programName == null || programName.isEmpty()) {
            return errorResult("Program name required");
        }

        // Already the current program? No-op.
        if (currentProgram != null && currentProgram.getName().equals(programName)) {
            JsonObject result = new JsonObject();
            result.addProperty("status", "success");
            result.addProperty("program", programName);
            return result;
        }

        Project project = state.getProject();
        if (project == null) {
            return errorResult("No project open");
        }

        try {
            ProjectData projectData = project.getProjectData();
            DomainFolder rootFolder = projectData.getRootFolder();

            // Find the domain file by name
            DomainFile domainFile = null;
            for (DomainFile f : rootFolder.getFiles()) {
                if (f.getName().equals(programName)) {
                    domainFile = f;
                    break;
                }
            }

            if (domainFile == null) {
                // Try as a path
                String path = programName.startsWith("/") ? programName : "/" + programName;
                domainFile = projectData.getFile(path);
            }

            if (domainFile == null) {
                // Build list of available programs for error message
                StringBuilder available = new StringBuilder();
                for (DomainFile f : rootFolder.getFiles()) {
                    if (available.length() > 0) available.append(", ");
                    available.append(f.getName());
                }
                return errorResult("Program not found: " + programName +
                    ". Available: " + available.toString());
            }

            Object consumer = project;
            TaskMonitor mon = new ConsoleTaskMonitor();

            // Release current program if one is open
            if (currentProgram != null) {
                try {
                    currentProgram.save("Auto-save before switch", mon);
                } catch (Exception e) {
                    // Best effort save
                }
                try {
                    currentProgram.release(consumer);
                } catch (Exception e) {
                    // Best effort release
                }
            }

            // Open the requested program
            DomainObject domObj = domainFile.getDomainObject(consumer, true, false, mon);
            if (domObj instanceof ghidra.program.model.listing.Program) {
                currentProgram = (ghidra.program.model.listing.Program) domObj;
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "success");
            result.addProperty("program", currentProgram.getName());
            return result;

        } catch (Exception e) {
            return errorResult("Failed to open program: " + e.getMessage());
        }
    }

    private JsonObject handleProgramClose() {
        if (currentProgram == null) {
            return errorResult("No program loaded");
        }

        String programName = currentProgram.getName();

        // In headless mode, we release the program
        try {
            Project project = state.getProject();
            if (project != null) {
                currentProgram.release(project);
            }
        } catch (Exception e) {
            // Best effort
        }

        currentProgram = null;

        JsonObject result = new JsonObject();
        result.addProperty("status", "closed");
        result.addProperty("program", programName);
        return result;
    }

    private JsonObject handleProgramDelete(JsonObject args) {
        String programName = getArgString(args, "program");
        if (programName == null || programName.isEmpty()) {
            return errorResult("Program name required");
        }

        Project project = state.getProject();
        if (project == null) {
            return errorResult("No project open");
        }

        try {
            ProjectData projectData = project.getProjectData();
            String path = programName.startsWith("/") ? programName : "/" + programName;
            DomainFile programFile = projectData.getFile(path);

            if (programFile == null) {
                return errorResult("Program not found: " + programName);
            }

            programFile.delete();

            JsonObject result = new JsonObject();
            result.addProperty("status", "deleted");
            result.addProperty("program", programName);
            return result;

        } catch (Exception e) {
            return errorResult("Failed to delete program: " + e.getMessage());
        }
    }

    private JsonObject handleProgramExport(JsonObject args) {
        if (currentProgram == null) {
            return errorResult("No program loaded");
        }

        String exportFormat = getArgString(args, "format");
        if (exportFormat == null) exportFormat = "json";
        String outputPath = getArgString(args, "output");

        if ("json".equals(exportFormat)) {
            // Get program info as base
            JsonObject data = handleProgramInfo();
            if (data.has("error")) {
                return data;
            }

            // Add function list
            FunctionManager fm = currentProgram.getFunctionManager();
            JsonArray functions = new JsonArray();
            FunctionIterator iter = fm.getFunctions(true);
            while (iter.hasNext()) {
                Function func = iter.next();
                JsonObject funcObj = new JsonObject();
                funcObj.addProperty("name", func.getName());
                funcObj.addProperty("address", func.getEntryPoint().toString());
                funcObj.addProperty("size", func.getBody().getNumAddresses());
                functions.add(funcObj);
            }
            data.add("functions", functions);

            if (outputPath != null && !outputPath.isEmpty()) {
                try (PrintWriter pw = new PrintWriter(new FileWriter(outputPath))) {
                    Gson prettyGson = new GsonBuilder().setPrettyPrinting().create();
                    pw.println(prettyGson.toJson(data));

                    JsonObject result = new JsonObject();
                    result.addProperty("status", "exported");
                    result.addProperty("format", "json");
                    result.addProperty("output", outputPath);
                    return result;
                } catch (IOException e) {
                    return errorResult("Failed to write file: " + e.getMessage());
                }
            } else {
                return data;
            }
        } else {
            return errorResult("Unsupported export format: " + exportFormat);
        }
    }

    // ================================================================
    // M2: Extended Command Handlers
    // ================================================================

    // --- Find Handlers ---

    private static final int STRING_PREVIEW_BYTES = 4096;
    private static final long STRING_SCAN_BYTES = 64L * 1024 * 1024;

    private boolean flag(JsonObject args, String name) {
        return args != null && args.has(name) && !args.get(name).isJsonNull() && args.get(name).getAsBoolean();
    }

    private boolean containsText(String value, String pattern, boolean sensitive) {
        return sensitive ? value.contains(pattern)
            : value.toLowerCase(java.util.Locale.ROOT).contains(pattern.toLowerCase(java.util.Locale.ROOT));
    }

    private static class StringHit {
        Address address;
        String value, source, encoding = "utf-8";
        int length;
        boolean terminated, truncated;
        StringHit(Address address, String value, int length, String source, boolean terminated, boolean truncated) {
            this.address = address; this.value = value; this.length = length; this.source = source;
            this.terminated = terminated; this.truncated = truncated;
        }
        JsonObject json() {
            JsonObject row = new JsonObject();
            row.addProperty("address", address.toString()); row.addProperty("value", value);
            row.addProperty("length", length); row.addProperty("source", source);
            row.addProperty("encoding", encoding);
            if (source.equals("defined")) row.add("terminated", JsonNull.INSTANCE); else row.addProperty("terminated", terminated);
            row.addProperty("truncated", truncated);
            return row;
        }
    }

    private StringHit definedStringHit(Data data, String value) {
        StringHit hit = new StringHit(data.getAddress(), value, data.getLength(), "defined", false, false);
        String charset = StringDataInstance.getStringDataInstance(data).getCharsetName();
        hit.encoding = charset == null ? "unknown" : charset;
        return hit;
    }

    private String decodeText(byte[] bytes) {
        try {
            return java.nio.charset.StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
                .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
                .decode(java.nio.ByteBuffer.wrap(bytes)).toString();
        } catch (java.nio.charset.CharacterCodingException e) { return null; }
    }

    private boolean textByte(int b) { return b >= 32 && b != 127 || b == 9 || b == 10 || b == 13; }

    private StringHit previewAt(Address address, int maximum) {
        Memory memory = currentProgram.getMemory();
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        boolean terminated = false, truncated = false;
        try {
            for (int i = 0; i <= maximum; i++) {
                int b = memory.getByte(address.addNoWrap(i)) & 255;
                if (b == 0) { terminated = true; break; }
                if (!textByte(b)) break;
                if (i == maximum) { truncated = true; break; }
                bytes.write(b);
            }
        } catch (Exception e) { /* a mapping boundary ends an unterminated preview */ }
        byte[] raw = bytes.toByteArray();
        String text = decodeText(raw);
        // A bounded preview may end in the middle of a UTF-8 sequence.
        if (truncated) for (int trim = 1; text == null && trim <= 3 && trim < raw.length; trim++)
            text = decodeText(Arrays.copyOf(raw, raw.length - trim));
        return text == null || text.isEmpty() ? null
            : new StringHit(address, text, raw.length, "bytes", terminated, truncated);
    }

    private static class StringSearch {
        java.util.TreeMap<Address, StringHit> hits = new java.util.TreeMap<>();
        long scanned;
        boolean truncated;
    }

    private StringSearch searchStrings(String pattern, boolean sensitive, int limit) throws Exception {
        StringSearch found = new StringSearch();
        Listing listing = currentProgram.getListing();
        DataIterator data = listing.getDefinedData(true);
        while (data.hasNext()) {
            monitor.checkCancelled();
            Data item = data.next();
            if (!item.hasStringValue()) continue;
            Object value = item.getValue();
            if (value != null && containsText(value.toString(), pattern, sensitive)) {
                found.hits.put(item.getAddress(), definedStringHit(item, value.toString()));
                if (found.hits.size() > limit) { found.truncated = true; return found; }
            }
        }
        // Scan complete printable runs, rather than treating a substring match as
        // the string base. Chunk boundaries do not terminate a run.
        Memory memory = currentProgram.getMemory();
        for (MemoryBlock block : memory.getBlocks()) {
            if (!block.isInitialized()) continue;
            ByteArrayOutputStream run = new ByteArrayOutputStream();
            Address start = null;
            boolean clipped = false;
            long offset = 0;
            while (offset < block.getSize()) {
                monitor.checkCancelled();
                if (found.scanned >= STRING_SCAN_BYTES) { found.truncated = true; return found; }
                int size = (int)Math.min(65536, Math.min(block.getSize() - offset, STRING_SCAN_BYTES - found.scanned));
                byte[] chunk = new byte[size];
                int read = memory.getBytes(block.getStart().addNoWrap(offset), chunk);
                if (read <= 0) break;
                for (int i = 0; i < read; i++) {
                    int b = chunk[i] & 255;
                    if (textByte(b)) {
                        if (start == null) start = block.getStart().addNoWrap(offset + i);
                        if (run.size() < STRING_PREVIEW_BYTES) run.write(b); else clipped = true;
                    } else if (start != null) {
                        addStringRun(found, start, run, clipped, b == 0, pattern, sensitive);
                        start = null; run.reset(); clipped = false;
                        if (found.hits.size() > limit) { found.truncated = true; return found; }
                    }
                }
                found.scanned += read; offset += read;
            }
            if (start != null) addStringRun(found, start, run, clipped, false, pattern, sensitive);
        }
        return found;
    }

    private void addStringRun(StringSearch found, Address start, ByteArrayOutputStream run,
            boolean clipped, boolean terminated, String pattern, boolean sensitive) {
        if (clipped) found.truncated = true;
        String text = decodeText(run.toByteArray());
        if (text == null || text.isEmpty() || !containsText(text, pattern, sensitive)) return;
        Data defined = currentProgram.getListing().getDataContaining(start);
        if (defined != null && defined.hasStringValue()) return;
        found.hits.putIfAbsent(start, new StringHit(start, text, run.size(), "bytes", terminated, clipped));
    }

    private JsonObject handleFindString(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");
        try {
            String pattern = getArgString(args, "pattern");
            if (pattern == null || pattern.isEmpty()) return errorResult("String pattern required");
            int limit = getArgInt(args, "limit", 1000);
            if (limit < 1 || limit > 100000) return errorResult("limit must be between 1 and 100000");
            StringSearch search = searchStrings(pattern, flag(args, "case_sensitive"), limit);
            JsonArray rows = new JsonArray();
            for (StringHit hit : search.hits.values()) { if (rows.size() == limit) break; rows.add(hit.json()); }
            JsonObject result = new JsonObject(); result.add("results", rows); result.addProperty("count", rows.size());
            JsonObject detail = new JsonObject(); detail.addProperty("sources", "defined-and-bytes");
            detail.addProperty("raw_encoding", "utf-8"); detail.addProperty("bytes_scanned", search.scanned);
            detail.addProperty("byte_budget", STRING_SCAN_BYTES); detail.addProperty("truncated", search.truncated || search.hits.size() > limit);
            detail.addProperty("limitations", "Raw search covers printable UTF-8 runs up to 4096 bytes; UTF-16 requires defined string data. Termination is unknown for defined data.");
            result.add("search", detail); return result;
        } catch (Exception e) { return errorResult("Failed to find strings: " + e.getMessage()); }
    }

    /** Existing consumers also use this helper for ASCII-like memory previews. */
    private String extractStringAt(Memory memory, Address addr, int maxLen) {
        StringHit hit = previewAt(addr, maxLen);
        return hit == null ? null : hit.value;
    }

    private boolean directDiscoverySupported() {
        return currentProgram.getLanguageID().toString().startsWith("x86:LE:64:");
    }

    private java.util.Set<Address> decodedTargets(Instruction instruction) {
        java.util.Set<Address> targets = new java.util.LinkedHashSet<>();
        for (int i = 0; i < instruction.getNumOperands(); i++) {
            Address direct = instruction.getAddress(i);
            if (direct != null) targets.add(direct);
            for (Object operand : instruction.getOpObjects(i))
                if (operand instanceof Address) targets.add((Address)operand);
        }
        // Sleigh represents RIP-relative LEA and absolute immediate moves as
        // constant COPY p-code rather than Address operand objects. LOAD/STORE
        // address inputs likewise expose direct memory operands. These are
        // candidates, not proof that an immediate was intended as a pointer.
        for (PcodeOp op : instruction.getPcode()) {
            Varnode value = null;
            if (op.getOpcode() == PcodeOp.COPY) value = op.getInput(0);
            else if (op.getOpcode() == PcodeOp.LOAD || op.getOpcode() == PcodeOp.STORE) value = op.getInput(1);
            if (value != null && value.isConstant()) {
                Address target = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(value.getOffset());
                if (currentProgram.getMemory().contains(target)) targets.add(target);
            }
        }
        return targets;
    }

    private JsonObject stringReference(StringHit hit, Address from, Address target, String type, String source) {
        JsonObject row = new JsonObject();
        row.addProperty("string_address", hit.address.toString()); row.addProperty("string_value", hit.value);
        row.addProperty("from", from.toString()); row.addProperty("ref_type", type);
        Function fn = currentProgram.getFunctionManager().getFunctionContaining(from);
        row.addProperty("from_function", fn == null ? null : fn.getName());
        row.addProperty("ownership", fn == null ? "unknown-no-containing-function" : "recorded-function");
        row.addProperty("target_address", target.toString()); row.addProperty("interior_offset", target.subtract(hit.address));
        row.addProperty("reference_source", source); return row;
    }

    private StringHit matchingHit(java.util.TreeMap<Address, StringHit> hits, Address target) {
        java.util.Map.Entry<Address, StringHit> entry = hits.floorEntry(target);
        if (entry == null) return null;
        StringHit hit = entry.getValue();
        if (!hit.address.getAddressSpace().equals(target.getAddressSpace())) return null;
        long offset = target.subtract(hit.address);
        return offset >= 0 && offset < hit.length ? hit : null;
    }

    private JsonObject handleStringRefs(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");
        String pattern = getArgString(args, "string");
        if (pattern == null || pattern.isEmpty()) return errorResult("String pattern required");
        try {
            boolean discover = flag(args, "discover");
            if (discover && !directDiscoverySupported()) return errorResult("Decoded discovery supports x86-64 little-endian only");
            int limit = getArgInt(args, "limit", 1000);
            if (limit < 1 || limit > 100000) return errorResult("limit must be between 1 and 100000");
            StringSearch search;
            if (discover) search = searchStrings(pattern, false, 10000);
            else {
                search = new StringSearch();
                DataIterator data = currentProgram.getListing().getDefinedData(true);
                while (data.hasNext()) {
                    Data item = data.next(); Object value = item.hasStringValue() ? item.getValue() : null;
                    if (value != null && containsText(value.toString(), pattern, false))
                        search.hits.put(item.getAddress(), definedStringHit(item, value.toString()));
                }
            }
            JsonArray rows = new JsonArray(); Set<String> seen = new HashSet<>(); boolean limited = false;
            ReferenceManager refs = currentProgram.getReferenceManager();
            for (StringHit hit : search.hits.values()) {
                // Include interior references, not just references to the string base.
                ghidra.program.model.address.AddressIterator destinations = refs.getReferenceDestinationIterator(
                    new ghidra.program.model.address.AddressSet(hit.address, hit.address.addNoWrap(hit.length - 1)), true);
                while (destinations.hasNext()) {
                    Address target = destinations.next();
                    for (Reference ref : refs.getReferencesTo(target)) {
                        String key = ref.getFromAddress() + ":" + target;
                        if (!seen.add(key)) continue;
                        if (rows.size() >= limit) { limited = true; break; }
                        rows.add(stringReference(hit, ref.getFromAddress(), target, ref.getReferenceType().toString(), "recorded"));
                    }
                }
            }
            JsonObject scope = new JsonObject(); JsonArray ranges = new JsonArray();
            long scanned = 0; boolean scopeTruncated = false; int decodeFailures = 0;
            if (discover) {
                int budget = getArgInt(args, "scan_bytes", 1048576);
                if (budget < 1 || budget > 67108864) return errorResult("scan_bytes must be between 1 and 67108864");
                Address first = getArgString(args, "start") == null ? null : resolveAddress(getArgString(args, "start"));
                Address last = getArgString(args, "end") == null ? null : resolveAddress(getArgString(args, "end"));
                if (getArgString(args, "start") != null && first == null || getArgString(args, "end") != null && last == null)
                    return errorResult("Invalid discovery address bound");
                if (first != null && last != null && first.compareTo(last) > 0) return errorResult("start must not exceed end");
                ghidra.app.util.PseudoDisassembler decoder = new ghidra.app.util.PseudoDisassembler(currentProgram);
                for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
                    if (!block.isExecute() || !block.isInitialized()) continue;
                    Address begin = block.getStart(), end = block.getEnd();
                    if (first != null && begin.compareTo(first) < 0) begin = first;
                    if (last != null && end.compareTo(last) > 0) end = last;
                    if (begin.compareTo(end) > 0) continue;
                    if (scanned >= budget || rows.size() >= limit) { scopeTruncated = true; break; }
                    Address cursor = begin; long inBlock = 0;
                    while (cursor != null && cursor.compareTo(end) <= 0 && scanned < budget && rows.size() < limit) {
                        monitor.checkCancelled();
                        Instruction instruction = currentProgram.getListing().getInstructionAt(cursor);
                        int length = 1;
                        try {
                            if (instruction == null) instruction = decoder.disassemble(cursor);
                            if (instruction == null) throw new IOException("Undecodable instruction");
                            length = instruction.getLength();
                            if (length > end.subtract(cursor) + 1 || scanned + length > budget) break;
                            for (Address target : decodedTargets(instruction)) {
                                StringHit hit = matchingHit(search.hits, target);
                                if (hit != null && seen.add(cursor + ":" + target)) {
                                    if (rows.size() >= limit) { limited = true; break; }
                                    rows.add(stringReference(hit, cursor, target, "DIRECT_OPERAND", "decoded"));
                                }
                            }
                        } catch (Exception e) { decodeFailures++; }
                        scanned += length; inBlock += length;
                        cursor = cursor.equals(end) ? null : cursor.addNoWrap(length);
                    }
                    if (inBlock > 0) { JsonObject range = new JsonObject(); range.addProperty("start", begin.toString());
                        range.addProperty("end", begin.addNoWrap(inBlock - 1).toString()); ranges.add(range); }
                    if (cursor != null && cursor.compareTo(end) <= 0) scopeTruncated = true;
                }
                scope.addProperty("byte_budget", budget); scope.addProperty("bytes_scanned", scanned);
                scope.add("ranges", ranges); scope.addProperty("decode_failures", decodeFailures);
                scope.addProperty("truncated", scopeTruncated || limited || search.truncated);
                scope.addProperty("limitations", "Linear executable scan; decoded operands are candidates. No register dataflow, pointer-chain, UTF-16 byte discovery, or exhaustive code-boundary recovery. Ownership requires a recorded function.");
                scope.addProperty("string_bytes_scanned", search.scanned); scope.addProperty("string_search_truncated", search.truncated);
            }
            JsonObject result = new JsonObject(); result.add("results", rows); result.addProperty("count", rows.size());
            result.addProperty("pattern", pattern);
            if (discover) result.add("discovery", scope);
            else if (limited) result.addProperty("truncated", true);
            return result;
        } catch (Exception e) { return errorResult("Failed to find string refs: " + e.getMessage()); }
    }

    // Read-only ELF unwind decoding. Never call the annotating GCC analyzer here.
    private class EhReader {
        Address at, end;
        EhReader(Address at, Address end) { this.at = at; this.end = end; }
        long raw(int size) throws Exception {
            if (size < 1 || size > 8 || at.compareTo(end) > 0 || end.subtract(at) < size - 1)
                throw new IOException("Unwind field exceeds its containing record");
            byte[] bytes = new byte[size]; currentProgram.getMemory().getBytes(at, bytes);
            long value = 0;
            for (int i = 0; i < size; i++) {
                int index = currentProgram.getLanguage().isBigEndian() ? i : size - 1 - i;
                value = (value << 8) | (bytes[index] & 255L);
            }
            at = at.addNoWrap(size); return value;
        }
        long leb(boolean signed) throws Exception {
            long value = 0; int shift = 0, b;
            do {
                b = (int)raw(1);
                int payload = b & 127;
                if (shift == 63 && (signed ? payload != 0 && payload != 127 : payload > 1))
                    throw new IOException("Overflow in unwind LEB128");
                value |= (long)(b & 127) << shift; shift += 7;
                if (shift >= 70 && (b & 128) != 0) throw new IOException("Overlong unwind LEB128");
            } while ((b & 128) != 0);
            if (signed && shift < 64 && (b & 64) != 0) value |= -1L << shift;
            return value;
        }
        String cstring() throws Exception {
            StringBuilder value = new StringBuilder();
            for (int i = 0; i < 256; i++) { int b = (int)raw(1); if (b == 0) return value.toString(); value.append((char)b); }
            throw new IOException("Unterminated CIE augmentation");
        }
        void skip(long size) throws Exception {
            if (size < 0 || size > end.subtract(at) + 1) throw new IOException("Invalid unwind augmentation length");
            at = at.addNoWrap(size);
        }
        long encoded(int encoding, Address dataBase, boolean addressValue) throws Exception {
            if (encoding == 255) throw new IOException("Omitted unwind field");
            int application = encoding & 112;
            if (application == 80) {
                if ((encoding & 15) != 0) throw new IOException("Aligned unwind encoding requires native pointers");
                int pointerSize = currentProgram.getDefaultPointerSize();
                long padding = (pointerSize - Long.remainderUnsigned(at.getOffset(), pointerSize)) % pointerSize;
                skip(padding); application = 0;
            }
            Address field = at;
            long value;
            switch (encoding & 15) {
                case 0: value = raw(currentProgram.getDefaultPointerSize()); break;
                case 1: value = leb(false); break;
                case 2: value = raw(2); break;
                case 3: value = raw(4); break;
                case 4: value = raw(8); break;
                case 9: value = leb(true); break;
                case 10: value = (short)raw(2); break;
                case 11: value = (int)raw(4); break;
                case 12: value = raw(8); break;
                default: throw new IOException("Unsupported DWARF encoding 0x" + Integer.toHexString(encoding));
            }
            if (!addressValue && (application != 0 || (encoding & 128) != 0))
                throw new IOException("Relative/indirect encoding is invalid for an unwind count or range");
            Address base = null;
            if (application == 16) base = field;
            else if (application == 48) base = dataBase;
            else if (application != 0) throw new IOException("Unsupported DWARF application 0x" + Integer.toHexString(application));
            if (application == 48 && base == null) throw new IOException("No data-relative base for this unwind field");
            if (base != null) value = base.addNoWrap(value).getOffset();
            if ((encoding & 128) != 0) {
                Address pointer = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(value);
                MemoryBlock block = currentProgram.getMemory().getBlock(pointer);
                if (block == null) throw new IOException("Unmapped indirect unwind pointer");
                value = new EhReader(pointer, block.getEnd()).raw(currentProgram.getDefaultPointerSize());
            }
            return value;
        }
    }

    private Address unwindAddress(long value) {
        return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(value);
    }

    private EhReader unwindRecord(Address start) throws Exception {
        MemoryBlock block = currentProgram.getMemory().getBlock(start);
        if (block == null || !block.isInitialized()) throw new IOException("Unmapped unwind record");
        EhReader reader = new EhReader(start, block.getEnd()); long length = reader.raw(4);
        if (length == 0xffffffffL) length = reader.raw(8);
        if (length < 4 || length > block.getEnd().subtract(reader.at) + 1)
            throw new IOException("Invalid unwind record length");
        reader.end = reader.at.addNoWrap(length - 1); return reader;
    }

    private int fdePointerEncoding(Address cieAddress) throws Exception {
        EhReader cie = unwindRecord(cieAddress);
        // DWARF64 uses an eight-byte CIE id; detect it from the initial length.
        int idSize = currentProgram.getMemory().getInt(cieAddress) == -1 ? 8 : 4;
        if (cie.raw(idSize) != 0) throw new IOException("FDE does not point to a CIE");
        int version = (int)cie.raw(1);
        if (version != 1 && version != 3 && version != 4) throw new IOException("Unsupported CIE version " + version);
        String augmentation = cie.cstring();
        if (version == 4 && (cie.raw(1) != currentProgram.getDefaultPointerSize() || cie.raw(1) != 0))
            throw new IOException("Unsupported CIE address/segment size");
        cie.leb(false); cie.leb(true);
        if (version == 1) cie.raw(1); else cie.leb(false);
        int encoding = 0;
        if (augmentation.isEmpty()) return encoding;
        if (!augmentation.startsWith("z")) throw new IOException("Unsupported CIE augmentation " + augmentation);
        long length = cie.leb(false);
        Address end = cie.at.addNoWrap(length);
        if (length < 0 || length > cie.end.subtract(cie.at) + 1) throw new IOException("CIE augmentation exceeds record");
        Address recordEnd = cie.end; cie.end = end.previous();
        for (int i = 1; i < augmentation.length(); i++) switch (augmentation.charAt(i)) {
            case 'L': cie.raw(1); break;
            case 'R': encoding = (int)cie.raw(1); break;
            case 'P': int personalityEncoding = (int)cie.raw(1); cie.encoded(personalityEncoding, null, true); break;
            case 'S': break;
            default: throw new IOException("Unsupported CIE augmentation " + augmentation);
        }
        cie.end = recordEnd; return encoding;
    }

    private Address[] fdeRange(Address address) throws Exception {
        EhReader fde = unwindRecord(address);
        int idSize = currentProgram.getMemory().getInt(address) == -1 ? 8 : 4;
        Address ciePointerField = fde.at; long cieOffset = fde.raw(idSize);
        if (cieOffset <= 0) throw new IOException("Invalid backward CIE offset");
        int encoding = fdePointerEncoding(ciePointerField.subtractNoWrap(cieOffset));
        Address start = unwindAddress(fde.encoded(encoding, null, true));
        long length = fde.encoded(encoding & 15, null, false);
        if (length <= 0) throw new IOException("Invalid FDE range length");
        return new Address[]{start, start.addNoWrap(length)};
    }

    private JsonObject handleFunctionCandidates(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");
        if (!currentProgram.getExecutableFormat().contains("ELF")) return errorResult("Unwind candidates currently support ELF .eh_frame_hdr only");
        try {
            JsonObject result = new JsonObject(); JsonArray rows = new JsonArray();
            result.add("results", rows); result.addProperty("source", "unwind");
            result.addProperty("limitations", "ELF .eh_frame_hdr index plus CIE/FDE decoding; not a complete function inventory. Text-relative/function-relative encodings and legacy augmentations are unsupported.");
            MemoryBlock block = currentProgram.getMemory().getBlock(".eh_frame_hdr");
            if (block == null) { result.addProperty("count", 0); result.addProperty("available", false); return result; }
            int limit = getArgInt(args, "limit", 1000);
            if (limit < 1 || limit > 100000) return errorResult("limit must be between 1 and 100000");
            Address lookup = getArgString(args, "address") == null ? null : resolveAddress(getArgString(args, "address"));
            if (getArgString(args, "address") != null && lookup == null) return errorResult("Invalid lookup address");
            EhReader header = new EhReader(block.getStart(), block.getEnd());
            if (header.raw(1) != 1) throw new IOException("Unsupported .eh_frame_hdr version");
            int frameEncoding = (int)header.raw(1), countEncoding = (int)header.raw(1), tableEncoding = (int)header.raw(1);
            header.encoded(frameEncoding, block.getStart(), true);
            long count = header.encoded(countEncoding, null, false);
            if (count < 0 || count > 1000000) throw new IOException("Unwind table count exceeds supported bound");
            if (tableEncoding == 255) throw new IOException("Unwind header has no search table");
            List<Address[]> index = new ArrayList<>(); Address previous = null;
            for (long i = 0; i < count; i++) {
                monitor.checkCancelled();
                Address start = unwindAddress(header.encoded(tableEncoding, block.getStart(), true));
                Address fde = unwindAddress(header.encoded(tableEncoding, block.getStart(), true));
                if (previous != null && previous.compareTo(start) > 0) throw new IOException("Unsorted unwind search table");
                previous = start; index.add(new Address[]{start, fde});
            }
            boolean truncated = false;
            for (int i = 0; i < index.size(); i++) {
                monitor.checkCancelled(); Address start = index.get(i)[0], fde = index.get(i)[1];
                if (lookup != null && start.compareTo(lookup) > 0) break;
                JsonObject row = new JsonObject(); row.addProperty("start", start.toString());
                row.addProperty("fde_address", fde.toString()); row.addProperty("source", ".eh_frame_hdr");
                row.addProperty("table_encoding", String.format("0x%02x", tableEncoding));
                row.addProperty("next_indexed_start", i + 1 < index.size() ? index.get(i + 1)[0].toString() : null);
                try {
                    Address[] range = fdeRange(fde);
                    if (!range[0].equals(start)) throw new IOException("FDE start disagrees with header index");
                    row.addProperty("range_start", range[0].toString()); row.addProperty("range_end_exclusive", range[1].toString());
                    row.addProperty("range_source", "fde");
                    if (lookup != null && (lookup.compareTo(range[0]) < 0 || lookup.compareTo(range[1]) >= 0)) continue;
                } catch (Exception e) {
                    row.addProperty("range_error", e.getMessage());
                    // A start is still useful evidence, but never guess an interval from its neighbor.
                    if (lookup != null && !lookup.equals(start)) continue;
                }
                Function fn = currentProgram.getFunctionManager().getFunctionAt(start);
                row.addProperty("function", fn == null ? null : fn.getName());
                if (rows.size() >= limit) { truncated = true; break; }
                rows.add(row);
            }
            result.addProperty("available", true); result.addProperty("indexed_entries", count);
            result.addProperty("count", rows.size()); result.addProperty("truncated", truncated); return result;
        } catch (Exception e) { return errorResult("Failed to read unwind candidates: " + e.getMessage()); }
    }

    private JsonObject handleVtableInspect(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");
        if (!currentProgram.getExecutableFormat().contains("ELF") || currentProgram.getDefaultPointerSize() != 8)
            return errorResult("Vtable inspection currently supports 64-bit ELF/Itanium address points only");
        try {
            Address point = resolveAddress(getArgString(args, "address"));
            int slots = getArgInt(args, "slots", 0);
            if (point == null || slots < 1 || slots > 512) return errorResult("A valid address and 1..512 slots are required");
            Memory memory = currentProgram.getMemory();
            long offsetToTop = memory.getLong(point.subtractNoWrap(16));
            long typeinfoValue = memory.getLong(point.subtractNoWrap(8));
            JsonObject result = new JsonObject(); result.addProperty("abi", "elf-itanium-64");
            result.addProperty("address_point", point.toString()); result.addProperty("offset_to_top", offsetToTop);
            result.addProperty("typeinfo_address", typeinfoValue == 0 ? null : unwindAddress(typeinfoValue).toString());
            JsonArray warnings = new JsonArray();
            warnings.add("The caller supplies the address point and slot count; table membership and boundaries are not inferred.");
            if (typeinfoValue != 0) try {
                Address typeinfo = unwindAddress(typeinfoValue);
                Address nameAddress = unwindAddress(memory.getLong(typeinfo.addNoWrap(8)));
                StringHit name = previewAt(nameAddress, 256);
                result.addProperty("typeinfo_name_address", nameAddress.toString());
                result.addProperty("typeinfo_name", name == null ? null : name.value);
                if (name == null || !name.terminated) warnings.add("RTTI name is unreadable or not terminated within the preview bound.");
            } catch (Exception e) { warnings.add("RTTI header/name is unreadable: " + e.getMessage()); }
            JsonArray methods = new JsonArray();
            for (int i = 0; i < slots; i++) {
                monitor.checkCancelled(); JsonObject row = new JsonObject(); Address slot = point.addNoWrap(i * 8L);
                row.addProperty("index", i); row.addProperty("slot_address", slot.toString());
                try {
                    long value = memory.getLong(slot); Address target = unwindAddress(value);
                    row.addProperty("target", target.toString()); MemoryBlock mapped = memory.getBlock(target);
                    row.addProperty("status", value == 0 ? "null" : mapped == null ? "unmapped" : mapped.isExecute() ? "executable" : "non-executable");
                    Function fn = currentProgram.getFunctionManager().getFunctionAt(target);
                    Symbol symbol = currentProgram.getSymbolTable().getPrimarySymbol(target);
                    row.addProperty("function", fn == null ? null : fn.getName());
                    row.addProperty("symbol", symbol == null ? null : symbol.getName());
                    row.addProperty("recorded_thunk", fn != null && fn.isThunk());
                } catch (Exception e) { row.addProperty("status", "unreadable"); row.addProperty("error", e.getMessage()); }
                methods.add(row);
            }
            result.add("slots", methods); result.add("warnings", warnings); return result;
        } catch (Exception e) { return errorResult("Failed to inspect vtable: " + e.getMessage()); }
    }

    private JsonObject handleFindBytes(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");

        String hexPattern = getArgString(args, "hex");
        if (hexPattern == null || hexPattern.isEmpty()) {
            return errorResult("No hex pattern provided");
        }

        try {
            String hexClean = hexPattern.replace("0x", "").replace(" ", "");
            byte[] searchBytes = new byte[hexClean.length() / 2];
            for (int i = 0; i < searchBytes.length; i++) {
                searchBytes[i] = (byte) Integer.parseInt(hexClean.substring(i * 2, i * 2 + 2), 16);
            }

            Memory memory = currentProgram.getMemory();
            JsonArray results = new JsonArray();

            Address addr = memory.getMinAddress();
            while (addr != null && results.size() < 100) {
                Address found = memory.findBytes(addr, searchBytes, null, true, monitor);
                if (found == null) break;
                JsonObject item = new JsonObject();
                item.addProperty("address", found.toString());
                results.add(item);
                addr = found.add(1);
            }

            JsonObject result = new JsonObject();
            result.add("results", results);
            result.addProperty("count", results.size());
            return result;
        } catch (Exception e) {
            return errorResult("Failed to find bytes: " + e.getMessage());
        }
    }

    private JsonObject handleFindFunction(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");

        String pattern = getArgString(args, "pattern");
        if (pattern == null) pattern = "";

        try {
            FunctionManager fm = currentProgram.getFunctionManager();
            JsonArray results = new JsonArray();
            boolean isWildcard = pattern.contains("*");

            FunctionIterator iter = fm.getFunctions(true);
            while (iter.hasNext()) {
                Function func = iter.next();
                String name = func.getName();
                boolean matches;

                if (isWildcard) {
                    // Simple wildcard matching: convert * to regex .*
                    String regex = pattern.replace(".", "\\.").replace("*", ".*");
                    matches = name.matches(regex);
                } else {
                    matches = name.toLowerCase().contains(pattern.toLowerCase());
                }

                if (matches) {
                    JsonObject item = new JsonObject();
                    item.addProperty("name", name);
                    item.addProperty("address", func.getEntryPoint().toString());
                    item.addProperty("size", func.getBody().getNumAddresses());
                    results.add(item);
                }
            }

            JsonObject result = new JsonObject();
            result.add("results", results);
            result.addProperty("count", results.size());
            return result;
        } catch (Exception e) {
            return errorResult("Failed to find functions: " + e.getMessage());
        }
    }

     private JsonObject handleFindCalls(JsonObject args) {
         if (currentProgram == null) return errorResult("No program loaded");
 
         String functionTarget = getArgString(args, "function");
         if (functionTarget == null || functionTarget.isEmpty()) {
             return errorResult("No function target provided");
         }
 
         try {
             FunctionManager fm = currentProgram.getFunctionManager();
             Function targetFunc = findFunctionByNameOrAddress(functionTarget);
 
             if (targetFunc == null) {
                 return errorResult(buildFunctionTargetHint(functionTarget));
             }
 
             // Collect outgoing CALL references from every address in the function body
             ReferenceManager refMgr = currentProgram.getReferenceManager();
             JsonArray results = new JsonArray();
 
             for (Address addr : targetFunc.getBody().getAddresses(true)) {
                 for (Reference ref : refMgr.getReferencesFrom(addr)) {
                     if (ref.getReferenceType().isCall()) {
                         Address toAddr = ref.getToAddress();
                         Function calleeFunc = fm.getFunctionAt(toAddr);
                         if (calleeFunc == null) calleeFunc = fm.getFunctionContaining(toAddr);
                         JsonObject item = new JsonObject();
                         item.addProperty("call_site", addr.toString());
                         item.addProperty("callee", calleeFunc != null ? calleeFunc.getName() : toAddr.toString());
                         item.addProperty("callee_address", toAddr.toString());
                         item.addProperty("type", ref.getReferenceType().toString());
                         results.add(item);
                     }
                 }
             }
 
             JsonObject result = new JsonObject();
             result.add("results", results);
             result.addProperty("count", results.size());
             result.addProperty("target", functionTarget);
             return result;
         } catch (Exception e) {
             return errorResult("Failed to find calls: " + e.getMessage());
         }
     }

    private JsonObject handleFindCrypto() {
        if (currentProgram == null) return errorResult("No program loaded");

        try {
            Memory memory = currentProgram.getMemory();
            JsonArray results = new JsonArray();

            String[][] cryptoPatterns = {
                {"AES S-box", "637c777bf26b6fc53001672bfed7ab76"},
                {"SHA-256", "428a2f98d728ae227137449123ef65cd"},
                {"MD5", "d76aa478e8c7b756242070db01234567"}
            };

            for (String[] cp : cryptoPatterns) {
                String name = cp[0];
                String hexPattern = cp[1];
                byte[] searchBytes = new byte[hexPattern.length() / 2];
                for (int i = 0; i < searchBytes.length; i++) {
                    searchBytes[i] = (byte) Integer.parseInt(hexPattern.substring(i * 2, i * 2 + 2), 16);
                }

                Address addr = memory.getMinAddress();
                Address found = memory.findBytes(addr, searchBytes, null, true, monitor);
                if (found != null) {
                    JsonObject item = new JsonObject();
                    item.addProperty("type", name);
                    item.addProperty("address", found.toString());
                    item.addProperty("pattern", hexPattern);
                    results.add(item);
                }
            }

            JsonObject result = new JsonObject();
            result.add("results", results);
            result.addProperty("count", results.size());
            return result;
        } catch (Exception e) {
            return errorResult("Failed to find crypto: " + e.getMessage());
        }
    }

    private JsonObject handleFindInteresting() {
        if (currentProgram == null) return errorResult("No program loaded");

        try {
            FunctionManager fm = currentProgram.getFunctionManager();
            ReferenceManager refMgr = currentProgram.getReferenceManager();
            List<JsonObject> resultsList = new ArrayList<>();

            String[] suspiciousNames = {"password", "key", "encrypt", "decrypt", "crypt",
                "auth", "login", "admin", "secret"};

            FunctionIterator iter = fm.getFunctions(true);
            while (iter.hasNext()) {
                Function func = iter.next();
                String funcName = func.getName();
                Address funcAddr = func.getEntryPoint();
                long funcSize = func.getBody().getNumAddresses();

                int xrefCount = 0;
                for (Reference ref : refMgr.getReferencesTo(funcAddr)) {
                    xrefCount++;
                }

                JsonArray reasons = new JsonArray();

                if (funcSize > 1000) {
                    reasons.add(new JsonPrimitive("large function (" + funcSize + " bytes)"));
                }
                if (xrefCount > 50) {
                    reasons.add(new JsonPrimitive("many xrefs (" + xrefCount + ")"));
                }
                for (String sus : suspiciousNames) {
                    if (funcName.toLowerCase().contains(sus)) {
                        reasons.add(new JsonPrimitive("suspicious name"));
                        break;
                    }
                }

                if (reasons.size() > 0) {
                    JsonObject item = new JsonObject();
                    item.addProperty("name", funcName);
                    item.addProperty("address", funcAddr.toString());
                    item.addProperty("size", funcSize);
                    item.addProperty("xrefs", xrefCount);
                    item.add("reasons", reasons);
                    resultsList.add(item);
                }
            }

            // Sort by number of reasons (descending)
            resultsList.sort((a, b) -> b.getAsJsonArray("reasons").size() - a.getAsJsonArray("reasons").size());

            JsonArray results = new JsonArray();
            int limit = Math.min(50, resultsList.size());
            for (int i = 0; i < limit; i++) {
                results.add(resultsList.get(i));
            }

            JsonObject result = new JsonObject();
            result.add("results", results);
            result.addProperty("count", resultsList.size());
            return result;
        } catch (Exception e) {
            return errorResult("Failed to find interesting functions: " + e.getMessage());
        }
    }

    // --- Symbol Handlers ---

    private JsonObject handleSymbolList(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");

        int limit = getArgInt(args, "limit", 0);
        String nameFilter = getArgString(args, "filter");

        SymbolTable symbolTable = currentProgram.getSymbolTable();
        JsonArray symbols = new JsonArray();
        int count = 0;

        SymbolIterator symIter = symbolTable.getAllSymbols(true);
        while (symIter.hasNext()) {
            if (limit > 0 && count >= limit) break;

            Symbol symbol = symIter.next();
            String name = symbol.getName();

            if (nameFilter != null && !name.toLowerCase().contains(nameFilter.toLowerCase())) {
                continue;
            }

            JsonObject symData = new JsonObject();
            symData.addProperty("name", name);
            symData.addProperty("address", symbol.getAddress().toString());
            symData.addProperty("type", symbol.getSymbolType().toString());
            symData.addProperty("source", symbol.getSource().toString());
            symData.addProperty("is_primary", symbol.isPrimary());
            symbols.add(symData);
            count++;
        }

        JsonObject result = new JsonObject();
        result.add("symbols", symbols);
        result.addProperty("count", symbols.size());
        return result;
    }

    private JsonObject handleSymbolGet(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");

        String addressOrName = getArgString(args, "name");
        if (addressOrName == null || addressOrName.isEmpty()) {
            return errorResult("No symbol name or address provided");
        }

        SymbolTable symbolTable = currentProgram.getSymbolTable();

        // Try as address first
        boolean looksLikeAddress = addressOrName.startsWith("0x") ||
            addressOrName.chars().allMatch(c -> "0123456789abcdefABCDEF".indexOf(c) >= 0);

        if (looksLikeAddress) {
            try {
                Address addr = currentProgram.getAddressFactory().getAddress(addressOrName);
                if (addr != null) {
                    Symbol[] symbolsAtAddr = symbolTable.getSymbols(addr);
                    if (symbolsAtAddr.length == 0) {
                        return errorResult("No symbol at address: " + addressOrName);
                    }
                    JsonArray syms = new JsonArray();
                    for (Symbol s : symbolsAtAddr) {
                        JsonObject symData = new JsonObject();
                        symData.addProperty("name", s.getName());
                        symData.addProperty("address", s.getAddress().toString());
                        symData.addProperty("type", s.getSymbolType().toString());
                        symData.addProperty("source", s.getSource().toString());
                        syms.add(symData);
                    }
                    JsonObject result = new JsonObject();
                    result.add("symbols", syms);
                    return result;
                }
            } catch (Exception e) {
                // fall through to name lookup
            }
        }

        // Try as name
        SymbolIterator symsByName = symbolTable.getSymbols(addressOrName);
        JsonArray syms = new JsonArray();
        while (symsByName.hasNext()) {
            Symbol s = symsByName.next();
            JsonObject symData = new JsonObject();
            symData.addProperty("name", s.getName());
            symData.addProperty("address", s.getAddress().toString());
            symData.addProperty("type", s.getSymbolType().toString());
            symData.addProperty("source", s.getSource().toString());
            syms.add(symData);
        }

        if (syms.size() == 0) {
            return errorResult("Symbol not found: " + addressOrName);
        }

        JsonObject result = new JsonObject();
        result.add("symbols", syms);
        return result;
    }

    private JsonObject handleSymbolCreate(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");

        String addressStr = getArgString(args, "address");
        String name = getArgString(args, "name");
        if (addressStr == null || name == null) {
            return errorResult("Address and name required");
        }

        try {
            Address addr = currentProgram.getAddressFactory().getAddress(addressStr);
            if (addr == null) return errorResult("Invalid address: " + addressStr);

            int txId = currentProgram.startTransaction("Create symbol");
            try {
                SymbolTable symbolTable = currentProgram.getSymbolTable();
                symbolTable.createLabel(addr, name, SourceType.USER_DEFINED);
                currentProgram.endTransaction(txId, true);
            } catch (Exception e) {
                currentProgram.endTransaction(txId, false);
                throw e;
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "created");
            result.addProperty("address", addressStr);
            result.addProperty("name", name);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to create symbol: " + e.getMessage());
        }
    }

    private JsonObject handleSymbolDelete(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");

        String name = getArgString(args, "name");
        if (name == null) return errorResult("Symbol name required");

        try {
            SymbolTable symbolTable = currentProgram.getSymbolTable();
            SymbolIterator syms = symbolTable.getSymbols(name);
            List<Symbol> toDelete = new ArrayList<>();
            while (syms.hasNext()) {
                toDelete.add(syms.next());
            }

            if (toDelete.isEmpty()) {
                return errorResult("Symbol not found: " + name);
            }

            int txId = currentProgram.startTransaction("Delete symbol");
            try {
                for (Symbol s : toDelete) {
                    s.delete();
                }
                currentProgram.endTransaction(txId, true);
            } catch (Exception e) {
                currentProgram.endTransaction(txId, false);
                throw e;
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "deleted");
            result.addProperty("name", name);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to delete symbol: " + e.getMessage());
        }
    }

    private JsonObject handleSymbolRename(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");

        String oldName = getArgString(args, "old_name");
        String newName = getArgString(args, "new_name");
        if (oldName == null || newName == null) {
            return errorResult("old_name and new_name required");
        }

        try {
            SymbolTable symbolTable = currentProgram.getSymbolTable();
            SymbolIterator syms = symbolTable.getSymbols(oldName);
            List<Symbol> toRename = new ArrayList<>();
            while (syms.hasNext()) {
                toRename.add(syms.next());
            }

            if (toRename.isEmpty()) {
                return errorResult("Symbol not found: " + oldName);
            }

            int txId = currentProgram.startTransaction("Rename symbol");
            try {
                for (Symbol s : toRename) {
                    s.setName(newName, SourceType.USER_DEFINED);
                }
                currentProgram.endTransaction(txId, true);
            } catch (Exception e) {
                currentProgram.endTransaction(txId, false);
                throw e;
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "renamed");
            result.addProperty("old_name", oldName);
            result.addProperty("new_name", newName);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to rename symbol: " + e.getMessage());
        }
    }

    // --- Type Handlers ---

    private JsonObject handleTypeList(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");

        int limit = getArgInt(args, "limit", 0);
        String nameFilter = getArgString(args, "filter");
        DataTypeManager dtm = currentProgram.getDataTypeManager();
        JsonArray types = new JsonArray();

        Iterator<DataType> dtIter = dtm.getAllDataTypes();
        int count = 0;
        while (dtIter.hasNext()) {
            DataType dt = dtIter.next();
            if (limit > 0 && count >= limit) break;

            if (nameFilter != null && !dt.getName().toLowerCase().contains(nameFilter.toLowerCase())) {
                continue;
            }

            JsonObject typeData = new JsonObject();
            typeData.addProperty("name", dt.getName());
            typeData.addProperty("path", dt.getPathName());
            typeData.addProperty("category", dt.getCategoryPath().toString());
            typeData.addProperty("size", dt.getLength());
            String kind;
            if (dt instanceof Structure) kind = "struct";
            else if (dt instanceof Union) kind = "union";
            else if (dt instanceof ghidra.program.model.data.Enum) kind = "enum";
            else if (dt instanceof TypeDef) kind = "typedef";
            else if (dt instanceof FunctionDefinition) kind = "functiondef";
            else if (dt instanceof Pointer) kind = "pointer";
            else if (dt instanceof Array) kind = "array";
            else kind = "other";
            typeData.addProperty("kind", kind);
            types.add(typeData);
            count++;
        }

        JsonObject result = new JsonObject();
        result.add("types", types);
        result.addProperty("count", types.size());
        return result;
    }

    private JsonObject handleTypeGet(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");

        String typeName = getArgString(args, "name");
        if (typeName == null) return errorResult("Type name required");

        DataType dataType = resolveDataType(typeName);
        if (dataType == null) {
            return errorResult("Type not found: " + typeName);
        }

        JsonObject typeInfo = new JsonObject();
        typeInfo.addProperty("name", dataType.getName());
        typeInfo.addProperty("path", dataType.getPathName());
        typeInfo.addProperty("category", dataType.getCategoryPath().toString());
        typeInfo.addProperty("size", dataType.getLength());
        typeInfo.addProperty("description", dataType.getDescription());

        if (dataType instanceof Structure) {
            typeInfo.addProperty("kind", "struct");
            Structure struct = (Structure) dataType;
            JsonArray components = new JsonArray();
            for (DataTypeComponent comp : struct.getComponents()) {
                JsonObject compObj = new JsonObject();
                compObj.addProperty("name", comp.getFieldName());
                compObj.addProperty("type", comp.getDataType().getName());
                compObj.addProperty("offset", comp.getOffset());
                compObj.addProperty("size", comp.getLength());
                components.add(compObj);
            }
            typeInfo.add("components", components);
        } else if (dataType instanceof Union) {
            typeInfo.addProperty("kind", "union");
            Union union = (Union) dataType;
            JsonArray components = new JsonArray();
            for (DataTypeComponent comp : union.getComponents()) {
                JsonObject compObj = new JsonObject();
                compObj.addProperty("name", comp.getFieldName());
                compObj.addProperty("type", comp.getDataType().getName());
                compObj.addProperty("offset", comp.getOffset());
                compObj.addProperty("size", comp.getLength());
                components.add(compObj);
            }
            typeInfo.add("components", components);
        } else if (dataType instanceof ghidra.program.model.data.Enum) {
            typeInfo.addProperty("kind", "enum");
            ghidra.program.model.data.Enum enumType = (ghidra.program.model.data.Enum) dataType;
            JsonArray members = new JsonArray();
            for (String name : enumType.getNames()) {
                JsonObject member = new JsonObject();
                member.addProperty("name", name);
                member.addProperty("value", enumType.getValue(name));
                members.add(member);
            }
            typeInfo.add("members", members);
        } else if (dataType instanceof TypeDef) {
            typeInfo.addProperty("kind", "typedef");
            TypeDef td = (TypeDef) dataType;
            typeInfo.addProperty("base_type", td.getDataType().getName());
            typeInfo.addProperty("base_type_path", td.getDataType().getPathName());
        } else if (dataType instanceof FunctionDefinition) {
            typeInfo.addProperty("kind", "functiondef");
        } else if (dataType instanceof Pointer) {
            typeInfo.addProperty("kind", "pointer");
        } else if (dataType instanceof Array) {
            typeInfo.addProperty("kind", "array");
        } else {
            typeInfo.addProperty("kind", "other");
        }

        return typeInfo;
    }

    private JsonObject handleTypeCreate(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");

        String typeName = getArgString(args, "definition");
        if (typeName == null) typeName = getArgString(args, "name");
        if (typeName == null) return errorResult("Type name required");

        try {
            DataTypeManager dtm = currentProgram.getDataTypeManager();
            int txId = currentProgram.startTransaction("Create type");
            try {
                StructureDataType newStruct = new StructureDataType(typeName, 0);
                dtm.addDataType(newStruct, null);
                currentProgram.endTransaction(txId, true);
            } catch (Exception e) {
                currentProgram.endTransaction(txId, false);
                throw e;
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "created");
            result.addProperty("name", typeName);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to create type: " + e.getMessage());
        }
    }

    private JsonObject handleTypeApply(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");

        String addressStr = getArgString(args, "address");
        String typeName = getArgString(args, "type_name");
        if (addressStr == null || typeName == null) {
            return errorResult("Address and type_name required");
        }

        try {
            Address addr = currentProgram.getAddressFactory().getAddress(addressStr);
            if (addr == null) return errorResult("Invalid address: " + addressStr);

            DataType dataType = resolveDataType(typeName);
            if (dataType == null) {
                return errorResult("Type not found: " + typeName);
            }

            int txId = currentProgram.startTransaction("Apply type");
            try {
                Listing listing = currentProgram.getListing();
                listing.createData(addr, dataType);
                currentProgram.endTransaction(txId, true);
            } catch (Exception e) {
                currentProgram.endTransaction(txId, false);
                throw e;
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "applied");
            result.addProperty("address", addressStr);
            result.addProperty("type", typeName);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to apply type: " + e.getMessage());
        }
    }

    private DataType resolveDataType(String name) {
        if (name == null || name.isEmpty()) return null;
        DataTypeManager dtm = currentProgram.getDataTypeManager();
        // Try by path first (e.g., "/int" or "/myCategory/myStruct")
        DataType dt = dtm.getDataType(name);
        if (dt != null) return dt;
        // Scan by simple name
        Iterator<DataType> iter = dtm.getAllDataTypes();
        while (iter.hasNext()) {
            DataType c = iter.next();
            if (c.getName().equals(name)) return c;
        }
        // Handle pointer syntax: "int *" or "char **"
        if (name.endsWith("*")) {
            String base = name.substring(0, name.lastIndexOf('*')).trim();
            DataType baseType = resolveDataType(base);
            if (baseType != null) return new PointerDataType(baseType);
        }
        return null;
    }

    private JsonObject handleTypeDelete(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");
        String typeName = getArgString(args, "name");
        if (typeName == null || typeName.isEmpty()) return errorResult("Type name required");

        try {
            DataType dataType = resolveDataType(typeName);
            if (dataType == null) return errorResult("Type not found: " + typeName);

            String fullPath = dataType.getPathName();
            DataTypeManager dtm = currentProgram.getDataTypeManager();
            int txId = currentProgram.startTransaction("Delete type");
            try {
                boolean removed = dtm.remove(dataType);
                currentProgram.endTransaction(txId, true);
                if (!removed) {
                    return errorResult("Failed to remove type: " + typeName + " (may be in use or built-in)");
                }
            } catch (Exception e) {
                currentProgram.endTransaction(txId, false);
                throw e;
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "deleted");
            result.addProperty("name", typeName);
            result.addProperty("path", fullPath);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to delete type: " + e.getMessage());
        }
    }

    private JsonObject handleTypeRename(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");
        String oldName = getArgString(args, "old_name");
        String newName = getArgString(args, "new_name");
        if (oldName == null || oldName.isEmpty()) return errorResult("Old type name required");
        if (newName == null || newName.isEmpty()) return errorResult("New type name required");

        try {
            DataType dataType = resolveDataType(oldName);
            if (dataType == null) return errorResult("Type not found: " + oldName);

            int txId = currentProgram.startTransaction("Rename type");
            try {
                dataType.setName(newName);
                currentProgram.endTransaction(txId, true);
            } catch (Exception e) {
                currentProgram.endTransaction(txId, false);
                throw e;
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "renamed");
            result.addProperty("old_name", oldName);
            result.addProperty("new_name", newName);
            result.addProperty("path", dataType.getPathName());
            return result;
        } catch (Exception e) {
            return errorResult("Failed to rename type: " + e.getMessage());
        }
    }

    private JsonObject handleTypeCreateEnum(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");
        String name = getArgString(args, "name");
        String valuesStr = getArgString(args, "values");
        int size = getArgInt(args, "size", 4);
        if (name == null || valuesStr == null) return errorResult("name and values required");

        if (size != 1 && size != 2 && size != 4 && size != 8)
            return errorResult("Enum size must be 1, 2, 4, or 8");

        try {
            DataTypeManager dtm = currentProgram.getDataTypeManager();
            int txId = currentProgram.startTransaction("Create enum");
            try {
                EnumDataType enumDt = new EnumDataType(name, size);
                String[] pairs = valuesStr.split(",");
                for (String pair : pairs) {
                    String[] kv = pair.trim().split("=", 2);
                    if (kv.length != 2)
                        throw new IllegalArgumentException("Invalid KEY=VALUE pair: " + pair.trim());
                    String key = kv[0].trim();
                    long value = Long.decode(kv[1].trim());
                    enumDt.add(key, value);
                }
                dtm.addDataType(enumDt, null);
                currentProgram.endTransaction(txId, true);
            } catch (Exception e) {
                currentProgram.endTransaction(txId, false);
                throw e;
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "created");
            result.addProperty("name", name);
            result.addProperty("kind", "enum");
            result.addProperty("size", size);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to create enum: " + e.getMessage());
        }
    }

    private JsonObject handleTypeTypedef(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");
        String name = getArgString(args, "name");
        String baseTypeName = getArgString(args, "base_type");
        if (name == null || baseTypeName == null) return errorResult("name and base_type required");

        try {
            DataType baseType = resolveDataType(baseTypeName);
            if (baseType == null) return errorResult("Base type not found: " + baseTypeName);

            DataTypeManager dtm = currentProgram.getDataTypeManager();
            int txId = currentProgram.startTransaction("Create typedef");
            try {
                TypedefDataType td = new TypedefDataType(name, baseType);
                dtm.addDataType(td, null);
                currentProgram.endTransaction(txId, true);
            } catch (Exception e) {
                currentProgram.endTransaction(txId, false);
                throw e;
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "created");
            result.addProperty("name", name);
            result.addProperty("kind", "typedef");
            result.addProperty("base_type", baseTypeName);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to create typedef: " + e.getMessage());
        }
    }

    private JsonObject handleTypeAddField(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");
        String typeName = getArgString(args, "type_name");
        String fieldName = getArgString(args, "field_name");
        String fieldTypeName = getArgString(args, "field_type");
        if (typeName == null || fieldName == null || fieldTypeName == null)
            return errorResult("type_name, field_name, and field_type required");

        try {
            DataType structType = resolveDataType(typeName);
            if (structType == null) return errorResult("Type not found: " + typeName);
            if (!(structType instanceof Structure))
                return errorResult("Type is not a struct: " + typeName);

            DataType fieldDataType = resolveDataType(fieldTypeName);
            if (fieldDataType == null) return errorResult("Field type not found: " + fieldTypeName);

            Structure struct = (Structure) structType;
            int txId = currentProgram.startTransaction("Add field to struct");
            try {
                int offset = getArgInt(args, "offset", -1);
                if (offset >= 0) {
                    int fieldSize = getArgInt(args, "size", fieldDataType.getLength());
                    struct.insertAtOffset(offset, fieldDataType, fieldSize, fieldName, null);
                } else {
                    struct.add(fieldDataType, fieldName, null);
                }
                currentProgram.endTransaction(txId, true);
            } catch (Exception e) {
                currentProgram.endTransaction(txId, false);
                throw e;
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "field_added");
            result.addProperty("struct", typeName);
            result.addProperty("field", fieldName);
            result.addProperty("field_type", fieldTypeName);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to add field: " + e.getMessage());
        }
    }

    private JsonObject handleTypeDelField(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");
        String typeName = getArgString(args, "type_name");
        String fieldName = getArgString(args, "field_name");
        if (typeName == null || fieldName == null)
            return errorResult("type_name and field_name required");

        try {
            DataType structType = resolveDataType(typeName);
            if (structType == null) return errorResult("Type not found: " + typeName);
            if (!(structType instanceof Structure))
                return errorResult("Type is not a struct: " + typeName);

            Structure struct = (Structure) structType;
            int ordinal = -1;
            for (DataTypeComponent comp : struct.getComponents()) {
                if (fieldName.equals(comp.getFieldName())) {
                    ordinal = comp.getOrdinal();
                    break;
                }
            }
            if (ordinal < 0)
                return errorResult("Field not found: " + fieldName + " in " + typeName);

            int txId = currentProgram.startTransaction("Delete field from struct");
            try {
                struct.delete(ordinal);
                currentProgram.endTransaction(txId, true);
            } catch (Exception e) {
                currentProgram.endTransaction(txId, false);
                throw e;
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "field_deleted");
            result.addProperty("struct", typeName);
            result.addProperty("field", fieldName);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to delete field: " + e.getMessage());
        }
    }

    private JsonObject handleFunctionSetSignature(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");
        String target = getArgString(args, "target");
        String sigStr = getArgString(args, "signature");
        if (target == null || sigStr == null) return errorResult("target and signature required");

        try {
            Function func = findFunctionByNameOrAddress(target);
            if (func == null) return errorResult(buildFunctionTargetHint(target));

            int txId = currentProgram.startTransaction("Set function signature");
            boolean commit = false;
            try {
                // A null ServiceProvider is invalid. This overload resolves program-local
                // types and throws parsing errors instead of displaying GUI dialogs.
                FunctionDefinitionDataType funcDef =
                    ghidra.app.util.cparser.C.CParserUtils.parseSignature(
                        (ghidra.app.services.DataTypeManagerService) null,
                        currentProgram, sigStr, false);
                if (funcDef == null) {
                    return errorResult("Failed to parse signature: " + sigStr);
                }
                ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(
                    func.getEntryPoint(), funcDef, SourceType.USER_DEFINED);
                if (!cmd.applyTo(currentProgram, monitor)) {
                    return errorResult("Failed to apply signature: " + cmd.getStatusMsg());
                }
                commit = true;
            } finally {
                currentProgram.endTransaction(txId, commit);
            }

            String newSig = null;
            try { newSig = func.getPrototypeString(false, false); } catch (Exception e) {}

            JsonObject result = new JsonObject();
            result.addProperty("status", "signature_set");
            result.addProperty("function", func.getName());
            result.addProperty("address", func.getEntryPoint().toString());
            if (newSig != null) {
                result.addProperty("signature", newSig);
            }
            return result;
        } catch (Exception | ghidra.app.util.cparser.C.TokenMgrError e) {
            return errorResult("Failed to set signature: " + e.getMessage());
        }
    }

    private JsonObject handleFunctionSetReturnType(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");
        String target = getArgString(args, "target");
        String returnTypeName = getArgString(args, "return_type");
        if (target == null || returnTypeName == null)
            return errorResult("target and return_type required");

        try {
            Function func = findFunctionByNameOrAddress(target);
            if (func == null) return errorResult(buildFunctionTargetHint(target));

            DataType returnType = resolveDataType(returnTypeName);
            if (returnType == null)
                return errorResult("Return type not found: " + returnTypeName);

            int txId = currentProgram.startTransaction("Set return type");
            try {
                func.setReturnType(returnType, SourceType.USER_DEFINED);
                currentProgram.endTransaction(txId, true);
            } catch (Exception e) {
                currentProgram.endTransaction(txId, false);
                throw e;
            }

            String sig = null;
            try { sig = func.getPrototypeString(false, false); } catch (Exception e) {}

            JsonObject result = new JsonObject();
            result.addProperty("status", "return_type_set");
            result.addProperty("function", func.getName());
            result.addProperty("return_type", returnTypeName);
            if (sig != null) result.addProperty("signature", sig);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to set return type: " + e.getMessage());
        }
    }

    private JsonObject handleFunctionSetCallingConvention(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");
        String target = getArgString(args, "target");
        String convention = getArgString(args, "convention");
        if (target == null || convention == null)
            return errorResult("target and convention required");

        try {
            Function func = findFunctionByNameOrAddress(target);
            if (func == null) return errorResult(buildFunctionTargetHint(target));

            int txId = currentProgram.startTransaction("Set calling convention");
            try {
                func.setCallingConvention(convention);
                currentProgram.endTransaction(txId, true);
            } catch (Exception e) {
                currentProgram.endTransaction(txId, false);
                throw e;
            }

            String sig = null;
            try { sig = func.getPrototypeString(false, false); } catch (Exception e) {}

            JsonObject result = new JsonObject();
            result.addProperty("status", "calling_convention_set");
            result.addProperty("function", func.getName());
            result.addProperty("calling_convention", convention);
            if (sig != null) result.addProperty("signature", sig);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to set calling convention: " + e.getMessage());
        }
    }

    private JsonObject handleFunctionSetNoReturn(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");
        String target = getArgString(args, "target");
        if (target == null || target.isEmpty())
            return errorResult("target required");
        boolean noReturn = getArgBool(args, "no_return", true);

        try {
            Function func = findFunctionByNameOrAddress(target);
            if (func == null) return errorResult(buildFunctionTargetHint(target));

            int txId = currentProgram.startTransaction("Set function no-return");
            try {
                func.setNoReturn(noReturn);
                currentProgram.endTransaction(txId, true);
            } catch (Exception e) {
                currentProgram.endTransaction(txId, false);
                throw e;
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "no_return_set");
            result.addProperty("function", func.getName());
            result.addProperty("no_return", func.hasNoReturn());
            return result;
        } catch (Exception e) {
            return errorResult("Failed to set no-return: " + e.getMessage());
        }
    }

    /**
     * Returns a function's body as a list of disjoint address ranges. Useful for detecting
     * cases where Ghidra has merged inlined exception-handling blocks (or other non-contiguous
     * code) into a function, or where a function's body doesn't cover everything expected.
     */
    private JsonObject handleFunctionBody(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");
        String target = getArgString(args, "target");
        if (target == null || target.isEmpty())
            return errorResult("target required");

        try {
            Function func = findFunctionByNameOrAddress(target);
            if (func == null) return errorResult(buildFunctionTargetHint(target));

            ghidra.program.model.address.AddressSetView body = func.getBody();
            JsonArray ranges = new JsonArray();
            ghidra.program.model.address.AddressRangeIterator rangeIter = body.getAddressRanges();
            while (rangeIter.hasNext()) {
                ghidra.program.model.address.AddressRange range = rangeIter.next();
                JsonObject rangeData = new JsonObject();
                rangeData.addProperty("min_address", range.getMinAddress().toString());
                rangeData.addProperty("max_address", range.getMaxAddress().toString());
                rangeData.addProperty("length", range.getLength());
                ranges.add(rangeData);
            }

            JsonObject result = new JsonObject();
            result.addProperty("function", func.getName());
            result.addProperty("entry_point", func.getEntryPoint().toString());
            result.add("ranges", ranges);
            result.addProperty("range_count", ranges.size());
            result.addProperty("total_size", body.getNumAddresses());
            result.addProperty("is_contiguous", ranges.size() <= 1);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to get function body: " + e.getMessage());
        }
    }

    /**
     * Adds or removes an address range from a function's body. Use with care: Ghidra's analyzers
     * generally own body boundaries, and manual edits can be undone by re-running analysis.
     */
    private JsonObject handleFunctionSetBody(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");
        String target = getArgString(args, "target");
        String startStr = getArgString(args, "start");
        String endStr = getArgString(args, "end");
        String action = getArgString(args, "action");
        if (action == null || action.isEmpty()) action = "add";
        if (target == null || target.isEmpty())
            return errorResult("target required");
        if (startStr == null || startStr.isEmpty() || endStr == null || endStr.isEmpty())
            return errorResult("start and end addresses required");

        try {
            Function func = findFunctionByNameOrAddress(target);
            if (func == null) return errorResult(buildFunctionTargetHint(target));

            Address startAddr = resolveAddress(startStr);
            Address endAddr = resolveAddress(endStr);
            if (startAddr == null) return errorResult("Invalid start address: " + startStr);
            if (endAddr == null) return errorResult("Invalid end address: " + endStr);

            ghidra.program.model.address.AddressSet newBody =
                new ghidra.program.model.address.AddressSet(func.getBody());
            ghidra.program.model.address.AddressSet rangeSet =
                new ghidra.program.model.address.AddressSet(startAddr, endAddr);

            if ("remove".equalsIgnoreCase(action)) {
                newBody.delete(rangeSet);
            } else if ("add".equalsIgnoreCase(action)) {
                newBody.add(rangeSet);
            } else {
                return errorResult("Invalid action '" + action + "' (expected 'add' or 'remove')");
            }

            int txId = currentProgram.startTransaction("Set function body");
            try {
                func.setBody(newBody);
                currentProgram.endTransaction(txId, true);
            } catch (Exception e) {
                currentProgram.endTransaction(txId, false);
                throw e;
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "body_set");
            result.addProperty("function", func.getName());
            result.addProperty("action", action);
            result.addProperty("total_size", func.getBody().getNumAddresses());
            return result;
        } catch (Exception e) {
            return errorResult("Failed to set function body: " + e.getMessage());
        }
    }

    private JsonObject handleSetVarType(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");
        String funcTarget = getArgString(args, "function");
        String varName = getArgString(args, "var_name");
        String typeName = getArgString(args, "type_name");
        if (funcTarget == null || funcTarget.isEmpty()) return errorResult("Function target required");
        if (varName == null || varName.isEmpty()) return errorResult("Variable name required (--var)");
        if (typeName == null || typeName.isEmpty()) return errorResult("Type name required (--type)");

        try {
            Function func = findFunctionByNameOrAddress(funcTarget);
            if (func == null) return errorResult(buildFunctionTargetHint(funcTarget));

            DataType newType = resolveDataType(typeName);
            if (newType == null) return errorResult("Type not found: " + typeName);

            DecompInterface decompiler = new DecompInterface();
            try {
                if (!decompiler.openProgram(currentProgram)) {
                    return errorResult("Decompilation failed: openProgram failed: " + decompiler.getLastMessage());
                }
                TaskMonitor mon = TaskMonitor.DUMMY;
                DecompileResults results = decompiler.decompileFunction(func, 30, mon);
                if (!results.decompileCompleted()) {
                    return errorResult("Decompilation failed for " + funcTarget + ": " + decompileFailureReason(results));
                }

                ghidra.program.model.pcode.HighFunction highFunc = results.getHighFunction();
                if (highFunc == null)
                    return errorResult("Could not get high-level function representation");

                ghidra.program.model.pcode.LocalSymbolMap lsm = highFunc.getLocalSymbolMap();
                ghidra.program.model.pcode.HighSymbol targetSym = null;
                Iterator<ghidra.program.model.pcode.HighSymbol> symIter = lsm.getSymbols();
                while (symIter.hasNext()) {
                    ghidra.program.model.pcode.HighSymbol sym = symIter.next();
                    if (sym.getName().equals(varName)) {
                        targetSym = sym;
                        break;
                    }
                }

                if (targetSym == null)
                    return errorResult("Variable not found: " + varName + " in function " + func.getName());

                int txId = currentProgram.startTransaction("Set variable type");
                try {
                    HighFunctionDBUtil.updateDBVariable(targetSym, targetSym.getName(), newType, SourceType.USER_DEFINED);
                    currentProgram.endTransaction(txId, true);
                } catch (Exception e) {
                    currentProgram.endTransaction(txId, false);
                    throw e;
                }

                JsonObject result = new JsonObject();
                result.addProperty("status", "updated");
                result.addProperty("function", func.getName());
                result.addProperty("variable", varName);
                result.addProperty("new_type", newType.getName());
                result.addProperty("address", func.getEntryPoint().toString());
                return result;
            } finally {
                decompiler.dispose();
            }
        } catch (Exception e) {
            return errorResult("Failed to set variable type: " + e.getMessage());
        }
    }

    // --- PCode Handlers ---

    private JsonObject handlePcodeAt(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");

        String addrStr = getArgString(args, "address");
        if (addrStr == null || addrStr.isEmpty()) return errorResult("address required");

        try {
            Address addr = resolveAddress(addrStr);
            if (addr == null) {
                return errorResult("Invalid address: " + addrStr);
            }

            Listing listing = currentProgram.getListing();
            Instruction inst = listing.getInstructionAt(addr);
            if (inst == null) {
                return errorResult("No instruction at address: " + addrStr);
            }

            PcodeOp[] pcodeOps = inst.getPcode();
            JsonArray ops = new JsonArray();
            for (PcodeOp op : pcodeOps) {
                ops.add(pcodeOpToJson(op));
            }

            JsonObject result = new JsonObject();
            result.addProperty("address", addr.toString());
            result.addProperty("mnemonic", inst.getMnemonicString());
            result.addProperty("instruction", inst.toString());
            result.addProperty("count", ops.size());
            result.add("pcode", ops);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to get PCode: " + e.getMessage());
        }
    }

    private JsonObject handlePcodeFunction(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");

        String target = getArgString(args, "function");
        boolean highPcode = args.has("high") && args.get("high").getAsBoolean();
        if (target == null || target.isEmpty()) return errorResult("function name or address required");

        try {
            Function func = findFunctionByNameOrAddress(target);
            if (func == null) {
                return errorResult(buildFunctionTargetHint(target));
            }

            if (highPcode) {
                DecompInterface decomp = new DecompInterface();
                try {
                    if (!decomp.openProgram(currentProgram)) {
                        return errorResult("Decompilation failed: openProgram failed: " + decomp.getLastMessage());
                    }
                    DecompileResults results = decomp.decompileFunction(func, 30, TaskMonitor.DUMMY);
                    if (!results.decompileCompleted()) {
                        return errorResult("Decompilation failed for " + func.getName() + ": " + decompileFailureReason(results));
                    }

                    HighFunction hf = results.getHighFunction();
                    Iterator<PcodeOpAST> it = hf.getPcodeOps();
                    JsonArray ops = new JsonArray();
                    while (it.hasNext()) {
                        PcodeOpAST op = it.next();
                        ops.add(pcodeOpToJson(op));
                    }

                    JsonObject result = new JsonObject();
                    result.addProperty("function", func.getName());
                    result.addProperty("address", func.getEntryPoint().toString());
                    result.addProperty("level", "high");
                    result.addProperty("count", ops.size());
                    result.add("pcode", ops);
                    return result;
                } finally {
                    decomp.dispose();
                }
            } else {
                Listing listing = currentProgram.getListing();
                ghidra.program.model.address.AddressSetView body = func.getBody();
                InstructionIterator instIter = listing.getInstructions(body, true);

                JsonArray ops = new JsonArray();
                while (instIter.hasNext()) {
                    Instruction inst = instIter.next();
                    PcodeOp[] pcodeOps = inst.getPcode();
                    for (PcodeOp op : pcodeOps) {
                        JsonObject opJson = pcodeOpToJson(op);
                        opJson.addProperty("instruction_address", inst.getAddress().toString());
                        ops.add(opJson);
                    }
                }

                JsonObject result = new JsonObject();
                result.addProperty("function", func.getName());
                result.addProperty("address", func.getEntryPoint().toString());
                result.addProperty("level", "raw");
                result.addProperty("count", ops.size());
                result.add("pcode", ops);
                return result;
            }
        } catch (Exception e) {
            return errorResult("Failed to get function PCode: " + e.getMessage());
        }
    }

    private JsonObject pcodeOpToJson(PcodeOp op) {
        JsonObject obj = new JsonObject();
        obj.addProperty("mnemonic", op.getMnemonic());
        obj.addProperty("opcode", op.getOpcode());

        Varnode output = op.getOutput();
        if (output != null) {
            obj.add("output", varnodeToJson(output));
        } else {
            obj.add("output", JsonNull.INSTANCE);
        }

        JsonArray inputs = new JsonArray();
        for (int i = 0; i < op.getNumInputs(); i++) {
            Varnode input = op.getInput(i);
            inputs.add(varnodeToJson(input));
        }
        obj.add("inputs", inputs);

        return obj;
    }

    private JsonObject varnodeToJson(Varnode vn) {
        JsonObject obj = new JsonObject();
        obj.addProperty("space", vn.getAddress().getAddressSpace().getName());
        obj.addProperty("offset", "0x" + Long.toHexString(vn.getOffset()));
        obj.addProperty("size", vn.getSize());
        if (vn.isConstant()) {
            obj.addProperty("type", "constant");
        } else if (vn.isRegister()) {
            obj.addProperty("type", "register");
            Register reg = currentProgram.getRegister(vn);
            if (reg != null) {
                obj.addProperty("register", reg.getName());
            }
        } else if (vn.isUnique()) {
            obj.addProperty("type", "unique");
        } else if (vn.getAddress().isStackAddress()) {
            obj.addProperty("type", "stack");
        } else {
            obj.addProperty("type", "ram");
        }
        return obj;
    }

    // --- Analysis Handlers ---

    private JsonObject handleAnalyzerList(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");

        try {
            ghidra.framework.options.Options analysisOptions =
                currentProgram.getOptions("Analyzers");

            List<String> optionNames = analysisOptions.getOptionNames();
            JsonArray analyzerList = new JsonArray();

            for (String optName : optionNames) {
                if (!optName.contains(".")) {
                    try {
                        boolean enabled = analysisOptions.getBoolean(optName, false);
                        JsonObject entry = new JsonObject();
                        entry.addProperty("name", optName);
                        entry.addProperty("enabled", enabled);
                        String desc = analysisOptions.getDescription(optName);
                        if (desc != null && !desc.isEmpty()) {
                            entry.addProperty("description", desc);
                        }
                        analyzerList.add(entry);
                    } catch (Exception e) {
                        // Skip non-boolean options
                    }
                }
            }

            JsonObject result = new JsonObject();
            result.addProperty("count", analyzerList.size());
            result.add("analyzers", analyzerList);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to list analyzers: " + e.getMessage());
        }
    }

    private JsonObject handleAnalyzerSet(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");

        String name = getArgString(args, "name");
        if (name == null || name.isEmpty()) return errorResult("analyzer name required");
        if (!args.has("enabled")) return errorResult("enabled (true/false) required");
        boolean enabled = args.get("enabled").getAsBoolean();

        try {
            ghidra.framework.options.Options analysisOptions =
                currentProgram.getOptions("Analyzers");

            List<String> optionNames = analysisOptions.getOptionNames();
            boolean found = false;
            for (String optName : optionNames) {
                if (optName.equals(name)) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                return errorResult("Unknown analyzer: " + name);
            }

            int txId = currentProgram.startTransaction("Set analyzer");
            try {
                analysisOptions.setBoolean(name, enabled);
                currentProgram.endTransaction(txId, true);

                JsonObject result = new JsonObject();
                result.addProperty("status", "set");
                result.addProperty("name", name);
                result.addProperty("enabled", enabled);
                return result;
            } catch (Exception e) {
                currentProgram.endTransaction(txId, false);
                throw e;
            }
        } catch (Exception e) {
            return errorResult("Failed to set analyzer: " + e.getMessage());
        }
    }

    private JsonObject handleAnalyzeRun(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");

        try {
            ghidra.program.model.address.AddressSetView fullAddressSet = currentProgram.getMemory();

            int txId = currentProgram.startTransaction("Re-analyze");
            try {
                ghidra.app.plugin.core.analysis.AutoAnalysisManager mgr =
                    ghidra.app.plugin.core.analysis.AutoAnalysisManager.getAnalysisManager(currentProgram);
                mgr.reAnalyzeAll(null);
                mgr.startAnalysis(new ConsoleTaskMonitor());
                currentProgram.endTransaction(txId, true);

                JsonObject result = new JsonObject();
                result.addProperty("status", "analysis_complete");
                result.addProperty("program", currentProgram.getName());
                return result;
            } catch (Exception e) {
                currentProgram.endTransaction(txId, false);
                throw e;
            }
        } catch (Exception e) {
            return errorResult("Failed to run analysis: " + e.getMessage());
        }
    }

    // --- Bookmark Handlers ---

    private JsonObject handleBookmarkList(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");

        String typeFilter = getArgString(args, "type");
        int limit = getArgInt(args, "limit", 0);

        BookmarkManager bm = currentProgram.getBookmarkManager();
        JsonArray bookmarks = new JsonArray();

        BookmarkType[] types = bm.getBookmarkTypes();
        int count = 0;
        for (BookmarkType typeObj : types) {
            String type = typeObj.getTypeString();
            if (typeFilter != null && !typeFilter.isEmpty() && !type.equalsIgnoreCase(typeFilter)) {
                continue;
            }
            Iterator<Bookmark> iter = bm.getBookmarksIterator(type);
            while (iter.hasNext()) {
                if (limit > 0 && count >= limit) break;
                Bookmark bookmark = iter.next();
                JsonObject bobj = new JsonObject();
                bobj.addProperty("address", bookmark.getAddress().toString());
                bobj.addProperty("type", bookmark.getTypeString());
                bobj.addProperty("category", bookmark.getCategory());
                bobj.addProperty("comment", bookmark.getComment());
                bookmarks.add(bobj);
                count++;
            }
            if (limit > 0 && count >= limit) break;
        }

        JsonObject result = new JsonObject();
        result.addProperty("count", bookmarks.size());
        result.add("bookmarks", bookmarks);
        return result;
    }

    private JsonObject handleBookmarkAdd(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");

        String addrStr = getArgString(args, "address");
        String type = getArgString(args, "type");
        String category = getArgString(args, "category");
        String comment = getArgString(args, "comment");
        if (addrStr == null || addrStr.isEmpty()) return errorResult("address required");

        if (type == null || type.isEmpty()) type = "Note";
        if (category == null) category = "";
        if (comment == null) comment = "";

        try {
            Address addr = resolveAddress(addrStr);
            if (addr == null) {
                return errorResult("Invalid address: " + addrStr);
            }

            BookmarkManager bm = currentProgram.getBookmarkManager();
            int txId = currentProgram.startTransaction("Add bookmark");
            try {
                Bookmark bookmark = bm.setBookmark(addr, type, category, comment);
                currentProgram.endTransaction(txId, true);

                JsonObject result = new JsonObject();
                result.addProperty("status", "added");
                result.addProperty("address", addr.toString());
                result.addProperty("type", bookmark.getTypeString());
                result.addProperty("category", bookmark.getCategory());
                result.addProperty("comment", bookmark.getComment());
                return result;
            } catch (Exception e) {
                currentProgram.endTransaction(txId, false);
                throw e;
            }
        } catch (Exception e) {
            return errorResult("Failed to add bookmark: " + e.getMessage());
        }
    }

    private JsonObject handleBookmarkDelete(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");

        String addrStr = getArgString(args, "address");
        String type = getArgString(args, "type");
        if (addrStr == null || addrStr.isEmpty()) return errorResult("address required");

        try {
            Address addr = resolveAddress(addrStr);
            if (addr == null) {
                return errorResult("Invalid address: " + addrStr);
            }

            BookmarkManager bm = currentProgram.getBookmarkManager();

            Bookmark[] bookmarksAtAddr = bm.getBookmarks(addr);
            if (bookmarksAtAddr.length == 0) {
                return errorResult("No bookmarks at address: " + addrStr);
            }

            int txId = currentProgram.startTransaction("Delete bookmark");
            try {
                int deleted = 0;
                for (Bookmark bookmark : bookmarksAtAddr) {
                    if (type == null || type.isEmpty() || bookmark.getTypeString().equalsIgnoreCase(type)) {
                        bm.removeBookmark(bookmark);
                        deleted++;
                    }
                }
                currentProgram.endTransaction(txId, true);

                JsonObject result = new JsonObject();
                result.addProperty("status", "deleted");
                result.addProperty("address", addr.toString());
                result.addProperty("deleted_count", deleted);
                return result;
            } catch (Exception e) {
                currentProgram.endTransaction(txId, false);
                throw e;
            }
        } catch (Exception e) {
            return errorResult("Failed to delete bookmark: " + e.getMessage());
        }
    }

    // --- Comment Handlers ---

    private CommentType resolveCommentType(String typeStr) {
        if (typeStr == null) return CommentType.EOL;
        switch (typeStr.toUpperCase()) {
            case "PRE":   return CommentType.PRE;
            case "POST":  return CommentType.POST;
            case "PLATE": return CommentType.PLATE;
            default:      return CommentType.EOL;
        }
    }


    private JsonObject handleCommentList(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");

        int limit = getArgInt(args, "limit", 0);
        String nameFilter = getArgString(args, "filter");

        Listing listing = currentProgram.getListing();
        Memory memory = currentProgram.getMemory();
        JsonArray comments = new JsonArray();
        int count = 0;

        CommentType[] commentTypes = {CommentType.EOL, CommentType.PRE, CommentType.POST, CommentType.PLATE};
        String[] commentNames = {"EOL", "PRE", "POST", "PLATE"};

        // getCommentAddressIterator returns ALL addresses with any comment, including
        // both auto-generated (LSDA, DWARF) and user-set.  It covers both the
        // commentAdapter path (data/undefined) and CodeUnit-backed instruction addresses.
        // Note: listing.getComment(type, addr) does NOT reliably retrieve CodeUnit
        // comments (it uses addrMap.getKey(addr, false) which may miss instruction
        // addresses); always use getCodeUnitAt(addr).getComment() for those.
        ghidra.program.model.address.AddressIterator addrIter =
            listing.getCommentAddressIterator(memory, true);
        while (addrIter.hasNext()) {
            if (limit > 0 && count >= limit) break;
            Address addr = addrIter.next();
            CodeUnit cu = listing.getCodeUnitAt(addr);
            for (int i = 0; i < commentNames.length; i++) {
                if (limit > 0 && count >= limit) break;
                String text = (cu != null)
                    ? cu.getComment(commentTypes[i])
                    : listing.getComment(commentTypes[i], addr);
                if (text != null) {
                    if (nameFilter != null && !text.toLowerCase().contains(nameFilter.toLowerCase())) continue;
                    JsonObject obj = new JsonObject();
                    obj.addProperty("address", addr.toString());
                    obj.addProperty("type", commentNames[i]);
                    obj.addProperty("text", text);
                    comments.add(obj);
                    count++;
                }
            }
        }

        JsonObject result = new JsonObject();
        result.add("comments", comments);
        result.addProperty("count", comments.size());
        return result;
    }

    private JsonObject handleCommentGet(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");

        String addressStr = getArgString(args, "address");
        if (addressStr == null) return errorResult("Address required");

        try {
            Address addr = currentProgram.getAddressFactory().getAddress(addressStr);
            if (addr == null) return errorResult("Invalid address: " + addressStr);

            Listing listing = currentProgram.getListing();
            CodeUnit cu = listing.getCodeUnitAt(addr);
            if (cu == null) return errorResult("No code unit at address: " + addressStr);

            CommentType[] types = {CommentType.EOL, CommentType.PRE, CommentType.POST, CommentType.PLATE};
            String[] names = {"EOL", "PRE", "POST", "PLATE"};

            JsonArray comments = new JsonArray();
            for (int i = 0; i < types.length; i++) {
                String text = cu.getComment(types[i]);
                if (text != null) {
                    JsonObject commentObj = new JsonObject();
                    commentObj.addProperty("type", names[i]);
                    commentObj.addProperty("text", text);
                    comments.add(commentObj);
                }
            }

            JsonObject result = new JsonObject();
            result.addProperty("address", addressStr);
            result.add("comments", comments);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to get comments: " + e.getMessage());
        }
    }

    private JsonObject handleCommentSet(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");

        String addressStr = getArgString(args, "address");
        String text = getArgString(args, "text");
        String commentTypeStr = getArgString(args, "comment_type");
        if (commentTypeStr == null) commentTypeStr = "EOL";

        if (addressStr == null) return errorResult("Address required");

        try {
            Address addr = currentProgram.getAddressFactory().getAddress(addressStr);
            if (addr == null) return errorResult("Invalid address: " + addressStr);

            Set<String> validTypes = new HashSet<>(Arrays.asList("EOL", "PRE", "POST", "PLATE"));
            if (!validTypes.contains(commentTypeStr.toUpperCase())) {
                return errorResult("Invalid comment type: " + commentTypeStr + ". Must be one of: EOL, PRE, POST, PLATE");
            }

            CommentType commentType = resolveCommentType(commentTypeStr);
            Listing listing = currentProgram.getListing();

            int txId = currentProgram.startTransaction("Set comment");
            try {
                listing.setComment(addr, commentType, text);
                currentProgram.endTransaction(txId, true);
            } catch (Exception e) {
                currentProgram.endTransaction(txId, false);
                throw e;
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "set");
            result.addProperty("address", addressStr);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to set comment: " + e.getMessage());
        }
    }

    private JsonObject handleCommentDelete(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");

        String addressStr = getArgString(args, "address");
        if (addressStr == null) return errorResult("Address required");

        try {
            Address addr = currentProgram.getAddressFactory().getAddress(addressStr);
            if (addr == null) return errorResult("Invalid address: " + addressStr);

            Listing listing = currentProgram.getListing();

            int txId = currentProgram.startTransaction("Delete comments");
            try {
                listing.setComment(addr, CommentType.EOL, null);
                listing.setComment(addr, CommentType.PRE, null);
                listing.setComment(addr, CommentType.POST, null);
                listing.setComment(addr, CommentType.PLATE, null);
                currentProgram.endTransaction(txId, true);
            } catch (Exception e) {
                currentProgram.endTransaction(txId, false);
                throw e;
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "deleted");
            result.addProperty("address", addressStr);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to delete comment: " + e.getMessage());
        }
    }

    // --- Graph Handlers ---

    private JsonObject handleGraphCalls(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");

        int limit = getArgInt(args, "limit", 0);

        FunctionManager fm = currentProgram.getFunctionManager();
        ReferenceManager refMgr = currentProgram.getReferenceManager();
        JsonArray nodes = new JsonArray();
        JsonArray edges = new JsonArray();
        int count = 0;

        FunctionIterator iter = fm.getFunctions(true);
        while (iter.hasNext()) {
            if (limit > 0 && count >= limit) break;
            Function func = iter.next();
            String funcAddr = func.getEntryPoint().toString();

            JsonObject node = new JsonObject();
            node.addProperty("id", funcAddr);
            node.addProperty("name", func.getName());
            node.addProperty("address", funcAddr);
            nodes.add(node);

            Reference[] refs = refMgr.getReferencesFrom(func.getEntryPoint());
            for (Reference ref : refs) {
                if (ref.getReferenceType().isCall()) {
                    Address targetAddr = ref.getToAddress();
                    Function targetFunc = fm.getFunctionAt(targetAddr);
                    if (targetFunc != null) {
                        JsonObject edge = new JsonObject();
                        edge.addProperty("from", funcAddr);
                        edge.addProperty("to", targetAddr.toString());
                        edge.addProperty("type", "call");
                        edges.add(edge);
                    }
                }
            }
            count++;
        }

        JsonObject result = new JsonObject();
        result.add("nodes", nodes);
        result.add("edges", edges);
        result.addProperty("node_count", nodes.size());
        result.addProperty("edge_count", edges.size());
        return result;
    }

    private Function findFunctionByNameOrAddress(String nameOrAddr) {
        if (currentProgram == null || nameOrAddr == null || nameOrAddr.isEmpty()) {
            return null;
        }

        FunctionManager fm = currentProgram.getFunctionManager();

        // Resolve addresses, symbols, and auto names like FUN_00401234.
        Address addr = resolveAddress(nameOrAddr);
        if (addr != null) {
            Function f = fm.getFunctionContaining(addr);
            if (f != null) {
                return f;
            }
        }

        // Try as name
        FunctionIterator iter = fm.getFunctions(true);
        while (iter.hasNext()) {
            Function func = iter.next();
            if (func.getName().equals(nameOrAddr)) return func;
        }
        return null;
    }

    private JsonObject handleGraphCallers(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");

        String funcName = getArgString(args, "function");
        if (funcName == null) return errorResult("Function name required");
        int depth = getArgInt(args, "depth", 1);

        Function targetFunc = findFunctionByNameOrAddress(funcName);
        if (targetFunc == null) return errorResult(buildFunctionTargetHint(funcName));

        ReferenceManager refMgr = currentProgram.getReferenceManager();
        FunctionManager fm = currentProgram.getFunctionManager();
        JsonArray callers = new JsonArray();
        Set<String> visited = new HashSet<>();

        findCallersRecursive(targetFunc, 0, depth, callers, visited, refMgr, fm);

        JsonObject result = new JsonObject();
        result.addProperty("function", funcName);
        result.add("callers", callers);
        result.addProperty("count", callers.size());
        return result;
    }

     private void findCallersRecursive(Function func, int currentDepth, int maxDepth,
             JsonArray callers, Set<String> visited, ReferenceManager refMgr, FunctionManager fm) {
         if (maxDepth > 0 && currentDepth >= maxDepth) return;
         String funcAddrStr = func.getEntryPoint().toString();
         if (visited.contains(funcAddrStr)) return;
         visited.add(funcAddrStr);
 
         for (Reference ref : refMgr.getReferencesTo(func.getEntryPoint())) {
             ghidra.program.model.symbol.RefType rt = ref.getReferenceType();
             if (rt.isCall() || rt == ghidra.program.model.symbol.RefType.PARAM
                     || rt == ghidra.program.model.symbol.RefType.INDIRECTION) {
                 Address fromAddr = ref.getFromAddress();
                 Function callerFunc = fm.getFunctionContaining(fromAddr);
                 if (callerFunc != null) {
                     JsonObject callerInfo = new JsonObject();
                     callerInfo.addProperty("name", callerFunc.getName());
                     callerInfo.addProperty("address", callerFunc.getEntryPoint().toString());
                     callerInfo.addProperty("call_site", fromAddr.toString());
                     callerInfo.addProperty("depth", currentDepth);
                     callers.add(callerInfo);
 
                     if (maxDepth == 0 || currentDepth + 1 < maxDepth) {
                         findCallersRecursive(callerFunc, currentDepth + 1, maxDepth, callers, visited, refMgr, fm);
                     }
                 }
             }
         }
     }

    private JsonObject handleGraphCallees(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");

        String funcName = getArgString(args, "function");
        if (funcName == null) return errorResult("Function name required");
        int depth = getArgInt(args, "depth", 1);

        Function targetFunc = findFunctionByNameOrAddress(funcName);
        if (targetFunc == null) return errorResult(buildFunctionTargetHint(funcName));

        ReferenceManager refMgr = currentProgram.getReferenceManager();
        FunctionManager fm = currentProgram.getFunctionManager();
        JsonArray callees = new JsonArray();
        Set<String> visited = new HashSet<>();

        findCalleesRecursive(targetFunc, 0, depth, callees, visited, refMgr, fm);

        JsonObject result = new JsonObject();
        result.addProperty("function", funcName);
        result.add("callees", callees);
        result.addProperty("count", callees.size());
        return result;
    }

     private void findCalleesRecursive(Function func, int currentDepth, int maxDepth,
             JsonArray callees, Set<String> visited, ReferenceManager refMgr, FunctionManager fm) {
         if (maxDepth > 0 && currentDepth >= maxDepth) return;
         String funcAddrStr = func.getEntryPoint().toString();
         if (visited.contains(funcAddrStr)) return;
         visited.add(funcAddrStr);
 
         // Iterate every address in the function body to find outgoing calls
         for (Address addr : func.getBody().getAddresses(true)) {
             for (Reference ref : refMgr.getReferencesFrom(addr)) {
                 if (ref.getReferenceType().isCall()) {
                     Address toAddr = ref.getToAddress();
                     Function calleeFunc = fm.getFunctionAt(toAddr);
                     if (calleeFunc != null) {
                         JsonObject calleeInfo = new JsonObject();
                         calleeInfo.addProperty("name", calleeFunc.getName());
                         calleeInfo.addProperty("address", calleeFunc.getEntryPoint().toString());
                         calleeInfo.addProperty("call_site", addr.toString());
                         calleeInfo.addProperty("depth", currentDepth);
                         callees.add(calleeInfo);
 
                         if (maxDepth == 0 || currentDepth + 1 < maxDepth) {
                             findCalleesRecursive(calleeFunc, currentDepth + 1, maxDepth, callees, visited, refMgr, fm);
                         }
                     }
                 }
             }
         }
     }

    private JsonObject handleGraphExport(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");

        String format = getArgString(args, "format");
        if (format == null) format = "json";

        // Build graph first
        JsonObject graphData = handleGraphCalls(new JsonObject());
        if (graphData.has("error")) return graphData;

        if ("json".equals(format)) {
            return graphData;
        } else if ("dot".equals(format)) {
            StringBuilder sb = new StringBuilder();
            sb.append("digraph CallGraph {\n");
            sb.append("  rankdir=LR;\n");
            sb.append("  node [shape=box];\n");

            JsonArray nodes = graphData.getAsJsonArray("nodes");
            for (int i = 0; i < nodes.size(); i++) {
                JsonObject node = nodes.get(i).getAsJsonObject();
                String nodeId = node.get("id").getAsString().replace(":", "_");
                String label = node.get("name").getAsString();
                sb.append("  \"").append(nodeId).append("\" [label=\"").append(label).append("\"];\n");
            }

            JsonArray edges = graphData.getAsJsonArray("edges");
            for (int i = 0; i < edges.size(); i++) {
                JsonObject edge = edges.get(i).getAsJsonObject();
                String fromId = edge.get("from").getAsString().replace(":", "_");
                String toId = edge.get("to").getAsString().replace(":", "_");
                sb.append("  \"").append(fromId).append("\" -> \"").append(toId).append("\";\n");
            }

            sb.append("}");

            JsonObject result = new JsonObject();
            result.addProperty("format", "dot");
            result.addProperty("output", sb.toString());
            return result;
        } else {
            return errorResult("Unsupported format: " + format);
        }
    }

    // --- Diff Handlers ---

    private JsonObject handleDiffPrograms(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");

        String prog1 = getArgString(args, "program1");
        String prog2 = getArgString(args, "program2");
        if (prog1 == null) prog1 = "";
        if (prog2 == null) prog2 = "";

        try {
            FunctionManager fm = currentProgram.getFunctionManager();
            Memory memory = currentProgram.getMemory();
            SymbolTable symbolTable = currentProgram.getSymbolTable();

            JsonObject prog1Stats = new JsonObject();
            prog1Stats.addProperty("name", prog1);
            prog1Stats.addProperty("function_count", fm.getFunctionCount());
            prog1Stats.addProperty("memory_size", memory.getSize());
            prog1Stats.addProperty("symbol_count", symbolTable.getNumSymbols());

            JsonArray memBlocks = new JsonArray();
            for (MemoryBlock block : memory.getBlocks()) {
                JsonObject blockObj = new JsonObject();
                blockObj.addProperty("name", block.getName());
                blockObj.addProperty("start", block.getStart().toString());
                blockObj.addProperty("end", block.getEnd().toString());
                blockObj.addProperty("size", block.getSize());
                memBlocks.add(blockObj);
            }
            prog1Stats.add("memory_blocks", memBlocks);

            JsonObject prog2Stats = new JsonObject();
            prog2Stats.addProperty("name", prog2);
            prog2Stats.addProperty("note", "Comparison requires loading second program");

            JsonObject result = new JsonObject();
            result.add("program1", prog1Stats);
            result.add("program2", prog2Stats);
            result.addProperty("status", "partial");
            result.addProperty("message", "Single program stats returned (multi-program comparison not implemented)");
            return result;
        } catch (Exception e) {
            return errorResult("Failed to diff programs: " + e.getMessage());
        }
    }

    private JsonObject handleDiffFunctions(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");

        String func1Target = getArgString(args, "func1");
        String func2Target = getArgString(args, "func2");
        if (func1Target == null || func2Target == null) {
            return errorResult("func1 and func2 required");
        }

        try {
            Function func1 = findFunctionByNameOrAddress(func1Target);
            Function func2 = findFunctionByNameOrAddress(func2Target);

            if (func1 == null) return errorResult(buildFunctionTargetHint(func1Target));
            if (func2 == null) return errorResult(buildFunctionTargetHint(func2Target));

            DecompInterface decompiler = new DecompInterface();
            try {
                if (!decompiler.openProgram(currentProgram)) {
                    return errorResult("Decompilation failed: openProgram failed: " + decompiler.getLastMessage());
                }
                TaskMonitor mon = TaskMonitor.DUMMY;

                DecompileResults res1 = decompiler.decompileFunction(func1, 30, mon);
                DecompileResults res2 = decompiler.decompileFunction(func2, 30, mon);

                if (!res1.decompileCompleted()) {
                    return errorResult("Failed to decompile " + func1Target + ": " + decompileFailureReason(res1));
                }
                if (!res2.decompileCompleted()) {
                    return errorResult("Failed to decompile " + func2Target + ": " + decompileFailureReason(res2));
                }

                String code1 = res1.getDecompiledFunction().getC();
                String code2 = res2.getDecompiledFunction().getC();

                String[] lines1 = code1.split("\n");
                String[] lines2 = code2.split("\n");

                JsonArray diffLines = new JsonArray();
                int maxLines = Math.max(lines1.length, lines2.length);
                for (int i = 0; i < maxLines; i++) {
                    String l1 = i < lines1.length ? lines1[i] : "";
                    String l2 = i < lines2.length ? lines2[i] : "";
                    if (!l1.equals(l2)) {
                        JsonObject diff = new JsonObject();
                        diff.addProperty("line", i + 1);
                        diff.addProperty("func1", l1);
                        diff.addProperty("func2", l2);
                        diff.addProperty("status", "changed");
                        diffLines.add(diff);
                    }
                }

                JsonObject f1Info = new JsonObject();
                f1Info.addProperty("name", func1.getName());
                f1Info.addProperty("lines", lines1.length);
                f1Info.addProperty("code", code1);

                JsonObject f2Info = new JsonObject();
                f2Info.addProperty("name", func2.getName());
                f2Info.addProperty("lines", lines2.length);
                f2Info.addProperty("code", code2);

                JsonObject result = new JsonObject();
                result.add("func1", f1Info);
                result.add("func2", f2Info);
                result.add("differences", diffLines);
                result.addProperty("diff_count", diffLines.size());
                return result;
            } finally {
                decompiler.dispose();
            }
        } catch (Exception e) {
            return errorResult("Failed to diff functions: " + e.getMessage());
        }
    }

    // --- Patch Handlers ---

     private JsonObject handlePatchBytes(JsonObject args) {
         if (currentProgram == null) return errorResult("No program loaded");
 
         String addressStr = getArgString(args, "address");
         String hexData = getArgString(args, "hex");
         if (addressStr == null || hexData == null) {
             return errorResult("Address and hex data required");
         }
 
         try {
             Address addr = currentProgram.getAddressFactory().getAddress(addressStr);
             if (addr == null) return errorResult("Invalid address: " + addressStr);
 
             String hexClean = hexData.replace("0x", "").replace(" ", "");
             byte[] patchData = new byte[hexClean.length() / 2];
             for (int i = 0; i < patchData.length; i++) {
                 patchData[i] = (byte) Integer.parseInt(hexClean.substring(i * 2, i * 2 + 2), 16);
             }
 
             Memory memory = currentProgram.getMemory();
             Listing listing = currentProgram.getListing();
             MemoryBlock block = memory.getBlock(addr);
             boolean wasWritable = block != null && block.isWrite();

             int txId = currentProgram.startTransaction("Patch bytes");
             try {
                 if (block != null && !wasWritable) block.setWrite(true);
                 // Clear any existing code units so the write doesn't conflict
                 listing.clearCodeUnits(addr, addr.add(patchData.length - 1), false);
                 memory.setBytes(addr, patchData);
                 if (block != null && !wasWritable) block.setWrite(false);
                 currentProgram.endTransaction(txId, true);
             } catch (Exception e) {
                 currentProgram.endTransaction(txId, false);
                 throw e;
             }
 
             JsonObject result = new JsonObject();
             result.addProperty("status", "patched");
             result.addProperty("address", addr.toString());
             result.addProperty("bytes", patchData.length);
             return result;
         } catch (Exception e) {
             return errorResult("Failed to patch bytes: " + e.getMessage());
         }
     }

    private JsonObject handlePatchNop(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");

        String addressStr = getArgString(args, "address");
        if (addressStr == null) return errorResult("Address required");

        int count = 1;
        if (args.has("count") && !args.get("count").isJsonNull()) {
            count = args.get("count").getAsInt();
            if (count < 1) return errorResult("Count must be >= 1");
        }

        try {
            Address addr = currentProgram.getAddressFactory().getAddress(addressStr);
            if (addr == null) return errorResult("Invalid address: " + addressStr);

            String processor = currentProgram.getLanguage().getProcessor().toString();
            byte nopByte;
            if (processor.toLowerCase().contains("x86")) {
                nopByte = (byte) 0x90;
            } else {
                nopByte = (byte) 0x00;
            }

            Listing listing = currentProgram.getListing();
            Memory memory = currentProgram.getMemory();
            MemoryBlock block = memory.getBlock(addr);
            boolean wasWritable = block != null && block.isWrite();
            int totalBytes = 0;
            int noppedCount = 0;
            Address currentAddr = addr;

            int txId = currentProgram.startTransaction("NOP " + count + " instruction(s)");
            try {
                if (block != null && !wasWritable) block.setWrite(true);
                for (int i = 0; i < count; i++) {
                    Instruction instruction = listing.getInstructionAt(currentAddr);
                    if (instruction == null) {
                        if (i == 0) {
                            if (block != null && !wasWritable) block.setWrite(false);
                            currentProgram.endTransaction(txId, false);
                            return errorResult("No instruction at address: " + currentAddr.toString());
                        }
                        break; // Stop at end of instructions
                    }

                    int instrLength = instruction.getLength();
                    byte[] nopBytes = new byte[instrLength];
                    Arrays.fill(nopBytes, nopByte);
                    // Clear existing code unit before overwriting bytes
                    listing.clearCodeUnits(currentAddr, currentAddr.add(instrLength - 1), false);
                    memory.setBytes(currentAddr, nopBytes);
                    totalBytes += instrLength;
                    noppedCount++;
                    currentAddr = currentAddr.add(instrLength);
                }
                if (block != null && !wasWritable) block.setWrite(false);
                currentProgram.endTransaction(txId, true);
            } catch (Exception e) {
                currentProgram.endTransaction(txId, false);
                throw e;
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "nopped");
            result.addProperty("address", addr.toString());
            result.addProperty("count", noppedCount);
            result.addProperty("bytes", totalBytes);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to NOP instruction(s): " + e.getMessage());
        }
    }

    private JsonObject handlePatchExport(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");

        String outputPath = getArgString(args, "output");
        if (outputPath == null || outputPath.isEmpty()) {
            return errorResult("Output path required");
        }

        try {
            // Use reflection to access BinaryExporter which may not always be available
            Class<?> exporterClass = Class.forName("ghidra.app.util.exporter.BinaryExporter");
            Object exporter = exporterClass.getDeclaredConstructor().newInstance();

            java.lang.reflect.Method exportMethod = exporterClass.getMethod("export",
                File.class, ghidra.program.model.listing.Program.class,
                ghidra.program.model.address.AddressSetView.class, TaskMonitor.class);

            File outputFile = new File(outputPath);
            TaskMonitor mon = new ConsoleTaskMonitor();
            exportMethod.invoke(exporter, outputFile, currentProgram, null, mon);

            JsonObject result = new JsonObject();
            result.addProperty("status", "exported");
            result.addProperty("output", outputPath);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to export binary: " + e.getMessage());
        }
    }

    private void addStringPreview(JsonObject reference, Address target) {
        if (target == null) return;
        Data defined = currentProgram.getListing().getDataContaining(target);
        if (defined != null && defined.hasStringValue() && defined.getValue() != null) {
            String value = defined.getValue().toString();
            int end = Math.min(value.length(), 256);
            // Do not cut between a UTF-16 surrogate pair.
            if (end > 0 && end < value.length() && Character.isHighSurrogate(value.charAt(end - 1))) end--;
            JsonObject preview = new JsonObject(); preview.addProperty("value", value.substring(0, end));
            preview.addProperty("address", defined.getAddress().toString()); preview.addProperty("source", "defined");
            preview.addProperty("encoding", StringDataInstance.getStringDataInstance(defined).getCharsetName()); preview.add("terminated", JsonNull.INSTANCE);
            preview.addProperty("truncated", end < value.length()); preview.addProperty("interior_offset", target.subtract(defined.getAddress()));
            reference.add("string_preview", preview);
        } else {
            StringHit hit = previewAt(target, 256);
            if (hit != null && hit.value.codePointCount(0, hit.value.length()) >= 4) reference.add("string_preview", hit.json());
        }
    }

    // --- Disasm Handler ---

    private JsonObject handleDisasm(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");

        String addressStr = getArgString(args, "address");
        String endStr = getArgString(args, "end");
        Integer maxBytes = args != null && args.has("bytes") && !args.get("bytes").isJsonNull()
            ? args.get("bytes").getAsInt() : null;
        // Count only applies as a bound when neither --end nor --bytes is given.
        boolean hasBoundedRange = endStr != null || maxBytes != null;
        int count = getArgInt(args, "count", hasBoundedRange ? Integer.MAX_VALUE : 10);

        if (addressStr == null || addressStr.isEmpty()) {
            return errorResult("Address required");
        }

        try {
            boolean previews = flag(args, "resolve_strings"), discover = flag(args, "discover");
            if (discover && !directDiscoverySupported()) return errorResult("Decoded discovery supports x86-64 little-endian only");
            ghidra.app.util.PseudoDisassembler decoder = discover ? new ghidra.app.util.PseudoDisassembler(currentProgram) : null;
            // Use resolveAddress which handles 0x prefix and symbol lookup
            Address addr = resolveAddress(addressStr);
            if (addr == null) return errorResult("Invalid address: " + addressStr);

            Address endAddr = null;
            if (endStr != null && !endStr.isEmpty()) {
                endAddr = resolveAddress(endStr);
                if (endAddr == null) return errorResult("Invalid end address: " + endStr);
            }

            Listing listing = currentProgram.getListing();
            Instruction instruction = listing.getInstructionAt(addr);

            // If no instruction at exact address, try containing instruction (mid-instruction)
            if (instruction == null) {
                instruction = listing.getInstructionContaining(addr);
            }

            // If still null, try starting from containing function's entry point
            if (instruction == null) {
                Function func = currentProgram.getFunctionManager().getFunctionContaining(addr);
                if (func != null) {
                    instruction = listing.getInstructionAt(func.getEntryPoint());
                }
            }

            if (instruction == null && discover) instruction = decoder.disassemble(addr);
            if (instruction == null) {
                return errorResult("No instruction at address " + addressStr +
                    ". Address may be data or unanalyzed code.");
            }

            JsonArray results = new JsonArray();
            Instruction current = instruction;
            ReferenceManager refMgr = currentProgram.getReferenceManager();
            FunctionManager fm = currentProgram.getFunctionManager();
            SymbolTable symbolTable = currentProgram.getSymbolTable();
            int bytesConsumed = 0;

            for (int i = 0; i < count && current != null; i++) {
                Address instrAddr = current.getAddress();

                // Bound check: stop once we've passed the requested end address or byte budget.
                if (endAddr != null && instrAddr.compareTo(endAddr) > 0) break;

                byte[] byteArray = current.getBytes();
                StringBuilder bytesHex = new StringBuilder();
                for (byte b : byteArray) {
                    bytesHex.append(String.format("%02x", b & 0xff));
                }

                if (maxBytes != null && bytesConsumed >= maxBytes) break;

                String mnemonic = current.getMnemonicString();
                JsonArray operands = new JsonArray();
                int numOperands = current.getNumOperands();
                for (int j = 0; j < numOperands; j++) {
                    operands.add(new JsonPrimitive(current.getDefaultOperandRepresentation(j)));
                }

                // Resolve any symbol(s) this instruction references (call/jump targets,
                // data references), distinct from the raw operand text Ghidra renders.
                JsonArray references = new JsonArray();
                for (Reference ref : refMgr.getReferencesFrom(instrAddr)) {
                    Address toAddr = ref.getToAddress();
                    JsonObject refData = new JsonObject();
                    refData.addProperty("to_address", toAddr.toString());
                    refData.addProperty("ref_type", ref.getReferenceType().toString());
                    Function toFunc = fm.getFunctionAt(toAddr);
                    Symbol sym = symbolTable.getPrimarySymbol(toAddr);
                    if (toFunc != null) {
                        refData.addProperty("symbol", toFunc.getName());
                    } else if (sym != null) {
                        refData.addProperty("symbol", sym.getName());
                    } else {
                        refData.add("symbol", JsonNull.INSTANCE);
                    }
                    references.add(refData);
                }

                if (previews) {
                    Set<Address> seenTargets = new HashSet<>();
                    for (JsonElement element : references) {
                        JsonObject ref = element.getAsJsonObject();
                        Address target = resolveAddress(ref.get("to_address").getAsString());
                        if (target != null) seenTargets.add(target);
                        ref.addProperty("reference_source", "recorded");
                        addStringPreview(ref, target);
                    }
                    if (discover) for (Address target : decodedTargets(current)) {
                        if (!seenTargets.add(target)) continue;
                        JsonObject ref = new JsonObject(); ref.addProperty("to_address", target.toString());
                        ref.addProperty("ref_type", "DIRECT_OPERAND"); ref.addProperty("reference_source", "decoded");
                        Symbol symbol = symbolTable.getPrimarySymbol(target);
                        ref.addProperty("symbol", symbol == null ? null : symbol.getName());
                        addStringPreview(ref, target); references.add(ref);
                    }
                }
                JsonObject instrData = new JsonObject();
                instrData.addProperty("address", instrAddr.toString());
                instrData.addProperty("bytes", bytesHex.toString());
                instrData.addProperty("mnemonic", mnemonic);
                instrData.add("operands", operands);
                instrData.add("references", references);
                results.add(instrData);

                bytesConsumed += byteArray.length;
                if (discover) {
                    Address next = instrAddr.addNoWrap(byteArray.length);
                    MemoryBlock block = currentProgram.getMemory().getBlock(next);
                    if (block == null || !block.isExecute() || endAddr != null && next.compareTo(endAddr) > 0
                            || maxBytes != null && bytesConsumed >= maxBytes || i + 1 >= count) break;
                    current = listing.getInstructionAt(next);
                    if (current == null) {
                        try { current = decoder.disassemble(next); }
                        catch (Exception e) { break; }
                    }
                } else current = current.getNext();
            }

            JsonObject result = new JsonObject();
            result.add("instructions", results);
            result.addProperty("count", results.size());
            if (discover) for (JsonElement element : results) {
                element.getAsJsonObject().addProperty("discovery_support", "x86-64 direct operands; linear decode; no register dataflow or pointer chains");
            }
            if (results.size() > 0) {
                result.addProperty("start_address",
                    results.get(0).getAsJsonObject().get("address").getAsString());
                result.addProperty("end_address",
                    results.get(results.size() - 1).getAsJsonObject().get("address").getAsString());
            }
            return result;
        } catch (Exception e) {
            return errorResult("Failed to disassemble: " + e.getMessage());
        }
    }

    // --- Stats Handler ---

    private JsonObject handleStats() {
        if (currentProgram == null) return errorResult("No program loaded");

        try {
            FunctionManager fm = currentProgram.getFunctionManager();
            SymbolTable symbolTable = currentProgram.getSymbolTable();
            Memory memory = currentProgram.getMemory();
            DataTypeManager dtm = currentProgram.getDataTypeManager();
            Listing listing = currentProgram.getListing();

            int functionCount = fm.getFunctionCount();

            int symbolCount = 0;
            SymbolIterator symIter = symbolTable.getAllSymbols(true);
            while (symIter.hasNext()) { symIter.next(); symbolCount++; }

            int stringCount = 0;
            DataIterator dataIter = listing.getDefinedData(true);
            while (dataIter.hasNext()) {
                if (dataIter.next().hasStringValue()) stringCount++;
            }

            long memorySize = 0;
            int sectionCount = 0;
            for (MemoryBlock block : memory.getBlocks()) {
                memorySize += block.getSize();
                sectionCount++;
            }

            int importCount = 0;
            SymbolIterator extSyms = symbolTable.getExternalSymbols();
            while (extSyms.hasNext()) { extSyms.next(); importCount++; }

            int exportCount = 0;
            ghidra.program.model.address.AddressIterator epIter = symbolTable.getExternalEntryPointIterator();
            while (epIter.hasNext()) { epIter.next(); exportCount++; }

            int dataTypeCount = dtm.getDataTypeCount(false);

            int instructionCount = 0;
            InstructionIterator instrIter = listing.getInstructions(true);
            while (instrIter.hasNext()) { instrIter.next(); instructionCount++; }

            JsonObject stats = new JsonObject();
            stats.addProperty("functions", functionCount);
            stats.addProperty("symbols", symbolCount);
            stats.addProperty("strings", stringCount);
            stats.addProperty("imports", importCount);
            stats.addProperty("exports", exportCount);
            stats.addProperty("memory_size", memorySize);
            stats.addProperty("sections", sectionCount);
            stats.addProperty("data_types", dataTypeCount);
            stats.addProperty("instructions", instructionCount);
            stats.addProperty("program_name", currentProgram.getName());
            stats.addProperty("executable_format", currentProgram.getExecutableFormat());
            String compiler = currentProgram.getCompiler();
            stats.addProperty("compiler", (compiler != null && !compiler.isEmpty()) ? compiler : "Unknown");

            JsonObject result = new JsonObject();
            result.add("stats", stats);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to gather statistics: " + e.getMessage());
        }
    }

    // --- Script Handlers ---

    private JsonObject handleScriptRun(JsonObject args) {
        String path = getArgString(args, "path");
        if (path == null) return errorResult("Script path required");
        try {
            File file = new File(path);
            generic.jar.ResourceFile source = file.isFile()
                ? new generic.jar.ResourceFile(file.getCanonicalFile())
                : ghidra.app.script.GhidraScriptUtil.findScriptByName(path);
            if (source == null || !source.isFile()) return errorResult("Script not found: " + path);
            String[] scriptArgs = new String[0];
            if (args.has("args")) {
                JsonArray array = args.getAsJsonArray("args");
                scriptArgs = new String[array.size()];
                for (int i = 0; i < array.size(); i++) scriptArgs[i] = array.get(i).getAsString();
            }
            return executeScript(source, scriptArgs);
        } catch (Exception e) {
            return errorResult("Failed to run script: " + e.getMessage());
        }
    }

    // Load an exact ResourceFile rather than passing an absolute path to
    // runScript(), which searches by name. Source registration also enables
    // compiling helpers alongside a script outside the default directories.
    private JsonObject executeScript(generic.jar.ResourceFile source, String[] args) {
        StringWriter output = new StringWriter();
        StringWriter errors = new StringWriter();
        PrintWriter out = new PrintWriter(output, true);
        PrintWriter err = new PrintWriter(errors, true);
        // Ghidra's generated manifest already imports its OSGi package. Direct
        // references here cause a duplicate Import-Package entry in Ghidra 12.1.4.
        Object host;
        try { host = ghidra.app.script.GhidraScriptUtil.class.getMethod("getBundleHost").invoke(null); }
        catch (ReflectiveOperationException e) { return errorResult("Cannot access script bundle host: " + e); }
        generic.jar.ResourceFile directory = source.getParentFile();
        boolean registered = !ghidra.app.script.GhidraScriptUtil.getScriptSourceDirectories().contains(directory);
        Object addedBundle = null;
        try {
            if (registered) addedBundle = host.getClass().getMethod("add",
                generic.jar.ResourceFile.class, boolean.class, boolean.class).invoke(host, directory, true, false);
            ghidra.app.script.GhidraScriptProvider provider = ghidra.app.script.GhidraScriptUtil.getProvider(source);
            if (provider == null) throw new IOException("Unsupported script type: " + source.getName());
            GhidraScript script = provider.getScriptInstance(source, err);
            if (script == null) throw new IOException("Could not load script: " + source.getName());
            script.setScriptArgs(args);
            // Use a fresh state so stale parent-script state cannot switch the
            // active program after the bridge has opened another program.
            ghidra.app.script.GhidraState scriptState = new ghidra.app.script.GhidraState(
                state.getTool(), state.getProject(), currentProgram,
                currentLocation, currentSelection, currentHighlight);
            int tx = currentProgram.startTransaction("Run " + source.getName());
            boolean commit = false;
            try {
                script.execute(scriptState, new ghidra.app.script.ScriptControls(out, err, monitor));
                commit = true;
            } finally {
                currentProgram.endTransaction(tx, commit);
            }
            JsonObject result = new JsonObject();
            result.addProperty("status", "executed");
            result.addProperty("script", source.getAbsolutePath());
            result.addProperty("stdout", output.toString());
            result.addProperty("stderr", errors.toString());
            return result;
        } catch (Exception | LinkageError | AssertionError e) {
            return errorResult("Failed to run script: " + e.getMessage() + "\n" + errors + output);
        } finally {
            if (addedBundle != null) {
                try {
                    String location = (String) addedBundle.getClass().getMethod("getLocationIdentifier").invoke(addedBundle);
                    host.getClass().getMethod("deactivateSynchronously", String.class).invoke(host, location);
                } catch (Exception e) { printerr("Script bundle cleanup: " + e.getMessage()); }
                try { host.getClass().getMethod("remove", generic.jar.ResourceFile.class).invoke(host, directory); }
                catch (Exception e) { printerr("Script source cleanup: " + e.getMessage()); }
            }
            out.close();
            err.close();
        }
    }

    private JsonObject handleScriptJava(JsonObject args) {
        String code = getArgString(args, "code");
        if (code == null) return errorResult("Java code required");
        java.nio.file.Path directory = null;
        try {
            directory = java.nio.file.Files.createTempDirectory("ghidra-cli-inline-");
            String className = "GhidraCliInline" + java.util.UUID.randomUUID().toString().replace("-", "");
            java.nio.file.Path source = directory.resolve(className + ".java");
            java.nio.file.Files.writeString(source,
                "import ghidra.app.script.GhidraScript;\npublic class " + className +
                " extends GhidraScript { public void run() throws Exception {\n" + code + "\n} }\n");
            JsonObject result = executeScript(new generic.jar.ResourceFile(source.toFile()), new String[0]);
            result.remove("script");
            result.addProperty("language", "java");
            return result;
        } catch (Exception e) {
            return errorResult("Failed to execute Java: " + e.getMessage());
        } finally {
            if (directory != null) {
                try (java.util.stream.Stream<java.nio.file.Path> paths = java.nio.file.Files.walk(directory)) {
                    paths.sorted(Comparator.reverseOrder()).forEach(path -> {
                        try { java.nio.file.Files.deleteIfExists(path); }
                        catch (IOException e) { printerr("Inline cleanup: " + e.getMessage()); }
                    });
                } catch (IOException e) { printerr("Inline cleanup: " + e.getMessage()); }
            }
        }
    }

    private JsonObject handleScriptPython(JsonObject args) {
        return errorResult("Python execution not available (Java bridge replaces Python bridge)");
    }

    private JsonObject handleScriptList() {
        try {
            JsonArray scripts = new JsonArray();

            // List scripts from Ghidra's script directories
            Class<?> utilClass = Class.forName("ghidra.app.script.GhidraScriptUtil");
            java.lang.reflect.Method getDirs = utilClass.getMethod("getScriptSourceDirectories");
            Object dirs = getDirs.invoke(null);

            if (dirs instanceof Iterable) {
                for (Object dirObj : (Iterable<?>) dirs) {
                    File dir = new File(dirObj.toString());
                    if (dir.exists() && dir.isDirectory()) {
                        for (File f : dir.listFiles()) {
                            if (f.getName().endsWith(".py") || f.getName().endsWith(".java")) {
                                JsonObject scriptObj = new JsonObject();
                                scriptObj.addProperty("name", f.getName());
                                scriptObj.addProperty("path", f.getAbsolutePath());
                                scriptObj.addProperty("type", f.getName().endsWith(".py") ? "python" : "java");
                                scripts.add(scriptObj);
                            }
                        }
                    }
                }
            }

            JsonObject result = new JsonObject();
            result.add("scripts", scripts);
            result.addProperty("count", scripts.size());
            return result;
        } catch (Exception e) {
            return errorResult("Failed to list scripts: " + e.getMessage());
        }
    }

    // --- Batch Handler ---

    private JsonObject handleBatch(JsonObject args) {
        // Batch operations are handled by the Rust side, not the bridge directly
        return errorResult("Batch operations are handled by the CLI, not via bridge script");
    }

    // --- Memory Read Handler ---

    private JsonObject handleReadMemory(JsonObject args) {
        String addrStr = getArgString(args, "address");
        if (addrStr == null) return errorResult("Address required");

        int size = 200;
        if (args != null && args.has("size")) {
            size = args.get("size").getAsInt();
        }

        try {
            ghidra.program.model.mem.Memory mem = currentProgram.getMemory();
            ghidra.program.model.address.AddressFactory af = currentProgram.getAddressFactory();

            // Parse address
            long addrLong;
            if (addrStr.startsWith("0x") || addrStr.startsWith("0X")) {
                addrLong = Long.parseUnsignedLong(addrStr.substring(2), 16);
            } else {
                addrLong = Long.parseUnsignedLong(addrStr, 16);
            }

            ghidra.program.model.address.Address baseAddr = af.getDefaultAddressSpace().getAddress(addrLong);

            // Read bytes
            byte[] bytes = new byte[size];
            int bytesRead = mem.getBytes(baseAddr, bytes);

            // Build hex string
            StringBuilder hexStr = new StringBuilder();
            for (int i = 0; i < bytesRead; i++) {
                hexStr.append(String.format("%02x", bytes[i] & 0xFF));
            }

            // Also interpret as array of 8-byte pointers
            JsonArray pointers = new JsonArray();
            for (int i = 0; i + 7 < bytesRead; i += 8) {
                long val = 0;
                for (int j = 0; j < 8; j++) {
                    val |= ((long)(bytes[i+j] & 0xFF)) << (8*j);
                }
                JsonObject ptrObj = new JsonObject();
                ptrObj.addProperty("offset", i);
                ptrObj.addProperty("address", String.format("0x%08x", addrLong + i));
                ptrObj.addProperty("value", String.format("0x%016x", val));

                // Check if value looks like a code address
                if (val >= 0x00401000L && val <= 0x05bb99ffL) {
                    ghidra.program.model.address.Address funcAddr = af.getDefaultAddressSpace().getAddress(val);
                    ghidra.program.model.listing.Function func = currentProgram.getFunctionManager().getFunctionAt(funcAddr);
                    if (func != null) {
                        ptrObj.addProperty("function", func.getName());
                    }
                }

                pointers.add(ptrObj);
            }

            JsonObject result = new JsonObject();
            result.addProperty("address", String.format("0x%08x", addrLong));
            result.addProperty("size", bytesRead);
            result.addProperty("hex", hexStr.toString());
            result.add("pointers", pointers);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to read memory: " + e.getMessage());
        }
    }
}
