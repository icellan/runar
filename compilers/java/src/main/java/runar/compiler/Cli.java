package runar.compiler;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import runar.compiler.canonical.Jcs;
import runar.compiler.frontend.ParserDispatch;
import runar.compiler.ir.anf.AnfProgram;
import runar.compiler.ir.ast.ContractNode;
import runar.compiler.ir.stack.StackProgram;
import runar.compiler.passes.AnfLoader;
import runar.compiler.passes.AnfLower;
import runar.compiler.passes.AnfOptimize;
import runar.compiler.passes.ConstantFold;
import runar.compiler.passes.Emit;
import runar.compiler.passes.ExpandFixedArrays;
import runar.compiler.passes.Peephole;
import runar.compiler.passes.StackLower;
import runar.compiler.passes.Typecheck;
import runar.compiler.passes.Validate;

/**
 * Command-line entry point for the Runar Java compiler.
 *
 * <p>Flag surface (matches the conformance-runner contract defined at
 * {@code conformance/runner/runner.ts}):
 *
 * <ul>
 *   <li>{@code --source <path> --emit-ir --disable-constant-folding} &rarr; canonical ANF JSON on stdout</li>
 *   <li>{@code --source <path> --hex --disable-constant-folding} &rarr; Bitcoin Script hex on stdout (M5)</li>
 *   <li>{@code --ir <path> --hex} &rarr; compile ANF JSON to hex (M5)</li>
 *   <li>{@code --version} &rarr; print {@code runar-java x.y.z}</li>
 * </ul>
 *
 * <p>The full pipeline (parse → validate → expand-fixed-arrays →
 * typecheck → ANF lower → optional constant-fold → ANF cleanup → stack
 * lower → peephole → emit) is wired end-to-end. {@code --emit-ir}
 * produces canonical ANF JSON; {@code --hex} produces Bitcoin Script
 * hex; both accept either a {@code --source} input in any of the 9
 * supported formats or a pre-generated {@code --ir} ANF JSON.
 */
public final class Cli {

    public static void main(String[] args) {
        int exit = new Cli(System.out, System.err).run(args);
        if (exit != 0) {
            System.exit(exit);
        }
    }

    private final PrintStream out;
    private final PrintStream err;

    public Cli(PrintStream out, PrintStream err) {
        this.out = out;
        this.err = err;
    }

    public int run(String[] args) {
        Args parsed;
        try {
            parsed = Args.parse(args);
        } catch (CliError e) {
            err.println("runar-java: " + e.getMessage());
            return 2;
        }

        if (parsed.version) {
            out.println("runar-java " + Version.VALUE);
            return 0;
        }

        if (parsed.daemon) {
            return runDaemon();
        }

        if (parsed.help || (parsed.source == null && parsed.ir == null)) {
            printUsage(out);
            return parsed.help ? 0 : 2;
        }

        if (parsed.ir != null) {
            return compileIr(parsed);
        }

        if (parsed.source != null) {
            return compileSource(parsed);
        }

        printUsage(out);
        return 2;
    }

    // ---------------------------------------------------------------
    // Pipeline orchestration
    // ---------------------------------------------------------------

    private int compileSource(Args parsed) {
        String filename = parsed.source;
        String source;
        try {
            source = Files.readString(Path.of(filename));
        } catch (IOException e) {
            err.println("runar-java: failed to read " + filename + ": " + e.getMessage());
            return 74;
        }

        ContractNode contract;
        try {
            contract = ParserDispatch.parse(source, filename);
        } catch (ParserDispatch.ParseException e) {
            err.println("runar-java: parse error: " + e.getMessage());
            return 65;
        } catch (RuntimeException e) {
            err.println("runar-java: parse error: " + e.getMessage());
            return 65;
        }

        try {
            Validate.run(contract);
        } catch (Validate.ValidationException e) {
            for (String msg : e.errors()) {
                err.println("runar-java: " + msg);
            }
            return 65;
        }

        // --parse-only: stop after parse + validate. Used by the conformance
        // runner's --parser-only universal-frontend coverage check.
        if (parsed.parseOnly) {
            out.println("parser ok");
            return 0;
        }

        try {
            contract = ExpandFixedArrays.run(contract);
        } catch (ExpandFixedArrays.ExpandException e) {
            for (String msg : e.errors()) {
                err.println("runar-java: " + msg);
            }
            return 65;
        }

        try {
            Typecheck.run(contract);
        } catch (Typecheck.TypeCheckException e) {
            for (String msg : e.errors()) {
                err.println("runar-java: " + msg);
            }
            return 65;
        }

        AnfProgram anf;
        try {
            anf = AnfLower.run(contract);
        } catch (RuntimeException e) {
            err.println("runar-java: anf-lower error: " + e.getMessage());
            return 70;
        }

        // Pass 4.25: constant folding (gated by --disable-constant-folding).
        // Pass 4.5:  general ANF cleanup (always on, matches Python pipeline).
        try {
            anf = optimizeAnf(anf, parsed.disableConstantFolding);
        } catch (RuntimeException e) {
            err.println("runar-java: anf-optimize error: " + e.getMessage());
            return 70;
        }

        // GAP-002: --emit-source-map writes {"mappings":[...]} to the path.
        // Runs INDEPENDENTLY of --emit-ir / --hex so a single invocation
        // can produce both artefacts (e.g. `--hex --emit-source-map=...`).
        if (parsed.emitSourceMap != null) {
            int rc = writeSourceMap(anf, parsed.emitSourceMap);
            if (rc != 0) return rc;
        }

        if (parsed.emitIr) {
            out.println(Jcs.stringify(anf));
            return 0;
        }

        if (parsed.hex) {
            return emitHex(anf);
        }

        // No output flag specified; default to IR emission for parity with
        // the other compilers' behaviour when --emit-ir is implied.
        out.println(Jcs.stringify(anf));
        return 0;
    }

    /**
     * GAP-002: lower ANF through stack + peephole + emit and write the
     * source map JSON to {@code path}. The path's parent directory is
     * created on demand. Returns 0 on success, non-zero on failure.
     */
    /**
     * GAP-011: source-map sourceFile values must be repo-relative (POSIX) so
     * goldens stay stable across worktree paths and developer machines. Walks
     * up from the source file looking for {@code pnpm-workspace.yaml} (the
     * canonical repo root marker); falls back to the basename if no marker is
     * found. Strings that aren't absolute paths are returned unchanged.
     */
    static String repoRelativeFileName(String srcPath) {
        if (srcPath == null || srcPath.isEmpty()) return srcPath;
        Path p = Path.of(srcPath);
        if (!p.isAbsolute()) return srcPath;
        Path dir = p.getParent();
        while (dir != null) {
            if (Files.exists(dir.resolve("pnpm-workspace.yaml"))) {
                String rel = dir.relativize(p).toString();
                return rel.replace(java.io.File.separatorChar, '/');
            }
            dir = dir.getParent();
        }
        return p.getFileName() == null ? srcPath : p.getFileName().toString();
    }

    private int writeSourceMap(AnfProgram anf, String path) {
        try {
            StackProgram stack = StackLower.run(anf);
            StackProgram optimised = Peephole.run(stack);
            Emit.EmitResultWithSourceMap result = Emit.runResultWithSourceMap(optimised);
            StringBuilder b = new StringBuilder(64 + 80 * result.sourceMap().size());
            b.append("{\n  \"mappings\": [");
            for (int i = 0; i < result.sourceMap().size(); i++) {
                Emit.SourceMapping m = result.sourceMap().get(i);
                if (i > 0) b.append(',');
                // GAP-011: normalize sourceFile to repo-relative POSIX so
                // goldens stay stable across worktree paths.
                b.append("\n    {\"opcodeIndex\": ").append(m.opcodeIndex())
                    .append(", \"sourceFile\": ").append(jsonString(repoRelativeFileName(m.sourceFile())))
                    .append(", \"line\": ").append(m.line())
                    .append(", \"column\": ").append(m.column())
                    .append('}');
            }
            if (!result.sourceMap().isEmpty()) b.append("\n  ");
            b.append("]\n}\n");
            Path target = Path.of(path);
            if (target.getParent() != null) {
                Files.createDirectories(target.getParent());
            }
            Files.writeString(target, b.toString());
            err.println("runar-java: source map written to " + path);
            return 0;
        } catch (IOException e) {
            err.println("runar-java: failed to write source map to " + path + ": " + e.getMessage());
            return 74;
        } catch (RuntimeException e) {
            err.println("runar-java: source-map emit error: " + e.getMessage());
            return 70;
        }
    }

    private int compileIr(Args parsed) {
        String irPath = parsed.ir;
        String json;
        try {
            json = Files.readString(Path.of(irPath));
        } catch (IOException e) {
            err.println("runar-java: failed to read " + irPath + ": " + e.getMessage());
            return 74;
        }

        AnfProgram anf;
        try {
            anf = AnfLoader.parse(json);
        } catch (RuntimeException e) {
            err.println("runar-java: ir parse error: " + e.getMessage());
            return 65;
        }

        // Pass 4.25/4.5 — same optimizer wiring as the source path.
        try {
            anf = optimizeAnf(anf, parsed.disableConstantFolding);
        } catch (RuntimeException e) {
            err.println("runar-java: anf-optimize error: " + e.getMessage());
            return 70;
        }

        // GAP-002: --emit-source-map also runs on the IR path.
        if (parsed.emitSourceMap != null) {
            int rc = writeSourceMap(anf, parsed.emitSourceMap);
            if (rc != 0) return rc;
        }

        if (parsed.emitIr) {
            out.println(Jcs.stringify(anf));
            return 0;
        }

        if (parsed.hex) {
            return emitHex(anf);
        }

        out.println(Jcs.stringify(anf));
        return 0;
    }

    /**
     * Apply the post-ANF optimization passes (constant folding + general
     * cleanup), respecting the {@code --disable-constant-folding} flag.
     * Public so tests can drive the optimizer end-to-end without spinning
     * up the whole CLI.
     */
    public static AnfProgram optimizeAnf(AnfProgram anf, boolean disableConstantFolding) {
        if (!disableConstantFolding) {
            anf = ConstantFold.run(anf);
        }
        // AnfOptimize delegates internally to {@link Dce#eliminateDead} for
        // dead-binding cleanup after any EC rewrite. The standalone Dce class
        // exists as the canonical, named DCE pass module mirroring Zig's
        // compilers/zig/src/passes/dce.zig.
        anf = AnfOptimize.run(anf);
        return anf;
    }

    private int emitHex(AnfProgram anf) {
        try {
            StackProgram stack = StackLower.run(anf);
            StackProgram optimised = Peephole.run(stack);
            String hex = Emit.run(optimised);
            out.println(hex);
            return 0;
        } catch (RuntimeException e) {
            err.println("runar-java: emit error: " + e.getMessage());
            return 70;
        }
    }

    static void printUsage(PrintStream stream) {
        stream.println("Usage: runar-java [options]");
        stream.println();
        stream.println("Options:");
        stream.println("  --source <path>              source file (.runar.{ts,sol,move,py,go,rs,zig,rb,java})");
        stream.println("  --ir <path>                  pre-generated ANF JSON");
        stream.println("  --emit-ir                    emit canonical ANF JSON on stdout");
        stream.println("  --hex                        emit Bitcoin Script hex on stdout");
        stream.println("  --disable-constant-folding   disable the constant-folding optimizer (required for conformance)");
        stream.println("  --emit-source-map <path>     write the artifact's sourceMap JSON to <path>");
        stream.println("  --daemon                     run in daemon mode (line-delimited JSON RPC on stdin/stdout)");
        stream.println("  --version                    print version and exit");
        stream.println("  -h, --help                   print this help and exit");
    }

    // -----------------------------------------------------------------
    // Daemon mode
    // -----------------------------------------------------------------
    //
    // Avoids paying ~1.5s of JVM cold-start on every conformance compile.
    // Reads line-delimited JSON requests from stdin, writes line-delimited
    // JSON responses to stdout. All compile state is request-local — the
    // process holds no contract state between requests.
    //
    // Request shape (one JSON object per line):
    //   {"id": <int>, "source": "<path>", "emitIr": <bool>, "hex": <bool>,
    //    "disableConstantFolding": <bool>}
    // Or to terminate: {"id": <int>, "shutdown": true}
    //
    // Response shape (one JSON object per line):
    //   {"id": <int>, "ok": true, "ir": "<canonical-json>", "hex": "<hex>"}
    //   {"id": <int>, "ok": false, "error": "<message>"}
    //
    // The daemon uses ONLY ASCII / UTF-8 in JSON values; strings are escaped
    // with the minimal set required by RFC 8259 (\\, \", \n, \r, \t, control
    // chars). Pulling in Jackson / Gson would inflate the runtime, so we
    // hand-roll a tiny single-line JSON parser scoped to this RPC shape.
    //
    // Output convention: each response is exactly ONE LINE; embedded
    // newlines in IR / hex strings are escaped. The peer reads a line, parses
    // it, dispatches by id.

    private int runDaemon() {
        // Print a small banner so the parent runner can sync on startup.
        out.println("{\"daemon\": \"runar-java\", \"version\": \"" + Version.VALUE + "\"}");
        out.flush();

        BufferedReader r = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        try {
            String line;
            while ((line = r.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty()) continue;
                DaemonRequest req;
                try {
                    req = DaemonRequest.parseLine(line);
                } catch (RuntimeException e) {
                    out.println("{\"id\":-1,\"ok\":false,\"error\":" + jsonString(
                        "request parse error: " + e.getMessage()) + "}");
                    out.flush();
                    continue;
                }
                if (req.shutdown) {
                    out.println("{\"id\":" + req.id + ",\"ok\":true,\"shutdown\":true}");
                    out.flush();
                    return 0;
                }
                String response = serveRequest(req);
                out.println(response);
                out.flush();
            }
        } catch (IOException e) {
            err.println("runar-java daemon: stdin read failed: " + e.getMessage());
            return 74;
        }
        return 0;
    }

    private String serveRequest(DaemonRequest req) {
        if (req.source == null || req.source.isEmpty()) {
            return "{\"id\":" + req.id + ",\"ok\":false,\"error\":"
                + jsonString("missing source path") + "}";
        }
        try {
            String src = Files.readString(Path.of(req.source));
            ContractNode contract = ParserDispatch.parse(src, req.source);
            Validate.run(contract);
            // parseOnly short-circuit: skip everything past validate. Used
            // by the conformance runner's --parser-only mode so the
            // universal frontend coverage check doesn't pay for the full
            // pipeline.
            if (req.parseOnly) {
                StringBuilder b = new StringBuilder(96);
                b.append("{\"id\":").append(req.id).append(",\"ok\":true,\"parsed\":true}");
                return b.toString();
            }
            contract = ExpandFixedArrays.run(contract);
            Typecheck.run(contract);
            AnfProgram anf = AnfLower.run(contract);
            anf = optimizeAnf(anf, req.disableConstantFolding);

            String irJson = req.emitIr || (!req.hex && !req.emitIr) ? Jcs.stringify(anf) : "";
            String hexStr = "";
            if (req.hex) {
                StackProgram stack = StackLower.run(anf);
                StackProgram opt = Peephole.run(stack);
                hexStr = Emit.run(opt);
            }
            StringBuilder b = new StringBuilder(256);
            b.append("{\"id\":").append(req.id).append(",\"ok\":true");
            if (req.emitIr || (!req.hex)) b.append(",\"ir\":").append(jsonString(irJson));
            if (req.hex) b.append(",\"hex\":").append(jsonString(hexStr));
            b.append('}');
            return b.toString();
        } catch (Throwable t) {
            String msg = t.getClass().getSimpleName() + ": " + (t.getMessage() == null ? "(no message)" : t.getMessage());
            return "{\"id\":" + req.id + ",\"ok\":false,\"error\":" + jsonString(msg) + "}";
        }
    }

    /** Minimal JSON string escaper. */
    static String jsonString(String s) {
        if (s == null) return "null";
        StringBuilder b = new StringBuilder(s.length() + 8);
        b.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> b.append("\\\"");
                case '\\' -> b.append("\\\\");
                case '\n' -> b.append("\\n");
                case '\r' -> b.append("\\r");
                case '\t' -> b.append("\\t");
                case '\b' -> b.append("\\b");
                case '\f' -> b.append("\\f");
                default -> {
                    if (c < 0x20) {
                        b.append(String.format("\\u%04x", (int) c));
                    } else {
                        b.append(c);
                    }
                }
            }
        }
        b.append('"');
        return b.toString();
    }

    /** Single-line JSON request decoder. Only handles the request shape. */
    static final class DaemonRequest {
        int id = -1;
        String source;
        boolean emitIr;
        boolean hex;
        boolean parseOnly;
        boolean disableConstantFolding;
        boolean shutdown;

        static DaemonRequest parseLine(String line) {
            DaemonRequest r = new DaemonRequest();
            // Accept any subset of these top-level keys. Naive but safe for
            // our well-formed peer.
            r.id = parseIntField(line, "id", -1);
            r.source = parseStringField(line, "source");
            r.emitIr = parseBoolField(line, "emitIr", false);
            r.hex = parseBoolField(line, "hex", false);
            r.parseOnly = parseBoolField(line, "parseOnly", false);
            r.disableConstantFolding = parseBoolField(line, "disableConstantFolding", false);
            r.shutdown = parseBoolField(line, "shutdown", false);
            return r;
        }
    }

    private static int parseIntField(String json, String key, int defaultValue) {
        String token = "\"" + key + "\"";
        int idx = json.indexOf(token);
        if (idx < 0) return defaultValue;
        int colon = json.indexOf(':', idx + token.length());
        if (colon < 0) return defaultValue;
        int p = colon + 1;
        while (p < json.length() && Character.isWhitespace(json.charAt(p))) p++;
        int start = p;
        if (p < json.length() && (json.charAt(p) == '-' || json.charAt(p) == '+')) p++;
        while (p < json.length() && Character.isDigit(json.charAt(p))) p++;
        if (p == start) return defaultValue;
        try {
            return Integer.parseInt(json.substring(start, p));
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    private static boolean parseBoolField(String json, String key, boolean defaultValue) {
        String token = "\"" + key + "\"";
        int idx = json.indexOf(token);
        if (idx < 0) return defaultValue;
        int colon = json.indexOf(':', idx + token.length());
        if (colon < 0) return defaultValue;
        int p = colon + 1;
        while (p < json.length() && Character.isWhitespace(json.charAt(p))) p++;
        if (p + 4 <= json.length() && json.startsWith("true", p)) return true;
        if (p + 5 <= json.length() && json.startsWith("false", p)) return false;
        return defaultValue;
    }

    private static String parseStringField(String json, String key) {
        String token = "\"" + key + "\"";
        int idx = json.indexOf(token);
        if (idx < 0) return null;
        int colon = json.indexOf(':', idx + token.length());
        if (colon < 0) return null;
        int p = colon + 1;
        while (p < json.length() && Character.isWhitespace(json.charAt(p))) p++;
        if (p >= json.length() || json.charAt(p) != '"') return null;
        p++;
        StringBuilder b = new StringBuilder();
        while (p < json.length()) {
            char c = json.charAt(p);
            if (c == '\\' && p + 1 < json.length()) {
                char esc = json.charAt(p + 1);
                switch (esc) {
                    case '"' -> b.append('"');
                    case '\\' -> b.append('\\');
                    case '/' -> b.append('/');
                    case 'n' -> b.append('\n');
                    case 'r' -> b.append('\r');
                    case 't' -> b.append('\t');
                    case 'b' -> b.append('\b');
                    case 'f' -> b.append('\f');
                    case 'u' -> {
                        if (p + 5 < json.length()) {
                            try {
                                b.append((char) Integer.parseInt(json.substring(p + 2, p + 6), 16));
                            } catch (NumberFormatException ignored) {}
                            p += 4;
                        }
                    }
                    default -> b.append(esc);
                }
                p += 2;
            } else if (c == '"') {
                return b.toString();
            } else {
                b.append(c);
                p++;
            }
        }
        return null;
    }

    static final class Args {
        String source;
        String ir;
        boolean emitIr;
        boolean hex;
        boolean parseOnly;
        boolean disableConstantFolding;
        boolean version;
        boolean help;
        boolean daemon;
        // GAP-002: when non-null, after compile finishes write the
        // sourceMap object ({"mappings":[...]}) to this path.
        String emitSourceMap;

        static Args parse(String[] argv) {
            Args out = new Args();
            List<String> list = new ArrayList<>(List.of(argv));
            while (!list.isEmpty()) {
                String arg = list.remove(0);
                if (arg.startsWith("--emit-source-map=")) {
                    out.emitSourceMap = arg.substring("--emit-source-map=".length());
                    continue;
                }
                switch (arg) {
                    case "--source" -> out.source = requireValue(list, "--source");
                    case "--ir" -> out.ir = requireValue(list, "--ir");
                    case "--emit-ir" -> out.emitIr = true;
                    case "--hex" -> out.hex = true;
                    case "--parse-only" -> out.parseOnly = true;
                    case "--disable-constant-folding" -> out.disableConstantFolding = true;
                    case "--emit-source-map" -> out.emitSourceMap = requireValue(list, "--emit-source-map");
                    case "--daemon" -> out.daemon = true;
                    case "--version" -> out.version = true;
                    case "-h", "--help" -> out.help = true;
                    default -> throw new CliError("unknown flag: " + arg);
                }
            }
            return out;
        }

        private static String requireValue(List<String> list, String flag) {
            if (list.isEmpty()) {
                throw new CliError("missing value for " + flag);
            }
            return list.remove(0);
        }
    }

    static final class CliError extends RuntimeException {
        CliError(String msg) {
            super(msg);
        }
    }
}
