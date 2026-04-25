package runar.compiler;

import java.io.IOException;
import java.io.PrintStream;
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
        stream.println("  --version                    print version and exit");
        stream.println("  -h, --help                   print this help and exit");
    }

    static final class Args {
        String source;
        String ir;
        boolean emitIr;
        boolean hex;
        boolean disableConstantFolding;
        boolean version;
        boolean help;

        static Args parse(String[] argv) {
            Args out = new Args();
            List<String> list = new ArrayList<>(List.of(argv));
            while (!list.isEmpty()) {
                String arg = list.remove(0);
                switch (arg) {
                    case "--source" -> out.source = requireValue(list, "--source");
                    case "--ir" -> out.ir = requireValue(list, "--ir");
                    case "--emit-ir" -> out.emitIr = true;
                    case "--hex" -> out.hex = true;
                    case "--disable-constant-folding" -> out.disableConstantFolding = true;
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
