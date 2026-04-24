package runar.compiler;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import runar.compiler.canonical.Jcs;
import runar.compiler.frontend.JavaParser;
import runar.compiler.ir.anf.AnfProgram;
import runar.compiler.ir.ast.ContractNode;
import runar.compiler.passes.AnfLower;
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
 * <p>M4: the parse/validate/typecheck/anf-lower pipeline is live; stack
 * lowering + emit land in M5 so {@code --hex} still short-circuits with
 * "not implemented".
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
            // M5 will wire stack lowering + emit on a pre-generated IR.
            err.println("runar-java: --ir is not yet implemented (M5 will add stack lowering + emit)");
            return 64;
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
            contract = JavaParser.parse(source, filename);
        } catch (JavaParser.ParseException e) {
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

        if (parsed.emitIr) {
            out.println(Jcs.stringify(anf));
            return 0;
        }

        if (parsed.hex) {
            // M5 will implement stack lowering + peephole + emit. Until
            // then, make the failure mode explicit so the conformance runner
            // can distinguish "not yet" from "broken".
            err.println("runar-java: --hex is not yet implemented (M5 will add stack lowering + emit)");
            return 64;
        }

        // No output flag specified; default to IR emission for parity with
        // the other compilers' behaviour when --emit-ir is implied.
        out.println(Jcs.stringify(anf));
        return 0;
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
