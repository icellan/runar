package runar.compiler;

import java.io.PrintStream;
import java.util.ArrayList;
import java.util.List;

/**
 * Command-line entry point for the Runar Java compiler.
 *
 * <p>Flag surface (matches the conformance-runner contract defined at
 * {@code conformance/runner/runner.ts:220-230}):
 *
 * <ul>
 *   <li>{@code --source <path> --emit-ir --disable-constant-folding} &rarr; ANF JSON</li>
 *   <li>{@code --source <path> --hex --disable-constant-folding} &rarr; Bitcoin Script hex</li>
 *   <li>{@code --ir <path> --hex} &rarr; compile ANF JSON to hex</li>
 *   <li>{@code --version} &rarr; print {@code runar-java x.y.z}</li>
 * </ul>
 *
 * <p>Phase 1: all compilation flags short-circuit with a "not implemented"
 * error. Pipeline passes land in milestones 3-6 of {@code docs/java-tier-plan.md}.
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

        if (parsed.help || parsed.source == null && parsed.ir == null) {
            printUsage(out);
            return parsed.help ? 0 : 2;
        }

        // Phase 1 short-circuit: pipeline not implemented yet.
        err.println("runar-java: compilation not yet implemented — milestone 3 will add parse/validate/typecheck");
        err.println("            see docs/java-tier-plan.md for the roadmap.");
        return 64;
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
