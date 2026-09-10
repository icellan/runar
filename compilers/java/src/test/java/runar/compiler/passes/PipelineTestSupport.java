package runar.compiler.passes;

import runar.compiler.Cli;
import runar.compiler.canonical.Jcs;
import runar.compiler.frontend.ParserDispatch;
import runar.compiler.ir.anf.AnfProgram;
import runar.compiler.ir.ast.ContractNode;
import runar.compiler.ir.stack.StackProgram;

/**
 * Shared end-to-end compile helpers for the #123 / #109 port tests. Reproduces
 * the production Cli pipeline in fold-OFF mode (constant folding disabled, DCE +
 * peephole ON) so results are byte-comparable with the checked-in cross-tier
 * goldens and the TypeScript reference compiled under {@code disableConstantFolding: true}.
 */
final class PipelineTestSupport {
    private PipelineTestSupport() {}

    /** Parse + validate (throws on error). */
    static ContractNode parseValidated(String src, String file) throws Exception {
        ContractNode contract = ParserDispatch.parse(src, file);
        Validate.run(contract); // throws ValidationException on errors
        return contract;
    }

    /** Full fold-OFF compile → Bitcoin Script hex. */
    static String hex(String src, String file) throws Exception {
        return hex(src, file, /* disableConstantFolding */ true);
    }

    /** Full compile → Bitcoin Script hex, choosing the constant-folding mode. */
    static String hex(String src, String file, boolean disableConstantFolding) throws Exception {
        ContractNode contract = parseValidated(src, file);
        contract = ExpandFixedArrays.run(contract);
        Typecheck.run(contract);
        AnfProgram anf = AnfLower.run(contract);
        anf = Cli.optimizeAnf(anf, disableConstantFolding); // DCE + EC rewrite always ON
        StackProgram stack = StackLower.run(anf);
        stack = Peephole.run(stack);
        return Emit.run(stack);
    }

    /** Fold-OFF compile → the constructor-slot parameter indexes, in emitted order. */
    static java.util.List<Integer> slotParamIndexes(String src, String file) throws Exception {
        ContractNode contract = parseValidated(src, file);
        contract = ExpandFixedArrays.run(contract);
        Typecheck.run(contract);
        AnfProgram anf = AnfLower.run(contract);
        anf = Cli.optimizeAnf(anf, /* disableConstantFolding */ true);
        StackProgram stack = StackLower.run(anf);
        stack = Peephole.run(stack);
        return Emit.runResultFull(stack).constructorSlots().stream()
            .map(Emit.ConstructorSlot::paramIndex)
            .toList();
    }

    /** Fold-OFF optimized ANF as canonical JSON. */
    static String anfJson(String src, String file) throws Exception {
        ContractNode contract = parseValidated(src, file);
        contract = ExpandFixedArrays.run(contract);
        Typecheck.run(contract);
        AnfProgram anf = AnfLower.run(contract);
        anf = Cli.optimizeAnf(anf, true);
        return Jcs.stringify(anf);
    }

    /** Collect validate diagnostics (never throws). Requires the source to parse. */
    static Validate.Result diagnostics(String src, String file) throws Exception {
        ContractNode contract = ParserDispatch.parse(src, file);
        return Validate.runCollecting(contract);
    }

    static boolean compiles(String src, String file) {
        try {
            hex(src, file);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
