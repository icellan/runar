package runar.compiler.ir.stack;

import java.util.List;

/**
 * Root of the Stack IR — the output of the stack-lowering pass (Pass 5).
 *
 * <p>Unlike {@link runar.compiler.ir.anf.AnfProgram}, Stack IR is
 * compiler-local rather than part of the cross-compiler conformance
 * boundary. It is still serialised through canonical JSON for golden
 * fixtures and debug dumps.
 *
 * <p>Matches {@code StackProgram} in
 * {@code packages/runar-ir-schema/src/stack-ir.ts}.
 */
public record StackProgram(String contractName, List<StackMethod> methods) {}
