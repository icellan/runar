package runar.compiler.ir.anf;

import java.util.List;

/**
 * Root of the ANF IR. This is the <b>canonical conformance boundary</b>
 * for Rúnar compilers: two compilers that accept the same source must
 * emit byte-identical {@code AnfProgram} under canonical JSON.
 */
public record AnfProgram(String contractName, List<AnfProperty> properties, List<AnfMethod> methods) {}
