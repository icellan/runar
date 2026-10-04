package runar.compiler.ir.anf;

import java.util.List;

/**
 * Root of the ANF IR. This is the <b>canonical conformance boundary</b>
 * for Rúnar compilers: two compilers that accept the same source must
 * emit byte-identical {@code AnfProgram} under canonical JSON.
 *
 * @param parentClass F-038: the base class the source contract extends
 *                    ("SmartContract" | "StatefulSmartContract" |
 *                    "UnsafeSmartContract"). Wire data — emitted as
 *                    {@code parentClass} so an {@code --emit-ir} ->
 *                    {@code --ir} round trip keeps the artifact's
 *                    parentClass, which the SDKs read to gate the
 *                    issue-#42/#44 subscript trim. {@code null} (omitted by
 *                    Jcs) only for IR loaded without it.
 */
public record AnfProgram(
    String contractName,
    List<AnfProperty> properties,
    List<AnfMethod> methods,
    String parentClass
) {
    /** A program with no recorded parent class (IR written before F-038, tests). */
    public AnfProgram(String contractName, List<AnfProperty> properties, List<AnfMethod> methods) {
        this(contractName, properties, methods, null);
    }

    /** This program with {@code methods} replaced and every other component kept. */
    public AnfProgram withMethods(List<AnfMethod> newMethods) {
        return new AnfProgram(contractName, properties, newMethods, parentClass);
    }
}
