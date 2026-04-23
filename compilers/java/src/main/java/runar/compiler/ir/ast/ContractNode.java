package runar.compiler.ir.ast;

import java.util.List;

/**
 * Root of the Rúnar AST. Every parser dispatch path ({@code .runar.ts},
 * {@code .runar.py}, {@code .runar.java}, &hellip;) produces a
 * {@code ContractNode}.
 */
public record ContractNode(
    String name,
    ParentClass parentClass,
    List<PropertyNode> properties,
    MethodNode constructor,
    List<MethodNode> methods,
    String sourceFile
) {
    public String kind() {
        return "contract";
    }
}
