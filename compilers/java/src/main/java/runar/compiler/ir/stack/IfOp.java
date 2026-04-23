package runar.compiler.ir.stack;

import java.util.List;
import runar.compiler.canonical.JsonName;

/**
 * Conditional: pop a value and execute {@code thenBranch} when truthy,
 * {@code elseBranch} otherwise. The Java-side component name
 * {@code thenBranch} / {@code elseBranch} is remapped to the JSON keys
 * {@code then} / {@code else} via {@link JsonName} because {@code else}
 * is a reserved word and {@code then} follows the same convention for
 * symmetry.
 *
 * <p>{@code elseBranch} is nullable; when {@code null} it is omitted
 * from canonical JSON output.
 */
public record IfOp(
    @JsonName("then") List<StackOp> thenBranch,
    @JsonName("else") List<StackOp> elseBranch,
    StackSourceLoc sourceLoc
) implements StackOp {
    public IfOp(List<StackOp> thenBranch, List<StackOp> elseBranch) {
        this(thenBranch, elseBranch, null);
    }

    public IfOp(List<StackOp> thenBranch) {
        this(thenBranch, null, null);
    }

    @Override
    public String op() {
        return "if";
    }
}
