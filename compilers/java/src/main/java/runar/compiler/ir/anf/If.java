package runar.compiler.ir.anf;

import java.util.List;
import runar.compiler.canonical.JsonName;

/**
 * The {@code else} branch uses a Java-safe component name
 * ({@code elseBranch}) because {@code else} is a reserved keyword;
 * serialisation emits it under the {@code else} key.
 */
public record If(
    String cond,
    @JsonName("then") List<AnfBinding> thenBranch,
    @JsonName("else") List<AnfBinding> elseBranch
) implements AnfValue {
    @Override
    public String kind() {
        return "if";
    }
}
