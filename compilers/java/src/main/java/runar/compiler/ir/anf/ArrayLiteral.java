package runar.compiler.ir.anf;

import java.util.List;

public record ArrayLiteral(List<String> elements) implements AnfValue {
    @Override
    public String kind() {
        return "array_literal";
    }
}
