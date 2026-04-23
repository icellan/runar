package runar.compiler.ir.anf;

import runar.compiler.canonical.JsonName;

public record UnaryOp(
    String op,
    String operand,
    @JsonName("result_type") String resultType
) implements AnfValue {
    @Override
    public String kind() {
        return "unary_op";
    }
}
