package runar.compiler.ir.anf;

import runar.compiler.canonical.JsonName;

/**
 * Binary operation on two temporaries. {@code resultType} is an optional
 * operand-type hint ({@code "bytes"} for byte-string operands, null for
 * numeric). Serialised as {@code result_type} per the TS ANF schema.
 */
public record BinOp(
    String op,
    String left,
    String right,
    @JsonName("result_type") String resultType
) implements AnfValue {
    @Override
    public String kind() {
        return "bin_op";
    }
}
