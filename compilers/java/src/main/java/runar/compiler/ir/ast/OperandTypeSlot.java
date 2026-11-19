package runar.compiler.ir.ast;

/**
 * D12 FE-F1: the operand family the TYPE CHECKER resolved for an operator
 * whose lowering depends on it ({@code +} = OP_CAT vs OP_ADD, {@code ===} /
 * {@code !==} = OP_EQUAL vs OP_NUMEQUAL, {@code & | ^ ~} on byte strings vs
 * numbers). AST nodes are immutable records, so the family lives in this small
 * mutable slot that each {@link BinaryExpr} / {@link UnaryExpr} carries: the
 * type checker writes it, ANF lowering reads it and refuses a node that
 * carries none. Never set by a parser. A rebuild of a node that should keep
 * the family passes the old node's slot to the new one.
 *
 * <p>Not part of node equality.
 */
public final class OperandTypeSlot {
    /** The operand families. */
    public enum OperandType { BYTES, NUMERIC }

    private OperandType value;

    public OperandTypeSlot() {}

    /** A slot already holding {@code value} (for nodes a pass synthesises). */
    public static OperandTypeSlot of(OperandType value) {
        OperandTypeSlot s = new OperandTypeSlot();
        s.value = value;
        return s;
    }

    public OperandType get() {
        return value;
    }

    public void set(OperandType value) {
        this.value = value;
    }

    @Override
    public String toString() {
        return String.valueOf(value);
    }
}
