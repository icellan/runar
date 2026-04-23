package runar.compiler.ir.ast;

import java.math.BigInteger;
import java.util.List;

/**
 * Rúnar expression nodes. Sealed interface with ~13 implementations
 * mirroring {@code Expression} in {@code packages/runar-ir-schema/src/runar-ast.ts}.
 */
public sealed interface Expression
    permits BinaryExpr, UnaryExpr, CallExpr, MemberExpr, Identifier,
            BigIntLiteral, BoolLiteral, ByteStringLiteral, TernaryExpr,
            PropertyAccessExpr, IndexAccessExpr, IncrementExpr,
            DecrementExpr, ArrayLiteralExpr {
    String kind();

    enum BinaryOp {
        ADD("+"), SUB("-"), MUL("*"), DIV("/"), MOD("%"),
        EQ("==="), NEQ("!=="),
        LT("<"), LE("<="), GT(">"), GE(">="),
        AND("&&"), OR("||"),
        BIT_AND("&"), BIT_OR("|"), BIT_XOR("^"),
        SHL("<<"), SHR(">>");

        private final String canonical;

        BinaryOp(String canonical) {
            this.canonical = canonical;
        }

        public String canonical() {
            return canonical;
        }

        public static BinaryOp fromCanonical(String s) {
            for (BinaryOp op : values()) {
                if (op.canonical.equals(s)) {
                    return op;
                }
            }
            throw new IllegalArgumentException("unknown binary op: " + s);
        }
    }

    enum UnaryOp {
        NOT("!"), NEG("-"), BIT_NOT("~");

        private final String canonical;

        UnaryOp(String canonical) {
            this.canonical = canonical;
        }

        public String canonical() {
            return canonical;
        }

        public static UnaryOp fromCanonical(String s) {
            for (UnaryOp op : values()) {
                if (op.canonical.equals(s)) {
                    return op;
                }
            }
            throw new IllegalArgumentException("unknown unary op: " + s);
        }
    }
}
