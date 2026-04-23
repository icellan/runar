package runar.compiler.ir.ast;

import java.math.BigInteger;

public record BigIntLiteral(BigInteger value) implements Expression {
    @Override
    public String kind() {
        return "bigint_literal";
    }
}
