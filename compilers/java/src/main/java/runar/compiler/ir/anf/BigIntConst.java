package runar.compiler.ir.anf;

import java.math.BigInteger;

public record BigIntConst(BigInteger value) implements ConstValue {
    @Override
    public Object raw() {
        return value;
    }
}
