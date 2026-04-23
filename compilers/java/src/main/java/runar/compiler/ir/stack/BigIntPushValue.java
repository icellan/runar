package runar.compiler.ir.stack;

import java.math.BigInteger;

public record BigIntPushValue(BigInteger value) implements PushValue {
    @Override
    public Object raw() {
        return value;
    }
}
