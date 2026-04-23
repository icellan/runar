package runar.compiler.ir.stack;

public record BoolPushValue(boolean value) implements PushValue {
    @Override
    public Object raw() {
        return value;
    }
}
