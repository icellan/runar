package runar.compiler.ir.anf;

public record BoolConst(boolean value) implements ConstValue {
    @Override
    public Object raw() {
        return value;
    }
}
