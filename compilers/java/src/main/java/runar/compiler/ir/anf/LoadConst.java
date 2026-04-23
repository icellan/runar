package runar.compiler.ir.anf;

public record LoadConst(ConstValue value) implements AnfValue {
    @Override
    public String kind() {
        return "load_const";
    }
}
