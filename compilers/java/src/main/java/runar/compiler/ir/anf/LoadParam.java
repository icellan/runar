package runar.compiler.ir.anf;

public record LoadParam(String name) implements AnfValue {
    @Override
    public String kind() {
        return "load_param";
    }
}
