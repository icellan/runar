package runar.compiler.ir.anf;

public record LoadProp(String name) implements AnfValue {
    @Override
    public String kind() {
        return "load_prop";
    }
}
