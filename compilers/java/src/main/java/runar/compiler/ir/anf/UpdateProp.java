package runar.compiler.ir.anf;

public record UpdateProp(String name, String value) implements AnfValue {
    @Override
    public String kind() {
        return "update_prop";
    }
}
