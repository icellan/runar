package runar.compiler.ir.anf;

public record Assert(String value) implements AnfValue {
    @Override
    public String kind() {
        return "assert";
    }
}
