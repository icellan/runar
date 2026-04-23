package runar.compiler.ir.anf;

public record GetStateScript() implements AnfValue {
    @Override
    public String kind() {
        return "get_state_script";
    }
}
