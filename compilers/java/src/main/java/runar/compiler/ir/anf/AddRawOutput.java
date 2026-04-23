package runar.compiler.ir.anf;

public record AddRawOutput(String satoshis, String scriptBytes) implements AnfValue {
    @Override
    public String kind() {
        return "add_raw_output";
    }
}
