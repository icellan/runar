package runar.compiler.ir.anf;

/**
 * Records a non-state-continuation transaction output. Included in the
 * auto-computed continuation hash after state outputs, before the
 * change output.
 */
public record AddDataOutput(String satoshis, String scriptBytes) implements AnfValue {
    @Override
    public String kind() {
        return "add_data_output";
    }
}
