package runar.compiler.ir.anf;

public record DeserializeState(String preimage) implements AnfValue {
    @Override
    public String kind() {
        return "deserialize_state";
    }
}
