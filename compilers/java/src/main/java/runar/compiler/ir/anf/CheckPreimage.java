package runar.compiler.ir.anf;

public record CheckPreimage(String preimage) implements AnfValue {
    @Override
    public String kind() {
        return "check_preimage";
    }
}
