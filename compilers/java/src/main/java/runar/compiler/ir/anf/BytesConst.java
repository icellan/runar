package runar.compiler.ir.anf;

/** Hex-encoded byte string; emitted to canonical JSON as a JSON string. */
public record BytesConst(String hex) implements ConstValue {
    @Override
    public Object raw() {
        return hex;
    }
}
