package runar.compiler.ir.stack;

/** Hex-encoded byte string; emitted to canonical JSON as a JSON string. */
public record ByteStringPushValue(String hex) implements PushValue {
    @Override
    public Object raw() {
        return hex;
    }
}
