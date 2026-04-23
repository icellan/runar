package runar.compiler.ir.ast;

/**
 * Closed enumeration of Rúnar primitive types. Every contract field,
 * method parameter, and expression result resolves to one of these (or
 * a {@code FixedArray<T, N>} of them).
 *
 * <p>Canonical name (what appears in the AST and ANF JSON) is the
 * {@link #canonical} field — not the Java enum literal, which uses
 * upper-case by convention.
 */
public enum PrimitiveTypeName {
    BIGINT("bigint"),
    BOOLEAN("boolean"),
    BYTE_STRING("ByteString"),
    PUB_KEY("PubKey"),
    SIG("Sig"),
    SHA_256("Sha256"),
    RIPEMD_160("Ripemd160"),
    ADDR("Addr"),
    SIG_HASH_PREIMAGE("SigHashPreimage"),
    RABIN_SIG("RabinSig"),
    RABIN_PUB_KEY("RabinPubKey"),
    POINT("Point"),
    P256_POINT("P256Point"),
    P384_POINT("P384Point");

    private final String canonical;

    PrimitiveTypeName(String canonical) {
        this.canonical = canonical;
    }

    public String canonical() {
        return canonical;
    }

    public static PrimitiveTypeName fromCanonical(String name) {
        for (PrimitiveTypeName t : values()) {
            if (t.canonical.equals(name)) {
                return t;
            }
        }
        throw new IllegalArgumentException("unknown primitive type: " + name);
    }
}
