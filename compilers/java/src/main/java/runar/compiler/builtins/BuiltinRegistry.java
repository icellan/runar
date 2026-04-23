package runar.compiler.builtins;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Central registry of Rúnar built-in functions.
 *
 * <p>Source-of-truth is {@code packages/runar-lang/src/builtins.ts}. Every
 * builtin that appears there has an entry here with its parameter types and
 * return type (expressed as canonical type-name strings, matching the
 * {@link runar.compiler.ir.ast.PrimitiveTypeName#canonical()} spelling).
 *
 * <p>The registry also includes a small number of preimage / output helpers
 * that are part of the Rúnar surface but live on {@code this} rather than as
 * free functions — they are accepted by the type-checker through a separate
 * path but are listed here in the "extended" table for completeness so a
 * cross-compiler parity check can rely on a single source.
 *
 * <p>The signatures below are mirrored from
 * {@code compilers/python/runar_compiler/frontend/typecheck.py:BUILTIN_FUNCTIONS}.
 */
public final class BuiltinRegistry {

    private BuiltinRegistry() {}

    /** One parameter of a builtin signature. */
    public record Param(String name, String type) {}

    /**
     * A builtin signature. {@code pure} is reserved for a future optimizer
     * hint — every current builtin is pure, so this defaults to {@code true}.
     */
    public record Signature(
        String name,
        List<Param> params,
        String returnType,
        boolean pure
    ) {
        public Signature {
            params = List.copyOf(params);
        }

        public int arity() {
            return params.size();
        }
    }

    private static final Map<String, Signature> SIGNATURES;

    static {
        Map<String, Signature> m = new LinkedHashMap<>();

        // ---------------- cryptographic hashes ----------------
        add(m, "sha256",          new String[][]{{"data", "ByteString"}}, "Sha256");
        add(m, "Sha256Hash",      new String[][]{{"data", "ByteString"}}, "Sha256");
        add(m, "ripemd160",       new String[][]{{"data", "ByteString"}}, "Ripemd160");
        add(m, "hash160",         new String[][]{{"data", "ByteString"}}, "Ripemd160");
        add(m, "hash256",         new String[][]{{"data", "ByteString"}}, "Sha256");
        add(m, "sha256Compress",  new String[][]{{"state", "ByteString"}, {"block", "ByteString"}}, "ByteString");
        add(m, "sha256Finalize",  new String[][]{{"state", "ByteString"}, {"remaining", "ByteString"}, {"msgBitLen", "bigint"}}, "ByteString");
        add(m, "blake3Compress",  new String[][]{{"chainingValue", "ByteString"}, {"block", "ByteString"}}, "ByteString");
        add(m, "blake3Hash",      new String[][]{{"message", "ByteString"}}, "ByteString");

        // ---------------- signature verification --------------
        add(m, "checkSig",        new String[][]{{"sig", "Sig"}, {"pubkey", "PubKey"}}, "boolean");
        add(m, "checkMultiSig",   new String[][]{{"sigs", "Sig[]"}, {"pubkeys", "PubKey[]"}}, "boolean");
        add(m, "checkPreimage",   new String[][]{{"preimage", "SigHashPreimage"}}, "boolean");
        add(m, "verifyRabinSig",  new String[][]{{"msg", "ByteString"}, {"sig", "RabinSig"}, {"padding", "ByteString"}, {"pubkey", "RabinPubKey"}}, "boolean");

        // ---------------- post-quantum (hash-based) -----------
        add(m, "verifyWOTS",                new String[][]{{"msg", "ByteString"}, {"sig", "ByteString"}, {"pubkey", "ByteString"}}, "boolean");
        add(m, "verifySLHDSA_SHA2_128s",    new String[][]{{"msg", "ByteString"}, {"sig", "ByteString"}, {"pubkey", "ByteString"}}, "boolean");
        add(m, "verifySLHDSA_SHA2_128f",    new String[][]{{"msg", "ByteString"}, {"sig", "ByteString"}, {"pubkey", "ByteString"}}, "boolean");
        add(m, "verifySLHDSA_SHA2_192s",    new String[][]{{"msg", "ByteString"}, {"sig", "ByteString"}, {"pubkey", "ByteString"}}, "boolean");
        add(m, "verifySLHDSA_SHA2_192f",    new String[][]{{"msg", "ByteString"}, {"sig", "ByteString"}, {"pubkey", "ByteString"}}, "boolean");
        add(m, "verifySLHDSA_SHA2_256s",    new String[][]{{"msg", "ByteString"}, {"sig", "ByteString"}, {"pubkey", "ByteString"}}, "boolean");
        add(m, "verifySLHDSA_SHA2_256f",    new String[][]{{"msg", "ByteString"}, {"sig", "ByteString"}, {"pubkey", "ByteString"}}, "boolean");

        // ---------------- byte-string operations --------------
        add(m, "len",             new String[][]{{"data", "ByteString"}}, "bigint");
        add(m, "cat",             new String[][]{{"a", "ByteString"}, {"b", "ByteString"}}, "ByteString");
        add(m, "substr",          new String[][]{{"data", "ByteString"}, {"start", "bigint"}, {"len", "bigint"}}, "ByteString");
        add(m, "left",            new String[][]{{"data", "ByteString"}, {"len", "bigint"}}, "ByteString");
        add(m, "right",           new String[][]{{"data", "ByteString"}, {"len", "bigint"}}, "ByteString");
        add(m, "split",           new String[][]{{"data", "ByteString"}, {"index", "bigint"}}, "ByteString");
        add(m, "reverseBytes",    new String[][]{{"data", "ByteString"}}, "ByteString");

        // ---------------- conversion --------------------------
        add(m, "num2bin",         new String[][]{{"value", "bigint"}, {"byteLen", "bigint"}}, "ByteString");
        add(m, "bin2num",         new String[][]{{"data", "ByteString"}}, "bigint");
        add(m, "int2str",         new String[][]{{"value", "bigint"}, {"byteLen", "bigint"}}, "ByteString");
        add(m, "toByteString",    new String[][]{{"data", "ByteString"}}, "ByteString");
        add(m, "pack",            new String[][]{{"value", "bigint"}}, "ByteString");
        add(m, "unpack",          new String[][]{{"data", "ByteString"}}, "bigint");

        // ---------------- assertion ---------------------------
        // assert accepts 1 or 2 args (condition, optional message); we model
        // the 1-arg form and the type-checker special-cases the optional 2nd
        // argument. Java's `assertThat` maps to this builtin at parse time;
        // both names are accepted.
        add(m, "assert",          new String[][]{{"condition", "boolean"}}, "void");
        add(m, "assertThat",      new String[][]{{"condition", "boolean"}}, "void");
        add(m, "exit",            new String[][]{{"condition", "boolean"}}, "void");

        // ---------------- math --------------------------------
        add(m, "abs",             new String[][]{{"value", "bigint"}}, "bigint");
        add(m, "min",             new String[][]{{"a", "bigint"}, {"b", "bigint"}}, "bigint");
        add(m, "max",             new String[][]{{"a", "bigint"}, {"b", "bigint"}}, "bigint");
        add(m, "within",          new String[][]{{"value", "bigint"}, {"min", "bigint"}, {"max", "bigint"}}, "boolean");
        add(m, "safediv",         new String[][]{{"a", "bigint"}, {"b", "bigint"}}, "bigint");
        add(m, "safemod",         new String[][]{{"a", "bigint"}, {"b", "bigint"}}, "bigint");
        add(m, "clamp",           new String[][]{{"value", "bigint"}, {"lo", "bigint"}, {"hi", "bigint"}}, "bigint");
        add(m, "sign",            new String[][]{{"value", "bigint"}}, "bigint");
        add(m, "pow",             new String[][]{{"base", "bigint"}, {"exp", "bigint"}}, "bigint");
        add(m, "mulDiv",          new String[][]{{"a", "bigint"}, {"b", "bigint"}, {"c", "bigint"}}, "bigint");
        add(m, "percentOf",       new String[][]{{"amount", "bigint"}, {"bps", "bigint"}}, "bigint");
        add(m, "sqrt",            new String[][]{{"n", "bigint"}}, "bigint");
        add(m, "gcd",             new String[][]{{"a", "bigint"}, {"b", "bigint"}}, "bigint");
        add(m, "divmod",          new String[][]{{"a", "bigint"}, {"b", "bigint"}}, "bigint");
        add(m, "log2",            new String[][]{{"n", "bigint"}}, "bigint");
        add(m, "bool",            new String[][]{{"value", "bigint"}}, "boolean");

        // ---------------- secp256k1 ---------------------------
        add(m, "ecAdd",              new String[][]{{"a", "Point"}, {"b", "Point"}}, "Point");
        add(m, "ecMul",              new String[][]{{"p", "Point"}, {"k", "bigint"}}, "Point");
        add(m, "ecMulGen",           new String[][]{{"k", "bigint"}}, "Point");
        add(m, "ecNegate",           new String[][]{{"p", "Point"}}, "Point");
        add(m, "ecOnCurve",          new String[][]{{"p", "Point"}}, "boolean");
        add(m, "ecModReduce",        new String[][]{{"value", "bigint"}, {"mod", "bigint"}}, "bigint");
        add(m, "ecEncodeCompressed", new String[][]{{"p", "Point"}}, "ByteString");
        add(m, "ecMakePoint",        new String[][]{{"x", "bigint"}, {"y", "bigint"}}, "Point");
        add(m, "ecPointX",           new String[][]{{"p", "Point"}}, "bigint");
        add(m, "ecPointY",           new String[][]{{"p", "Point"}}, "bigint");

        // ---------------- P-256 ------------------------------
        add(m, "p256Add",              new String[][]{{"a", "P256Point"}, {"b", "P256Point"}}, "P256Point");
        add(m, "p256Mul",              new String[][]{{"p", "P256Point"}, {"k", "bigint"}}, "P256Point");
        add(m, "p256MulGen",           new String[][]{{"k", "bigint"}}, "P256Point");
        add(m, "p256Negate",           new String[][]{{"p", "P256Point"}}, "P256Point");
        add(m, "p256OnCurve",          new String[][]{{"p", "P256Point"}}, "boolean");
        add(m, "p256EncodeCompressed", new String[][]{{"p", "P256Point"}}, "ByteString");
        add(m, "verifyECDSA_P256",     new String[][]{{"msg", "ByteString"}, {"sig", "ByteString"}, {"pubkey", "ByteString"}}, "boolean");

        // ---------------- P-384 ------------------------------
        add(m, "p384Add",              new String[][]{{"a", "P384Point"}, {"b", "P384Point"}}, "P384Point");
        add(m, "p384Mul",              new String[][]{{"p", "P384Point"}, {"k", "bigint"}}, "P384Point");
        add(m, "p384MulGen",           new String[][]{{"k", "bigint"}}, "P384Point");
        add(m, "p384Negate",           new String[][]{{"p", "P384Point"}}, "P384Point");
        add(m, "p384OnCurve",          new String[][]{{"p", "P384Point"}}, "boolean");
        add(m, "p384EncodeCompressed", new String[][]{{"p", "P384Point"}}, "ByteString");
        add(m, "verifyECDSA_P384",     new String[][]{{"msg", "ByteString"}, {"sig", "ByteString"}, {"pubkey", "ByteString"}}, "boolean");

        // ---------------- BabyBear base field -----------------
        add(m, "bbFieldAdd",      new String[][]{{"a", "bigint"}, {"b", "bigint"}}, "bigint");
        add(m, "bbFieldSub",      new String[][]{{"a", "bigint"}, {"b", "bigint"}}, "bigint");
        add(m, "bbFieldMul",      new String[][]{{"a", "bigint"}, {"b", "bigint"}}, "bigint");
        add(m, "bbFieldInv",      new String[][]{{"a", "bigint"}}, "bigint");

        // ---------------- BabyBear Ext4 -----------------------
        String[][] ext4MulParams = new String[][]{
            {"a0", "bigint"}, {"a1", "bigint"}, {"a2", "bigint"}, {"a3", "bigint"},
            {"b0", "bigint"}, {"b1", "bigint"}, {"b2", "bigint"}, {"b3", "bigint"}
        };
        String[][] ext4InvParams = new String[][]{
            {"a0", "bigint"}, {"a1", "bigint"}, {"a2", "bigint"}, {"a3", "bigint"}
        };
        add(m, "bbExt4Mul0", ext4MulParams, "bigint");
        add(m, "bbExt4Mul1", ext4MulParams, "bigint");
        add(m, "bbExt4Mul2", ext4MulParams, "bigint");
        add(m, "bbExt4Mul3", ext4MulParams, "bigint");
        add(m, "bbExt4Inv0", ext4InvParams, "bigint");
        add(m, "bbExt4Inv1", ext4InvParams, "bigint");
        add(m, "bbExt4Inv2", ext4InvParams, "bigint");
        add(m, "bbExt4Inv3", ext4InvParams, "bigint");

        // ---------------- KoalaBear base field ----------------
        add(m, "kbFieldAdd",      new String[][]{{"a", "bigint"}, {"b", "bigint"}}, "bigint");
        add(m, "kbFieldSub",      new String[][]{{"a", "bigint"}, {"b", "bigint"}}, "bigint");
        add(m, "kbFieldMul",      new String[][]{{"a", "bigint"}, {"b", "bigint"}}, "bigint");
        add(m, "kbFieldInv",      new String[][]{{"a", "bigint"}}, "bigint");

        // ---------------- KoalaBear Ext4 ----------------------
        add(m, "kbExt4Mul0", ext4MulParams, "bigint");
        add(m, "kbExt4Mul1", ext4MulParams, "bigint");
        add(m, "kbExt4Mul2", ext4MulParams, "bigint");
        add(m, "kbExt4Mul3", ext4MulParams, "bigint");
        add(m, "kbExt4Inv0", ext4InvParams, "bigint");
        add(m, "kbExt4Inv1", ext4InvParams, "bigint");
        add(m, "kbExt4Inv2", ext4InvParams, "bigint");
        add(m, "kbExt4Inv3", ext4InvParams, "bigint");

        // ---------------- BN254 base field --------------------
        add(m, "bn254FieldAdd",   new String[][]{{"a", "bigint"}, {"b", "bigint"}}, "bigint");
        add(m, "bn254FieldSub",   new String[][]{{"a", "bigint"}, {"b", "bigint"}}, "bigint");
        add(m, "bn254FieldMul",   new String[][]{{"a", "bigint"}, {"b", "bigint"}}, "bigint");
        add(m, "bn254FieldInv",   new String[][]{{"a", "bigint"}}, "bigint");
        add(m, "bn254FieldNeg",   new String[][]{{"a", "bigint"}}, "bigint");

        // ---------------- BN254 G1 ----------------------------
        add(m, "bn254G1Add",      new String[][]{{"p1", "Point"}, {"p2", "Point"}}, "Point");
        add(m, "bn254G1ScalarMul",new String[][]{{"p", "Point"}, {"s", "bigint"}}, "Point");
        add(m, "bn254G1Negate",   new String[][]{{"p", "Point"}}, "Point");
        add(m, "bn254G1OnCurve",  new String[][]{{"p", "Point"}}, "boolean");

        // ---------------- Merkle ------------------------------
        add(m, "merkleRootSha256",  new String[][]{{"leaf", "ByteString"}, {"proof", "ByteString"}, {"index", "bigint"}, {"depth", "bigint"}}, "ByteString");
        add(m, "merkleRootHash256", new String[][]{{"leaf", "ByteString"}, {"proof", "ByteString"}, {"index", "bigint"}, {"depth", "bigint"}}, "ByteString");

        // ---------------- sighash preimage extractors ---------
        // These are surface-level helpers exposed through the Rúnar grammar;
        // the Python reference keeps them alongside the builtins and the
        // type-checker treats them identically.
        add(m, "extractVersion",       new String[][]{{"preimage", "SigHashPreimage"}}, "bigint");
        add(m, "extractHashPrevouts",  new String[][]{{"preimage", "SigHashPreimage"}}, "Sha256");
        add(m, "extractHashSequence",  new String[][]{{"preimage", "SigHashPreimage"}}, "Sha256");
        add(m, "extractOutpoint",      new String[][]{{"preimage", "SigHashPreimage"}}, "ByteString");
        add(m, "extractInputIndex",    new String[][]{{"preimage", "SigHashPreimage"}}, "bigint");
        add(m, "extractScriptCode",    new String[][]{{"preimage", "SigHashPreimage"}}, "ByteString");
        add(m, "extractAmount",        new String[][]{{"preimage", "SigHashPreimage"}}, "bigint");
        add(m, "extractSequence",      new String[][]{{"preimage", "SigHashPreimage"}}, "bigint");
        add(m, "extractOutputHash",    new String[][]{{"preimage", "SigHashPreimage"}}, "Sha256");
        add(m, "extractOutputs",       new String[][]{{"preimage", "SigHashPreimage"}}, "Sha256");
        add(m, "extractLocktime",      new String[][]{{"preimage", "SigHashPreimage"}}, "bigint");
        add(m, "extractSigHashType",   new String[][]{{"preimage", "SigHashPreimage"}}, "bigint");
        add(m, "buildChangeOutput",    new String[][]{{"pubKeyHash", "ByteString"}, {"amount", "bigint"}}, "ByteString");

        SIGNATURES = Collections.unmodifiableMap(m);
    }

    private static void add(
        Map<String, Signature> map,
        String name,
        String[][] params,
        String returnType
    ) {
        Param[] pa = new Param[params.length];
        for (int i = 0; i < params.length; i++) {
            pa[i] = new Param(params[i][0], params[i][1]);
        }
        map.put(name, new Signature(name, List.of(pa), returnType, true));
    }

    // ------------------------------------------------------------------
    // Public API
    // ------------------------------------------------------------------

    /** Return the signature for a builtin, or empty if unknown. */
    public static Optional<Signature> lookup(String name) {
        return Optional.ofNullable(SIGNATURES.get(name));
    }

    /** Return {@code true} iff {@code name} names a known Rúnar builtin. */
    public static boolean isBuiltin(String name) {
        return SIGNATURES.containsKey(name);
    }

    /** All known builtin names, in insertion order. */
    public static Iterable<String> names() {
        return SIGNATURES.keySet();
    }

    /** Total number of registered builtins (including aliases). */
    public static int size() {
        return SIGNATURES.size();
    }
}
