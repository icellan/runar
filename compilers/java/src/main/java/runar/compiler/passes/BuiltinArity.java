package runar.compiler.passes;

import java.util.List;
import java.util.Map;

/**
 * Builtin call arities, for validating ANF IR that never went through the
 * frontend (R-128 / R-165 family).
 *
 * <p>The source pipeline type-checks every call before codegen. {@code --ir}
 * runs no frontend at all, so a call with the wrong number of arguments used to
 * reach stack lowering, where each dispatch family consumes {@code args.size()}
 * from the stack MODEL and then emits a FIXED-arity opcode blob. Measured
 * through the six {@code --ir} CLIs on one file:
 *
 * <pre>
 *   cat(1 arg, needs 2)   go / ruby / rust / python / java compiled it to `7e`,
 *                         a bare OP_CAT with nothing beneath it
 *   assert(0 args)        the same five emitted an EMPTY script — the only
 *                         guard in the contract vanished, which is
 *                         anyone-can-spend, not merely wrong
 *                         (zig refused both, with InvalidBuiltin)
 * </pre>
 *
 * <p>This tier has no central builtin signature table to derive from — its
 * type-checker validates each family inline — so the counts are transcribed
 * from {@code compilers/go/ir/builtin_arity.go}, which is itself checked
 * against that tier's signature map by a drift test. The cross-tier gate is
 * {@code conformance/negatives/ir/} : every {@code I*.ir.json} must be refused
 * by all six tiers with an {@code --ir} mode, so a table that drifts here shows
 * up as an accepted negative rather than as silence.
 *
 * <p>Values are the ALLOWED argument counts. Two builtins accept more than one:
 * {@code assert} takes 1 or 2 (the optional message) and
 * {@code extractPrevOutputScript} takes 2 or 3 (the optional prefix length).
 * {@code merkleRootPoseidon2KB} is variadic by a rule and is handled in
 * {@link #check}.
 */
public final class BuiltinArity {

    private BuiltinArity() {}

    private static final Map<String, List<Integer>> ARITY = Map.ofEntries(
        Map.entry("abs", List.of(1)),
        Map.entry("assert", List.of(1, 2)),
        Map.entry("assertGroth16WitnessAssisted", List.of(0)),
        Map.entry("assertGroth16WitnessAssistedWithMSM", List.of(0)),
        Map.entry("bbExt4Inv0", List.of(4)),
        Map.entry("bbExt4Inv1", List.of(4)),
        Map.entry("bbExt4Inv2", List.of(4)),
        Map.entry("bbExt4Inv3", List.of(4)),
        Map.entry("bbExt4Mul0", List.of(8)),
        Map.entry("bbExt4Mul1", List.of(8)),
        Map.entry("bbExt4Mul2", List.of(8)),
        Map.entry("bbExt4Mul3", List.of(8)),
        Map.entry("bbFieldAdd", List.of(2)),
        Map.entry("bbFieldInv", List.of(1)),
        Map.entry("bbFieldMul", List.of(2)),
        Map.entry("bbFieldSub", List.of(2)),
        Map.entry("bin2num", List.of(1)),
        Map.entry("blake3Compress", List.of(2)),
        Map.entry("blake3Hash", List.of(1)),
        Map.entry("bn254FieldAdd", List.of(2)),
        Map.entry("bn254FieldInv", List.of(1)),
        Map.entry("bn254FieldMul", List.of(2)),
        Map.entry("bn254FieldNeg", List.of(1)),
        Map.entry("bn254FieldSub", List.of(2)),
        Map.entry("bn254G1Add", List.of(2)),
        Map.entry("bn254G1Negate", List.of(1)),
        Map.entry("bn254G1OnCurve", List.of(1)),
        Map.entry("bn254G1ScalarMul", List.of(2)),
        Map.entry("bn254MultiPairing3", List.of(27)),
        Map.entry("bn254MultiPairing4", List.of(20)),
        Map.entry("bn254Pairing", List.of(5)),
        Map.entry("bool", List.of(1)),
        Map.entry("buildChangeOutput", List.of(2)),
        Map.entry("cat", List.of(2)),
        Map.entry("checkMultiSig", List.of(2)),
        Map.entry("checkPreimage", List.of(1)),
        Map.entry("checkSig", List.of(2)),
        Map.entry("clamp", List.of(3)),
        Map.entry("currentBlockHeight", List.of(0)),
        Map.entry("divmod", List.of(2)),
        Map.entry("ecAdd", List.of(2)),
        Map.entry("ecEncodeCompressed", List.of(1)),
        Map.entry("ecMakePoint", List.of(2)),
        Map.entry("ecModReduce", List.of(2)),
        Map.entry("ecMul", List.of(2)),
        Map.entry("ecMulGen", List.of(1)),
        Map.entry("ecNegate", List.of(1)),
        Map.entry("ecOnCurve", List.of(1)),
        Map.entry("ecPointX", List.of(1)),
        Map.entry("ecPointY", List.of(1)),
        Map.entry("exit", List.of(1)),
        Map.entry("extractAmount", List.of(1)),
        Map.entry("extractHashPrevouts", List.of(1)),
        Map.entry("extractHashSequence", List.of(1)),
        Map.entry("extractInputIndex", List.of(1)),
        Map.entry("extractLocktime", List.of(1)),
        Map.entry("extractOutpoint", List.of(1)),
        Map.entry("extractOutputHash", List.of(1)),
        Map.entry("extractOutputs", List.of(1)),
        Map.entry("extractPrevOutputScript", List.of(2, 3)),
        Map.entry("extractScriptCode", List.of(1)),
        Map.entry("extractSequence", List.of(1)),
        Map.entry("extractSigHashType", List.of(1)),
        Map.entry("extractVersion", List.of(1)),
        Map.entry("gcd", List.of(2)),
        Map.entry("groth16PublicInput", List.of(1)),
        Map.entry("hash160", List.of(1)),
        Map.entry("hash256", List.of(1)),
        Map.entry("int2str", List.of(2)),
        Map.entry("kbExt4Inv0", List.of(4)),
        Map.entry("kbExt4Inv1", List.of(4)),
        Map.entry("kbExt4Inv2", List.of(4)),
        Map.entry("kbExt4Inv3", List.of(4)),
        Map.entry("kbExt4Mul0", List.of(8)),
        Map.entry("kbExt4Mul1", List.of(8)),
        Map.entry("kbExt4Mul2", List.of(8)),
        Map.entry("kbExt4Mul3", List.of(8)),
        Map.entry("kbFieldAdd", List.of(2)),
        Map.entry("kbFieldInv", List.of(1)),
        Map.entry("kbFieldMul", List.of(2)),
        Map.entry("kbFieldSub", List.of(2)),
        Map.entry("left", List.of(2)),
        Map.entry("len", List.of(1)),
        Map.entry("log2", List.of(1)),
        Map.entry("max", List.of(2)),
        Map.entry("merkleRootHash256", List.of(4)),
        Map.entry("merkleRootSha256", List.of(4)),
        Map.entry("min", List.of(2)),
        Map.entry("mulDiv", List.of(3)),
        Map.entry("num2bin", List.of(2)),
        Map.entry("p256Add", List.of(2)),
        Map.entry("p256EncodeCompressed", List.of(1)),
        Map.entry("p256Mul", List.of(2)),
        Map.entry("p256MulGen", List.of(1)),
        Map.entry("p256Negate", List.of(1)),
        Map.entry("p256OnCurve", List.of(1)),
        Map.entry("p384Add", List.of(2)),
        Map.entry("p384EncodeCompressed", List.of(1)),
        Map.entry("p384Mul", List.of(2)),
        Map.entry("p384MulGen", List.of(1)),
        Map.entry("p384Negate", List.of(1)),
        Map.entry("p384OnCurve", List.of(1)),
        Map.entry("pack", List.of(1)),
        Map.entry("percentOf", List.of(2)),
        Map.entry("pow", List.of(2)),
        Map.entry("requireOutputP2PKH", List.of(3)),
        Map.entry("reverseBytes", List.of(1)),
        Map.entry("right", List.of(2)),
        Map.entry("ripemd160", List.of(1)),
        Map.entry("safediv", List.of(2)),
        Map.entry("safemod", List.of(2)),
        Map.entry("sha256", List.of(1)),
        Map.entry("sha256Compress", List.of(2)),
        Map.entry("sha256Finalize", List.of(3)),
        Map.entry("sign", List.of(1)),
        Map.entry("split", List.of(2)),
        Map.entry("sqrt", List.of(1)),
        Map.entry("substr", List.of(3)),
        Map.entry("toByteString", List.of(1)),
        Map.entry("unpack", List.of(1)),
        Map.entry("verifyECDSA_P256", List.of(3)),
        Map.entry("verifyECDSA_P384", List.of(3)),
        Map.entry("verifyRabinSig", List.of(4)),
        Map.entry("verifySLHDSA_SHA2_128f", List.of(3)),
        Map.entry("verifySLHDSA_SHA2_128s", List.of(3)),
        Map.entry("verifySLHDSA_SHA2_192f", List.of(3)),
        Map.entry("verifySLHDSA_SHA2_192s", List.of(3)),
        Map.entry("verifySLHDSA_SHA2_256f", List.of(3)),
        Map.entry("verifySLHDSA_SHA2_256s", List.of(3)),
        Map.entry("verifySP1FRI", List.of(3)),
        Map.entry("verifyWOTS", List.of(3)),
        Map.entry("within", List.of(3)),
        Map.entry("__never__", List.of(0))
    );

    /**
     * Returns a diagnostic when {@code func} is a known builtin called with an
     * argument count it does not accept, or {@code null} when the call is fine
     * (or the name is not a builtin this table knows).
     */
    public static String check(String methodName, String bindingName, String func, int got) {
        if (func == null || func.isEmpty()) {
            return null;
        }
        if (func.equals("merkleRootPoseidon2KB")) {
            // 8 leaf elements + 8 per proof level + index + depth.
            if (got < 10) {
                return diagnostic(methodName, bindingName, func, got,
                    "at least 10 arguments (8 leaf + index + depth)");
            }
            if ((got - 10) % 8 != 0) {
                return diagnostic(methodName, bindingName, func, got, "8*depth + 10 arguments");
            }
            return null;
        }
        List<Integer> allowed = ARITY.get(func);
        if (allowed == null || allowed.contains(got)) {
            return null;
        }
        StringBuilder wanted = new StringBuilder();
        for (int i = 0; i < allowed.size(); i++) {
            if (i > 0) {
                wanted.append(i == allowed.size() - 1 ? " or " : ", ");
            }
            wanted.append(allowed.get(i));
        }
        return diagnostic(methodName, bindingName, func, got, wanted.toString());
    }

    private static String diagnostic(
        String methodName, String bindingName, String func, int got, String wanted
    ) {
        return "IR validation: method " + methodName + " binding " + bindingName
            + " calls " + func + "() with " + got + " argument(s); it takes " + wanted;
    }
}
