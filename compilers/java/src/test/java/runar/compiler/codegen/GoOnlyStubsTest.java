package runar.compiler.codegen;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import runar.compiler.ir.stack.StackOp;

/**
 * Module-presence parity tests for the seven Go-only Mode-3 STARK / FRI /
 * Groth16 verifier codegen stubs:
 * {@link BabyBear}, {@link KoalaBear}, {@link Poseidon2KoalaBear},
 * {@link Poseidon2Merkle}, {@link Bn254}, {@link Merkle},
 * {@link FiatShamirKb}.
 *
 * <p>Per CLAUDE.md ("Go-only crypto codegen modules") these families are
 * NOT conformance targets for the Java tier. The stub modules exist so
 * that {@code compilers/java/src/main/java/runar/compiler/codegen/} has
 * the same module surface as the other five non-Go tiers (TS, Rust,
 * Python, Zig, Ruby). Each module advertises its builtin name set via
 * {@code isXxxBuiltin(String)} and rejects {@code dispatch(...)} calls
 * with {@link UnsupportedOperationException}.
 */
class GoOnlyStubsTest {

    // No-op stack-op sink — dispatch() throws before the sink is ever invoked.
    private static final java.util.function.Consumer<StackOp> SINK = op -> {};

    // ----- BabyBear -------------------------------------------------------

    @Test
    void babyBearRecognisesItsBuiltins() {
        assertTrue(BabyBear.isBabyBearBuiltin("bbFieldAdd"));
        assertTrue(BabyBear.isBabyBearBuiltin("bbFieldSub"));
        assertTrue(BabyBear.isBabyBearBuiltin("bbFieldMul"));
        assertTrue(BabyBear.isBabyBearBuiltin("bbFieldInv"));
        assertTrue(BabyBear.isBabyBearBuiltin("bbExt4Mul0"));
        assertTrue(BabyBear.isBabyBearBuiltin("bbExt4Mul3"));
        assertTrue(BabyBear.isBabyBearBuiltin("bbExt4Inv0"));
        assertTrue(BabyBear.isBabyBearBuiltin("bbExt4Inv3"));
    }

    @Test
    void babyBearRejectsForeignNames() {
        assertFalse(BabyBear.isBabyBearBuiltin("kbFieldAdd"));
        assertFalse(BabyBear.isBabyBearBuiltin("sha256"));
        assertFalse(BabyBear.isBabyBearBuiltin(""));
        assertFalse(BabyBear.isBabyBearBuiltin("bbExt4Mul4")); // out of range
    }

    @Test
    void babyBearDispatchThrows() {
        UnsupportedOperationException ex = assertThrows(
            UnsupportedOperationException.class,
            () -> BabyBear.dispatch("bbFieldAdd", SINK));
        assertNotNull(ex.getMessage());
        assertTrue(ex.getMessage().contains("BabyBear"),
            "exception message should name the BabyBear family: " + ex.getMessage());
        assertTrue(ex.getMessage().contains("CLAUDE.md"),
            "exception message should reference CLAUDE.md");
    }

    @Test
    void babyBearConstants() {
        // p = 2^31 - 2^27 + 1
        assertEquals(2013265921L, BabyBear.BB_P);
        assertEquals(BabyBear.BB_P - 2L, BabyBear.BB_P_MINUS_2);
        assertEquals(11L, BabyBear.BB_W);
    }

    // ----- KoalaBear ------------------------------------------------------

    @Test
    void koalaBearRecognisesItsBuiltins() {
        assertTrue(KoalaBear.isKoalaBearBuiltin("kbFieldAdd"));
        assertTrue(KoalaBear.isKoalaBearBuiltin("kbFieldInv"));
        assertTrue(KoalaBear.isKoalaBearBuiltin("kbExt4Mul0"));
        assertTrue(KoalaBear.isKoalaBearBuiltin("kbExt4Inv3"));
    }

    @Test
    void koalaBearRejectsForeignNames() {
        assertFalse(KoalaBear.isKoalaBearBuiltin("bbFieldAdd"));
        assertFalse(KoalaBear.isKoalaBearBuiltin("bn254FieldAdd"));
    }

    @Test
    void koalaBearDispatchThrows() {
        UnsupportedOperationException ex = assertThrows(
            UnsupportedOperationException.class,
            () -> KoalaBear.dispatch("kbFieldMul", SINK));
        assertTrue(ex.getMessage().contains("KoalaBear"));
    }

    @Test
    void koalaBearConstants() {
        // p = 2^31 - 2^24 + 1
        assertEquals(2130706433L, KoalaBear.KB_P);
        assertEquals(KoalaBear.KB_P - 2L, KoalaBear.KB_P_MINUS_2);
        assertEquals(3L, KoalaBear.KB_W);
    }

    // ----- Poseidon2KoalaBear --------------------------------------------

    @Test
    void poseidon2KoalaBearHasNoUserBuiltins() {
        // Poseidon2-KB is driver-only; no top-level builtin name routes here.
        assertFalse(Poseidon2KoalaBear.isPoseidon2KoalaBearBuiltin("merkleRootPoseidon2KB"));
        assertFalse(Poseidon2KoalaBear.isPoseidon2KoalaBearBuiltin("poseidon2Permute"));
        assertFalse(Poseidon2KoalaBear.isPoseidon2KoalaBearBuiltin(""));
    }

    @Test
    void poseidon2KoalaBearDispatchThrows() {
        UnsupportedOperationException ex = assertThrows(
            UnsupportedOperationException.class,
            () -> Poseidon2KoalaBear.dispatch("poseidon2Permute", SINK));
        assertTrue(ex.getMessage().contains("Poseidon2-KoalaBear"));
    }

    @Test
    void poseidon2KoalaBearConstants() {
        assertEquals(16, Poseidon2KoalaBear.POSEIDON2_KB_WIDTH);
        assertEquals(8, Poseidon2KoalaBear.POSEIDON2_KB_EXTERNAL_ROUNDS);
        assertEquals(20, Poseidon2KoalaBear.POSEIDON2_KB_INTERNAL_ROUNDS);
        assertEquals(28, Poseidon2KoalaBear.POSEIDON2_KB_TOTAL_ROUNDS);
    }

    // ----- Poseidon2Merkle ------------------------------------------------

    @Test
    void poseidon2MerkleRecognisesItsBuiltin() {
        assertTrue(Poseidon2Merkle.isPoseidon2MerkleBuiltin("merkleRootPoseidon2KB"));
    }

    @Test
    void poseidon2MerkleRejectsForeignNames() {
        assertFalse(Poseidon2Merkle.isPoseidon2MerkleBuiltin("merkleRootSha256"));
        assertFalse(Poseidon2Merkle.isPoseidon2MerkleBuiltin("merkleRootHash256"));
    }

    @Test
    void poseidon2MerkleDispatchThrows() {
        UnsupportedOperationException ex = assertThrows(
            UnsupportedOperationException.class,
            () -> Poseidon2Merkle.dispatch("merkleRootPoseidon2KB", SINK));
        assertTrue(ex.getMessage().contains("Poseidon2-Merkle"));
    }

    @Test
    void poseidon2MerkleDepthBounds() {
        assertEquals(1, Poseidon2Merkle.MIN_DEPTH);
        assertEquals(32, Poseidon2Merkle.MAX_DEPTH);
    }

    // ----- Bn254 ----------------------------------------------------------

    @Test
    void bn254RecognisesFieldAndCurveBuiltins() {
        assertTrue(Bn254.isBn254Builtin("bn254FieldAdd"));
        assertTrue(Bn254.isBn254Builtin("bn254FieldNeg"));
        assertTrue(Bn254.isBn254Builtin("bn254G1Add"));
        assertTrue(Bn254.isBn254Builtin("bn254G1OnCurve"));
        assertTrue(Bn254.isBn254Builtin("bn254Pairing"));
        assertTrue(Bn254.isBn254Builtin("bn254MultiPairing3"));
        assertTrue(Bn254.isBn254Builtin("bn254MultiPairing4"));
    }

    @Test
    void bn254RecognisesGroth16Helpers() {
        assertTrue(Bn254.isBn254Builtin("assertGroth16WitnessAssisted"));
        assertTrue(Bn254.isBn254Builtin("assertGroth16WitnessAssistedWithMSM"));
        assertTrue(Bn254.isBn254Builtin("groth16PublicInput"));
    }

    @Test
    void bn254RejectsForeignNames() {
        assertFalse(Bn254.isBn254Builtin("bbFieldAdd"));
        assertFalse(Bn254.isBn254Builtin("ecAdd")); // secp256k1, distinct module
        assertFalse(Bn254.isBn254Builtin("p256Add"));
    }

    @Test
    void bn254DispatchThrows() {
        UnsupportedOperationException ex = assertThrows(
            UnsupportedOperationException.class,
            () -> Bn254.dispatch("bn254Pairing", SINK));
        assertTrue(ex.getMessage().contains("BN254"));
    }

    @Test
    void bn254FieldPrimeHasCorrectLeadingBytes() {
        // p = 0x30644e72...fd47 (big-endian)
        assertEquals(32, Bn254.BN254_FIELD_P_BE.length);
        assertEquals((byte) 0x30, Bn254.BN254_FIELD_P_BE[0]);
        assertEquals((byte) 0x64, Bn254.BN254_FIELD_P_BE[1]);
        assertEquals((byte) 0x47, Bn254.BN254_FIELD_P_BE[31]);
    }

    @Test
    void bn254CurveOrderHasCorrectTrailingByte() {
        // r = 0x...f0000001 (big-endian)
        assertEquals(32, Bn254.BN254_CURVE_R_BE.length);
        assertEquals((byte) 0x30, Bn254.BN254_CURVE_R_BE[0]);
        assertEquals((byte) 0x01, Bn254.BN254_CURVE_R_BE[31]);
        assertEquals((byte) 0x00, Bn254.BN254_CURVE_R_BE[30]);
    }

    // ----- Merkle (sha256 single-hash variant) ----------------------------

    @Test
    void merkleRecognisesSha256Variant() {
        assertTrue(Merkle.isMerkleBuiltin("merkleRootSha256"));
    }

    @Test
    void merkleExcludesHash256Variant() {
        // Standard double-SHA-256 Bitcoin Merkle is NOT Go-only and is
        // intentionally not routed through this stub. See Merkle class javadoc.
        assertFalse(Merkle.isMerkleBuiltin("merkleRootHash256"));
        assertFalse(Merkle.isMerkleBuiltin("merkleRootPoseidon2KB"));
    }

    @Test
    void merkleDispatchThrows() {
        UnsupportedOperationException ex = assertThrows(
            UnsupportedOperationException.class,
            () -> Merkle.dispatch("merkleRootSha256", SINK));
        assertTrue(ex.getMessage().contains("sha256-Merkle"));
    }

    @Test
    void merkleDepthBounds() {
        assertEquals(1, Merkle.MIN_DEPTH);
        assertEquals(32, Merkle.MAX_DEPTH);
    }

    // ----- FiatShamirKb ---------------------------------------------------

    @Test
    void fiatShamirKbRecognisesSp1FriEntryPoint() {
        assertTrue(FiatShamirKb.isFiatShamirKbBuiltin("verifySP1FRI"));
    }

    @Test
    void fiatShamirKbRejectsForeignNames() {
        assertFalse(FiatShamirKb.isFiatShamirKbBuiltin("verifyWOTS"));
        assertFalse(FiatShamirKb.isFiatShamirKbBuiltin("checkSig"));
    }

    @Test
    void fiatShamirKbDispatchThrows() {
        UnsupportedOperationException ex = assertThrows(
            UnsupportedOperationException.class,
            () -> FiatShamirKb.dispatch("verifySP1FRI", SINK));
        assertTrue(ex.getMessage().contains("FiatShamir-KB"));
    }

    @Test
    void fiatShamirKbSpongeParameters() {
        assertEquals(16, FiatShamirKb.FS_SPONGE_WIDTH);
        assertEquals(8, FiatShamirKb.FS_SPONGE_RATE);
    }
}
