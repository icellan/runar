package runar.lang.sdk;

import java.math.BigInteger;
import java.util.List;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * N-223 — out-of-range constructorSlots paramIndex.
 *
 * <p>The constructor only checks {@code constructorArgs.size() ==
 * abi.constructor.params.size()} — it never cross-checks that every
 * {@link RunarArtifact.ConstructorSlot#paramIndex()} actually falls within
 * that range. Before this fix:
 * <ul>
 *   <li>{@link ContractScript#buildCodeScript} did {@code if (slot.paramIndex()
 *       >= constructorArgs.size()) continue;} — the OP_0 placeholder was left
 *       unfilled instead of being refused (the "Java silently skips the slot"
 *       bug named in this item's brief).</li>
 *   <li>{@link ContractScript#resolvedCodeSepSlots} and {@link
 *       RunarContract#adjustCodeSepOffset} (not in the brief's affected-files
 *       list, but reads the same unguarded array) skipped the shift
 *       contribution of an out-of-range slot the same way, silently computing
 *       the WRONG code-separator offset instead of refusing.</li>
 * </ul>
 *
 * <p>Parity target: TS N-081 / N-223 ({@code
 * packages/runar-sdk/src/__tests__/constructor-slots.test.ts}).
 */
class N223OutOfRangeParamIndexTest {

    private static RunarArtifact.ABI abi(List<RunarArtifact.ABIParam> ctorParams) {
        return new RunarArtifact.ABI(new RunarArtifact.ABIConstructor(ctorParams), List.of());
    }

    @Test
    void buildCodeScriptRefusesAnOutOfRangeParamIndex() {
        // Exactly 1 constructor arg below (matching the 1 ABI param), but the
        // slot references paramIndex 1 -- out of range.
        RunarArtifact artifact = new RunarArtifact(
            "1", "0.1.0", "Test",
            abi(List.of(new RunarArtifact.ABIParam("threshold", "bigint", null))),
            "009c69", // OP_0(slot) OP_NUMEQUAL OP_VERIFY
            "", "",
            List.of(),
            List.of(new RunarArtifact.ConstructorSlot(1, 0)),
            List.of(),
            null, null);

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
            () -> ContractScript.renderLockingScript(artifact, List.of(BigInteger.valueOf(1000)), null));
        assertTrue(ex.getMessage().contains("paramIndex"), "error must name paramIndex: " + ex.getMessage());
    }

    @Test
    void adjustCodeSepOffsetRefusesAnOutOfRangeParamIndex_reachedWithoutBuildCodeScript() {
        // getCodeSepIndex falls straight to adjustCodeSepOffset when no
        // currentUtxo is set (no live script to byte-walk instead) -- this
        // never calls buildCodeScript / renderLockingScript at all, proving
        // the gap the primary-site fix alone does not cover.
        RunarArtifact artifact = new RunarArtifact(
            "1", "0.1.0", "CodeSep",
            abi(List.of(new RunarArtifact.ABIParam("threshold", "bigint", null))),
            "00ab9c69", // OP_0(slot) OP_CODESEPARATOR OP_NUMEQUAL OP_VERIFY
            "", "",
            List.of(),
            List.of(new RunarArtifact.ConstructorSlot(1, 0)),
            List.of(),
            2, List.of(2));

        RunarContract contract = new RunarContract(artifact, List.of(BigInteger.valueOf(1000)));
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
            () -> contract.getCodeSepIndex(0));
        assertTrue(ex.getMessage().contains("paramIndex"), "error must name paramIndex: " + ex.getMessage());
    }
}
