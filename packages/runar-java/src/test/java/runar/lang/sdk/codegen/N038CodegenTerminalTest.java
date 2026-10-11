package runar.lang.sdk.codegen;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Method;
import java.util.List;

import org.junit.jupiter.api.Test;

import runar.lang.sdk.RunarArtifact.ABIMethod;
import runar.lang.sdk.RunarArtifact.ABIParam;

/**
 * N-038: a stateful SIGHASH_SINGLE method declares no {@code _changePKH} (BIP-143
 * SINGLE does not commit the change output) and the compiler writes
 * {@code isTerminal} only when true, so the typed generator's terminal fallback
 * must not read the missing change param as "terminal".
 *
 * Proves: SINGLE (0x43, 0xc3) with no isTerminal is a continuation; an explicit
 * isTerminal still wins; the default-mode fallback is unchanged. Does not prove:
 * the generated wrapper compiles or spends (TypedContractGeneratorTest and the
 * N038SighashSingleCallTest vector cover the call path).
 */
class N038CodegenTerminalTest {

    private static boolean isTerminal(ABIMethod m) throws Exception {
        Method f = TypedContractGenerator.class.getDeclaredMethod("isTerminal", ABIMethod.class, boolean.class);
        f.setAccessible(true);
        return (Boolean) f.invoke(null, m, true);
    }

    private static final List<ABIParam> PREIMAGE_ONLY =
        List.of(new ABIParam("txPreimage", "SigHashPreimage", null));

    @Test
    void singleMethodWithoutChangeParamsIsAContinuation() throws Exception {
        for (int st : new int[] {0x43, 0xc3}) {
            assertFalse(isTerminal(new ABIMethod("bump", PREIMAGE_ONLY, true, null, true, st)));
            assertTrue(isTerminal(new ABIMethod("bump", PREIMAGE_ONLY, true, true, true, st)));
        }
    }

    @Test
    void defaultModeFallbackIsUnchanged() throws Exception {
        assertTrue(isTerminal(new ABIMethod("close", PREIMAGE_ONLY, true, null, true, null)));
        List<ABIParam> withChange = List.of(
            new ABIParam("_changePKH", "Ripemd160", null),
            new ABIParam("_changeAmount", "bigint", null),
            new ABIParam("txPreimage", "SigHashPreimage", null));
        assertFalse(isTerminal(new ABIMethod("bump", withChange, true, null, true, null)));
    }
}
