package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/**
 * F-081 — {@code checkMultiSig(sigs, pks)} over arrays declared BEFORE an
 * {@code if} / loop must compile when the call sits inside it.
 *
 * <p>An {@code array_literal} binding is metadata only in {@link StackLower}
 * ({@code arrayLengths} / {@code arrayElements}); its elements stay individual
 * stack slots. Two things were lost at a scope boundary, in all seven tiers:
 *
 * <ol>
 *   <li>{@code subContext()} copied the stack, private methods, renamed params
 *       and the code-separator flag but NOT the array metadata, so a
 *       checkMultiSig in either arm threw
 *       {@code "checkMultiSig: array_literal metadata missing"};</li>
 *   <li>{@code computeLastUses} followed only the {@code array_literal}
 *       binding, not the {@code sigs = @ref:t} alias every frontend emits for
 *       {@code const sigs = [..]}, and an arm / loop body saw only its own
 *       bindings. The elements had no last-use and were consumed at the first
 *       read, so a second call failed with {@code "value 't0' not found"}.</li>
 * </ol>
 *
 * <p>Expected hex is the TypeScript reference, fold-OFF; the cross-tier
 * {@code packages/runar-testing/src/__tests__/f081-multisig-array-in-branch-vm.test.ts}
 * replays every tier's script on the real {@code @bsv/sdk} Spend engine
 * (honest 1-of-2 accepted, uncommitted-key signature rejected).
 *
 * <p>Proves: Java compiles each shape and emits the TS bytes. Does NOT prove
 * on-chain behaviour on its own (the cross-tier Spend test does), arrays
 * declared inside an arm and used after it, or hostile {@code --ir} input.
 */
class F081MultiSigArrayScopeTest {

    private static final String PRELUDE =
        """
        import { SmartContract, assert, PubKey, Sig, checkMultiSig } from 'runar-lang';

        class Probe extends SmartContract {
          readonly pk1: PubKey;
          readonly pk2: PubKey;

          constructor(pk1: PubKey, pk2: PubKey) {
            super(pk1, pk2);
            this.pk1 = pk1;
            this.pk2 = pk2;
          }

        """;
    private static final String CONTROL_STRAIGHT_LINE = PRELUDE +
        """
          public unlock(sig1: Sig, mode: bigint) {
            const sigs = [sig1];
            const pks = [this.pk1, this.pk2];
            assert(mode == 1n);
            assert(checkMultiSig(sigs, pks));
          }
        }
        """;
    private static final String STRAIGHT_LINE_REUSE = PRELUDE +
        """
          public unlock(sig1: Sig, mode: bigint) {
            const sigs = [sig1];
            const pks = [this.pk1, this.pk2];
            assert(mode == 1n);
            assert(checkMultiSig(sigs, pks));
            assert(checkMultiSig(sigs, pks));
          }
        }
        """;
    private static final String THEN_ARM = PRELUDE +
        """
          public unlock(sig1: Sig, mode: bigint) {
            const sigs = [sig1];
            const pks = [this.pk1, this.pk2];
            if (mode == 1n) {
              assert(checkMultiSig(sigs, pks));
            } else {
              assert(mode == 2n);
            }
          }
        }
        """;
    private static final String ELSE_ARM = PRELUDE +
        """
          public unlock(sig1: Sig, mode: bigint) {
            const sigs = [sig1];
            const pks = [this.pk1, this.pk2];
            if (mode == 2n) {
              assert(mode == 2n);
            } else {
              assert(checkMultiSig(sigs, pks));
            }
          }
        }
        """;
    private static final String NESTED_ARMS = PRELUDE +
        """
          public unlock(sig1: Sig, mode: bigint) {
            const sigs = [sig1];
            const pks = [this.pk1, this.pk2];
            if (mode > 0n) {
              if (mode == 1n) {
                assert(checkMultiSig(sigs, pks));
              } else {
                assert(mode == 2n);
              }
            } else {
              assert(false);
            }
          }
        }
        """;
    private static final String TWO_CALLS_ONE_ARM = PRELUDE +
        """
          public unlock(sig1: Sig, mode: bigint) {
            const sigs = [sig1];
            const pks = [this.pk1, this.pk2];
            if (mode == 1n) {
              assert(checkMultiSig(sigs, pks));
              assert(checkMultiSig(sigs, pks));
            } else {
              assert(mode == 2n);
            }
          }
        }
        """;
    private static final String TWO_ITERATION_LOOP = PRELUDE +
        """
          public unlock(sig1: Sig, mode: bigint) {
            const sigs = [sig1];
            const pks = [this.pk1, this.pk2];
            let ok = mode == 1n;
            for (let i = 0n; i < 2n; i++) {
              ok = ok && checkMultiSig(sigs, pks);
            }
            assert(ok);
          }
        }
        """;
    private static final String REUSED_AFTER_LOOP = PRELUDE +
        """
          public unlock(sig1: Sig, mode: bigint) {
            const sigs = [sig1];
            const pks = [this.pk1, this.pk2];
            let ok = mode == 1n;
            for (let i = 0n; i < 1n; i++) {
              ok = ok && checkMultiSig(sigs, pks);
            }
            assert(ok);
            assert(checkMultiSig(sigs, pks));
          }
        }
        """;
    private static String hex(String src) throws Exception {
        return PipelineTestSupport.hex(src, "Probe.runar.ts");
    }

    @Test
    void controlStraightLine() throws Exception {
        assertEquals("7c0000537a519d00537a51547a547a52ae", hex(CONTROL_STRAIGHT_LINE));
    }

    @Test
    void straightLineReuse() throws Exception {
        assertEquals("7c0000537a519d005379515479547952af00537a51547a547a52ae", hex(STRAIGHT_LINE_REUSE));
    }

    @Test
    void thenArm() throws Exception {
        assertEquals("7c00005379519c6300537a51547a547a52ae7767537a529c77777768", hex(THEN_ARM));
    }

    @Test
    void elseArm() throws Exception {
        assertEquals("7c00005379529c63537a529c7777776700537a51547a547a52ae7768", hex(ELSE_ARM));
    }

    @Test
    void nestedArms() throws Exception {
        assertEquals("7c0000537900a0635379519c6300537a51547a547a52ae7767537a529c7777776867007777777768", hex(NESTED_ARMS));
    }

    @Test
    void twoCallsOneArm() throws Exception {
        assertEquals("7c00005379519c63005379515479547952af00537a51547a547a52ae7767537a529c77777768", hex(TWO_CALLS_ONE_ARM));
    }

    @Test
    void twoIterationLoop() throws Exception {
        assertEquals("7c0000537a519c007c63005479515579557952ae67006877517c6300547a51557a557a52ae6700547a75537a757b756877", hex(TWO_ITERATION_LOOP));
    }

    @Test
    void reusedAfterLoop() throws Exception {
        assertEquals("7c0000537a519c007c63005479515579557952ae670068776900537a51547a547a52ae", hex(REUSED_AFTER_LOOP));
    }
}
