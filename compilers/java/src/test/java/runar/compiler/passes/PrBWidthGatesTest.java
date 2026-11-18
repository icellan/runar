package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * #180 / #213 / D13: a public method's fixed-width parameter is pinned to its
 * declared width at entry ({@code <copy> OP_SIZE <w> OP_NUMEQUALVERIFY OP_DROP}),
 * except a PubKey that only ever reaches checkSig / checkMultiSig / hash160.
 *
 * <p>Port of the TypeScript reference pins ({@code 05-stack-lower.ts},
 * {@code emitFixedWidthParamGate} / {@code paramNeedsWidthGate}). The expected
 * bytes are the TS tier's output for the same sources, in both fold modes.
 */
class PrBWidthGatesTest {

    private static final String LOCK =
        """
        import { StatefulSmartContract, cat, toByteString } from 'runar-lang';
        import type { Point } from 'runar-lang';
        class Lock extends StatefulSmartContract {
          n: bigint;
          constructor(n: bigint) { super(n); this.n = n; }
          public lock(p: Point) {
            this.addRawOutput(1000n, cat(cat(toByteString('40'), p), toByteString('87')));
            this.n = this.n + 1n;
          }
        }
        """;

    private static final String PAY_TO_KEY =
        """
        import { StatefulSmartContract, cat, toByteString } from 'runar-lang';
        import type { PubKey } from 'runar-lang';
        class PayToKey extends StatefulSmartContract {
          n: bigint;
          constructor(n: bigint) { super(n); this.n = n; }
          public pay(pk: PubKey) {
            this.addRawOutput(1000n, cat(cat(toByteString('21'), pk), toByteString('ac')));
            this.n = this.n + 1n;
          }
        }
        """;

    private static final String P2PKH =
        """
        import { SmartContract, assert, PubKey, Sig, Addr, hash160, checkSig } from 'runar-lang';
        class P2PKH extends SmartContract {
          readonly pubKeyHash: Addr;
          constructor(pubKeyHash: Addr) { super(pubKeyHash); this.pubKeyHash = pubKeyHash; }
          public unlock(sig: Sig, pubKey: PubKey) {
            assert(hash160(pubKey) === this.pubKeyHash);
            assert(checkSig(sig, pubKey));
          }
        }
        """;

    private static final String HELPER_P2PKH =
        """
        import { SmartContract, assert, checkSig, hash160 } from 'runar-lang';
        import type { PubKey, Sig, Addr } from 'runar-lang';
        class HelperP2PKH extends SmartContract {
          readonly pkh: Addr;
          constructor(pkh: Addr) { super(pkh); this.pkh = pkh; }
          private verify(s: Sig, k: PubKey): boolean { return checkSig(s, k); }
          public unlock(sig: Sig, pubKey: PubKey) {
            assert(hash160(pubKey) === this.pkh);
            assert(this.verify(sig, pubKey));
          }
        }
        """;

    private static String hex(String src, String file, boolean disable) throws Exception {
        return PipelineTestSupport.hex(src, file, disable).toLowerCase();
    }

    /** Occurrences of {@code sub} that start on a byte boundary. */
    private static int countAligned(String h, String sub) {
        int n = 0;
        for (int i = 0; i + sub.length() <= h.length(); i += 2) {
            if (h.startsWith(sub, i)) n++;
        }
        return n;
    }

    @Test
    void pointParamAndChangePkhAreWidthGated() throws Exception {
        for (boolean disable : new boolean[] {true, false}) {
            String h = hex(LOCK, "Lock.runar.ts", disable);
            assertTrue(h.contains("5379820140" + "9d75" + "5279820114" + "9d75"),
                "disableFold=" + disable + ": missing Point + _changePKH entry gates: " + h);
            for (String gate : new String[] {"8201409d", "8201149d"}) {
                assertEquals(1, countAligned(h, gate), "disableFold=" + disable + ": " + gate);
            }
        }
    }

    @Test
    void splicedPubKeyIsWidthGated() throws Exception {
        for (boolean disable : new boolean[] {true, false}) {
            String h = hex(PAY_TO_KEY, "PayToKey.runar.ts", disable);
            assertTrue(h.contains("5379820121" + "9d75"),
                "disableFold=" + disable + ": missing PubKey entry gate: " + h);
            assertEquals(1, countAligned(h, "8201219d"), "disableFold=" + disable);
        }
    }

    @Test
    void p2pkhStaysOnStandardTemplate() throws Exception {
        for (boolean disable : new boolean[] {true, false}) {
            assertEquals("76a90088ac", hex(P2PKH, "P2PKH.runar.ts", disable), "disableFold=" + disable);
        }
    }

    @Test
    void pubKeyVerifiedThroughPrivateHelperIsNotGated() throws Exception {
        for (boolean disable : new boolean[] {true, false}) {
            String h = hex(HELPER_P2PKH, "HelperP2PKH.runar.ts", disable);
            assertFalse(h.contains("8201219d"), "disableFold=" + disable + ": " + h);
        }
    }

    private static final String PICK_KEY =
        """
        import { StatefulSmartContract, cat, toByteString } from 'runar-lang';
        import type { PubKey } from 'runar-lang';
        class PickKey extends StatefulSmartContract {
          n: bigint;
          constructor(n: bigint) { super(n); this.n = n; }
          public pay(pick: boolean, a: PubKey, b: PubKey) {
            const k = pick ? a : b;
            this.addRawOutput(1000n, cat(cat(toByteString('21'), k), toByteString('ac')));
            this.n = this.n + 1n;
          }
        }
        """;

    private static final String ID_KEY =
        """
        import { StatefulSmartContract, cat, toByteString } from 'runar-lang';
        import type { PubKey } from 'runar-lang';
        class IdKey extends StatefulSmartContract {
          n: bigint;
          constructor(n: bigint) { super(n); this.n = n; }
          private id(k: PubKey): PubKey { return k; }
          public pay(pk: PubKey) {
            this.addRawOutput(1000n, cat(cat(toByteString('21'), this.id(pk)), toByteString('ac')));
            this.n = this.n + 1n;
          }
        }
        """;

    @Test
    void pubKeyThroughTernaryArmIsWidthGated() throws Exception {
        for (boolean disable : new boolean[] {true, false}) {
            String h = hex(PICK_KEY, "PickKey.runar.ts", disable);
            assertEquals(2, countAligned(h, "8201219d"), "disableFold=" + disable + ": " + h);
        }
    }

    @Test
    void pubKeyReturnedByPrivateHelperIsWidthGated() throws Exception {
        for (boolean disable : new boolean[] {true, false}) {
            String h = hex(ID_KEY, "IdKey.runar.ts", disable);
            assertEquals(1, countAligned(h, "8201219d"), "disableFold=" + disable + ": " + h);
        }
    }
    private static final String MERGED_KEY = """
        import { StatefulSmartContract, assert } from 'runar-lang';
        import type { PubKey } from 'runar-lang';
        class MergedKey extends StatefulSmartContract {
          closed: bigint = 0n;
          k: PubKey = "000000000000000000000000000000000000000000000000000000000000000000" as PubKey;
          amt: bigint = 0n;
          constructor(seed: bigint) { super(seed); this.closed = seed; }
          public bid(bidderKey: PubKey, bidAmount: bigint) {
            assert(this.closed === 0n);
            let nk = this.k;
            let namt = this.amt;
            if (this.amt === 0n) { nk = bidderKey; namt = bidAmount; }
            else { nk = bidderKey; namt = bidAmount + 1n; }
            this.addOutput(bidAmount, this.closed, nk, namt);
          }
        }
        """;

    @Test
    void cyclicMergedLocalAliasTerminatesAndIsGated() throws Exception {
        for (boolean disable : new boolean[] {true, false}) {
            String h = hex(MERGED_KEY, "MergedKey.runar.ts", disable);
            assertTrue(h.contains("5479820121" + "9d75"), "disableFold=" + disable + ": " + h);
            assertEquals(2, countAligned(h, "8201219d"), "disableFold=" + disable + ": " + h);
        }
    }
}
