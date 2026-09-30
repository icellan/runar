package runar.compiler.frontend;

import org.junit.jupiter.api.Test;
import runar.compiler.ir.ast.ContractNode;
import runar.compiler.ir.ast.ParentClass;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * N-011 — which class in a {@code .runar.ts} file is the contract.
 *
 * <p>The TS reference ({@code packages/runar-compiler/src/passes/01-parse.ts})
 * walks EVERY class and keeps only one whose {@code extends} names a valid base
 * (SmartContract / StatefulSmartContract / UnsafeSmartContract): other classes
 * are ignored wherever they sit; each valid class after the first gets
 * "Only one SmartContract subclass is allowed per file" at its first token (the
 * LAST one is kept); no valid class gets "No class extending SmartContract,
 * StatefulSmartContract, or UnsafeSmartContract found" at 1:0.
 *
 * <p>Pre-fix {@code TsParser} returned on the FIRST {@code class} token and
 * defaulted a missing {@code extends} to SmartContract, so a leading helper was
 * compiled as the contract. In DECOY_FIRST the helper's {@code unlock} accepts
 * every preimage EXCEPT the real one. The real-engine proof is
 * {@code packages/runar-testing/src/__tests__/n011-ts-class-selection-vm.test.ts}.
 * Expected values were captured by running the TS reference on the same shapes.
 *
 * <p>What this proves: the Java .runar.ts parser picks the same class and parent
 * and emits the same diagnostics (message + line:column) as the TS reference on
 * the seven F-016 shapes. What it does NOT prove: the other Java-tier surfaces.
 */
class N011TsContractClassSelectionTest {

    static final String F = "Probe.runar.ts";
    static final String NO_CLASS =
        "No class extending SmartContract, StatefulSmartContract, or UnsafeSmartContract found";
    static final String ONLY_ONE = "Only one SmartContract subclass is allowed per file";

    static final String IMPORTS =
        "import { SmartContract, assert, ByteString, Sha256, sha256 } from 'runar-lang';\n\n";

    static final String HASHLOCK = """
        export class HashLock extends SmartContract {
          readonly hashValue: Sha256;

          constructor(hashValue: Sha256) {
            super(hashValue);
            this.hashValue = hashValue;
          }

          public unlock(preimage: ByteString) {
            assert(sha256(preimage) === this.hashValue);
          }
        }
        """;

    static final String DECOY = """
        class Helper {
          readonly hashValue: Sha256;

          constructor(hashValue: Sha256) {
            super(hashValue);
            this.hashValue = hashValue;
          }

          public unlock(preimage: ByteString) {
            assert(sha256(preimage) !== this.hashValue);
          }
        }
        """;

    static final String FOREIGN = DECOY.replace("class Helper {", "class Helper extends Base {");

    static final String TWO_VALID = IMPORTS + """
        export class First extends SmartContract {
          constructor() {
            super();
          }

          public unlock(preimage: ByteString) {
            assert(true);
          }
        }
        """ + "\n" + HASHLOCK;

    static final String THREE_VALID = """
        import { SmartContract, assert } from 'runar-lang';

        export class A extends SmartContract {
          constructor() { super(); }
          public unlock(x: bigint) { assert(x === 1n); }
        }
        export class B extends SmartContract {
          constructor() { super(); }
          public unlock(x: bigint) { assert(x === 2n); }
        }
        export class C extends SmartContract {
          constructor() { super(); }
          public unlock(x: bigint) { assert(x === 3n); }
        }
        """;

    private static void assertSelectsHashLock(String src) throws Exception {
        ContractNode c = TsParser.parse(src, F);
        assertEquals("HashLock", c.name());
        assertEquals(ParentClass.SMART_CONTRACT, c.parentClass());
    }

    private static String refusal(String src) {
        return assertThrows(TsParser.ParseException.class, () -> TsParser.parse(src, F)).getMessage();
    }

    @Test
    void decoyFirstSelectsTheExtendingClass() throws Exception {
        assertSelectsHashLock(IMPORTS + DECOY + "\n" + HASHLOCK);
    }

    @Test
    void foreignBaseFirstSelectsTheExtendingClass() throws Exception {
        assertSelectsHashLock(IMPORTS + FOREIGN + "\n" + HASHLOCK);
    }

    @Test
    void contractFirstThenHelper() throws Exception {
        assertSelectsHashLock(IMPORTS + HASHLOCK + "\n" + DECOY);
    }

    @Test
    void noExtendsOnlyIsRefused() {
        assertEquals(F + ":1:0: " + NO_CLASS, refusal(IMPORTS + DECOY));
    }

    @Test
    void foreignBaseOnlyIsRefused() {
        assertEquals(F + ":1:0: " + NO_CLASS, refusal(IMPORTS + FOREIGN));
    }

    @Test
    void twoValidReportsTheSecond() {
        assertEquals(F + ":13:0: " + ONLY_ONE, refusal(TWO_VALID));
    }

    @Test
    void threeValidReportsEachExtraClass() {
        assertEquals(F + ":7:0: " + ONLY_ONE + "\n" + F + ":11:0: " + ONLY_ONE, refusal(THREE_VALID));
    }
}
