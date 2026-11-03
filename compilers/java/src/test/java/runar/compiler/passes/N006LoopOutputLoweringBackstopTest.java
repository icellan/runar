package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import runar.compiler.frontend.ParserDispatch;
import runar.compiler.ir.ast.ContractNode;

/**
 * N-006 / CL-BUG-186 — the pass-4 backstop behind R-127.
 *
 * <p>R-127 is a syntactic search in {@link Validate}. {@link AnfLower#run} is
 * public, so a caller can lower a parsed contract having run no validator at
 * all, and {@code lowerForStatement} used to drop the body sub-context's output
 * refs without a word: the loop's outputs were built but left out of the
 * continuation hash, so a spender could drop them (proven on @bsv/sdk Spend for
 * the TS and Go tiers in
 * packages/runar-testing/src/__tests__/f005-go-loop-output-continuation.test.ts).
 *
 * <p>What this proves: this tier's pass 4 refuses a loop whose body registered
 * an output ref, with R-127's shared diagnostic, whatever let the contract past
 * passes 1-3; a loop with no output in it still lowers.
 * What it does not prove: anything about emitted bytes.
 */
class N006LoopOutputLoweringBackstopTest {

    private static final String HEAD = """
        import { StatefulSmartContract, ByteString, assert, num2bin } from 'runar-lang';

        class Fan extends StatefulSmartContract {
          count: bigint;

          constructor(count: bigint) {
            super(count);
            this.count = count;
          }
        """;

    private static ContractNode parse(String method) throws Exception {
        return ParserDispatch.parse(HEAD + method + "\n}\n", "Fan.runar.ts");
    }

    private static void assertRefused(String method, String intrinsic) throws Exception {
        ContractNode contract = parse(method);
        IllegalStateException e = assertThrows(
            IllegalStateException.class,
            () -> AnfLower.run(contract),
            "AnfLower accepted an output intrinsic inside a loop body");
        assertTrue(
            e.getMessage().contains(
                "Output intrinsic '" + intrinsic + "' cannot be called inside a loop body."),
            "refused, but not with the R-127 diagnostic: " + e.getMessage());
    }

    @Test
    void arrayLiteralRawOutputInLoopIsRefusedAtLowering() throws Exception {
        assertRefused("""
              public fan(n: bigint) {
                this.addOutput(1000n, this.count + 1n);
                for (let i = 0n; i < 2n; i++) {
                  const xs = [this.addRawOutput(n, num2bin(i, 4n))];
                }
              }
            """, "addRawOutput");
    }

    @Test
    void addOutputAndDataOutputInLoopAreRefusedAtLowering() throws Exception {
        assertRefused("""
              public fan(n: bigint) {
                this.addOutput(1000n, this.count);
                for (let i = 0n; i < 2n; i++) {
                  this.addOutput(1000n, this.count + i);
                }
                assert(n > 0n);
              }
            """, "addOutput");
        assertRefused("""
              public fan(n: bigint) {
                for (let i = 0n; i < 2n; i++) {
                  if (i < n) {
                    this.addDataOutput(0n, num2bin(i, 4n));
                  }
                }
                this.count = this.count + 1n;
              }
            """, "addDataOutput");
    }

    @Test
    void controlLoopWithoutOutputsStillLowers() throws Exception {
        ContractNode contract = parse("""
              public fan(n: bigint) {
                let acc: bigint = 0n;
                for (let i = 0n; i < 2n; i++) {
                  acc = acc + n;
                }
                this.addOutput(1000n, this.count + acc);
              }
            """);
        assertDoesNotThrow(() -> AnfLower.run(contract));
    }
}
