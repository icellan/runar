package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * R-069: seven-tier builtin-coverage parity for the Java tier.
 *
 * <p>CLAUDE.md makes frontend parity an invariant with "no exceptions": a
 * contract that compiles in six tiers must compile in the seventh, to the same
 * bytes. A seven-tier probe sweep over every entry of {@code BUILTIN_FUNCTIONS}
 * (packages/runar-compiler/src/passes/03-typecheck.ts) found three builtins
 * that the TypeScript, Go, Rust, Python and Ruby tiers all lower and that the
 * Java tier rejected outright:
 *
 * <ul>
 *   <li>{@code right(data, n)} &mdash; "unknown builtin"</li>
 *   <li>{@code reverseBytes(data)} &mdash; "unknown builtin"</li>
 *   <li>{@code extractVersion(preimage)} &mdash; "unknown extractor"</li>
 * </ul>
 *
 * <p>Every expected hex below is the output the peer tiers produce for the
 * probe source beside it, captured by compiling that exact source through
 * {@code compilers/go/runar-go --source &lt;probe&gt; --hex
 * --disable-constant-folding} and cross-checked against ts / rust / python /
 * ruby, which agree byte for byte. Byte-identity with the peers is the
 * requirement, not "some correct lowering": a divergent-but-plausible sequence
 * still breaks cross-tier hex parity.
 *
 * <p>The numeric extractor probe consumes its result with {@code > 0n} rather
 * than {@code === expected}: the {@code ===} route exposes an unrelated,
 * pre-existing ts/rust-vs-rest disagreement over whether a preimage
 * extractor's result compares with OP_EQUAL or OP_NUMEQUAL, which would
 * smuggle a second variable into this fixture.
 *
 * <p>The expected values are inlined here on purpose: they are NOT read from
 * conformance goldens, so this test can never be "fixed" by moving a golden.
 */
class R069BuiltinParityTest {

    private static final String FILE = "Probe.runar.ts";

    // ------------------------------------------------------------------
    // right(data, n)
    // ------------------------------------------------------------------

    private static final String SRC_RIGHT = """
        import { SmartContract, assert, right } from 'runar-lang';

        class Probe extends SmartContract {
          readonly seed: bigint;

          constructor(seed: bigint) {
            super(seed);
            this.seed = seed;
          }

          public run(data: ByteString, n: bigint, expected: ByteString) {
            assert(this.seed === this.seed);
            assert(right(data, n) === expected);
          }
        }
        """;

    /** OP_ROT OP_ROT OP_SWAP OP_SIZE OP_ROT OP_SUB OP_SPLIT OP_NIP OP_SWAP OP_EQUAL. */
    private static final String EXPECTED_RIGHT = "00009d7b7b7c827b947f777c87";

    @Test
    void rightLowersToThePeerTiersEndRelativeSplit() throws Exception {
        assertEquals(EXPECTED_RIGHT, PipelineTestSupport.hex(SRC_RIGHT, FILE));
    }

    // ------------------------------------------------------------------
    // reverseBytes(data)
    // ------------------------------------------------------------------

    private static final String SRC_REVERSE_BYTES = """
        import { SmartContract, assert, reverseBytes } from 'runar-lang';

        class Probe extends SmartContract {
          readonly seed: bigint;

          constructor(seed: bigint) {
            super(seed);
            this.seed = seed;
          }

          public run(data: ByteString, expected: ByteString) {
            assert(this.seed === this.seed);
            assert(reverseBytes(data) === expected);
          }
        }
        """;

    /**
     * One unrolled reversal iteration:
     * OP_DUP OP_SIZE OP_NIP OP_IF OP_1 OP_SPLIT OP_SWAP OP_ROT OP_CAT OP_SWAP OP_ENDIF.
     */
    private static final String REVERSE_ITERATION_HEX = "76827763517f7c7b7e7c68";

    /** 520 = the maximum BSV stack-element size, so any legal ByteString reverses. */
    private static final int REVERSE_ITERATIONS = 520;

    private static String expectedReverseBytesHex() {
        StringBuilder sb = new StringBuilder();
        sb.append("00009d7c"); // prologue: seed slot, OP_NUMEQUALVERIFY, OP_SWAP
        sb.append("007c");     // OP_0 OP_SWAP — empty accumulator under the data
        sb.append(REVERSE_ITERATION_HEX.repeat(REVERSE_ITERATIONS));
        sb.append("75");       // OP_DROP — drop the drained remainder
        sb.append("7c87");     // OP_SWAP OP_EQUAL — the probe's comparison
        return sb.toString();
    }

    @Test
    void reverseBytesLowersToThePeerTiersUnrolledReversal() throws Exception {
        String expected = expectedReverseBytesHex();
        assertEquals(11458, expected.length(), "reference hex length drifted");
        assertEquals(expected, PipelineTestSupport.hex(SRC_REVERSE_BYTES, FILE));
    }

    /**
     * Semantic guard: a reversal that emits a byte-identical copy of a WRONG
     * reference would still pass the equality test above, so run the emitted
     * opcodes on 0x0102 and require 0x0201 back.
     */
    @Test
    void reverseBytesActuallyReversesTheBytes() throws Exception {
        String hex = PipelineTestSupport.hex(SRC_REVERSE_BYTES, FILE);
        int start = hex.indexOf("007c" + REVERSE_ITERATION_HEX);
        assertTrue(start >= 0, "reversal loop not found in emitted script");
        int end = start + 4 + REVERSE_ITERATION_HEX.length() * REVERSE_ITERATIONS + 2; // + OP_DROP
        String loop = hex.substring(start, end);
        assertEquals("0201", MiniVm.reverseWith(loop, "0102"));
        assertEquals("", MiniVm.reverseWith(loop, ""));
        assertEquals("ddccbbaa", MiniVm.reverseWith(loop, "aabbccdd"));
    }

    // ------------------------------------------------------------------
    // extractVersion(preimage)
    // ------------------------------------------------------------------

    private static final String SRC_EXTRACT_VERSION = """
        import { SmartContract, assert, extractVersion } from 'runar-lang';
        import type { SigHashPreimage } from 'runar-lang';

        class Probe extends SmartContract {
          readonly seed: bigint;

          constructor(seed: bigint) {
            super(seed);
            this.seed = seed;
          }

          public run(p: SigHashPreimage) {
            assert(this.seed === this.seed);
            assert(extractVersion(p) > 0n);
          }
        }
        """;

    /** OP_4 OP_SPLIT OP_DROP OP_BIN2NUM OP_0 OP_GREATERTHAN. */
    private static final String EXPECTED_EXTRACT_VERSION = "00009d547f7501007e8100a0";

    @Test
    void extractVersionLowersToTheLeadingFourByteSlice() throws Exception {
        assertEquals(EXPECTED_EXTRACT_VERSION, PipelineTestSupport.hex(SRC_EXTRACT_VERSION, FILE));
    }

    // ------------------------------------------------------------------
    // Semantics.
    //
    // Byte-identity with the peers proves agreement, not correctness: a
    // sequence identical to a WRONG reference passes every assertion above.
    // These tests EXECUTE what the tier emitted. The Java tier ships no
    // ScriptVM (CLAUDE.md: no usable upstream BSV script interpreter), so the
    // MiniVm below covers exactly the opcodes these lowerings emit.
    // ------------------------------------------------------------------

    /**
     * A synthetic BIP-143 sighash preimage, 161 bytes:
     * nVersion(4)=2, hashPrevouts(32)=0x11.., hashSequence(32)=0x22..,
     * outpoint(36)=0x33..||vout=7, scriptCode(5)=aabbccddee, amount(8)=100000,
     * nSequence(4)=10, hashOutputs(32)=0x44.., nLocktime(4)=5, sighashType(4)=65.
     */
    private static final String PREIMAGE_HEX =
        "02000000"
        + "11".repeat(32)
        + "22".repeat(32)
        + "33".repeat(32) + "07000000"
        + "aabbccddee"
        + "a086010000000000"
        + "0a000000"
        + "44".repeat(32)
        + "05000000"
        + "41000000";

    @Test
    void syntheticPreimageMatchesTheBip143Layout() {
        assertEquals(161 * 2, PREIMAGE_HEX.length());
    }

    @Test
    void extractVersionActuallyYieldsNVersion() throws Exception {
        String hex = PipelineTestSupport.hex(SRC_EXTRACT_VERSION, FILE);
        String core = "547f7501007e81"; // <4> OP_SPLIT OP_DROP <0x00> OP_CAT OP_BIN2NUM (W1)
        assertTrue(hex.contains(core), "extractVersion core sequence not emitted");
        assertEquals("02", MiniVm.runOn(core, PREIMAGE_HEX));
    }

    @Test
    void rightActuallyReturnsTheLastNBytes() throws Exception {
        String hex = PipelineTestSupport.hex(SRC_RIGHT, FILE);
        String core = "7c827b947f77"; // OP_SWAP OP_SIZE OP_ROT OP_SUB OP_SPLIT OP_NIP
        assertTrue(hex.contains(core), "right core sequence not emitted");
        // Stack bottom-to-top: <data> <n>. A left()-shaped bug returns "aabb".
        assertEquals("ddee", MiniVm.runOn(core, "aabbccddee", "02"));
        assertEquals("ee", MiniVm.runOn(core, "aabbccddee", "01"));
    }

    // ------------------------------------------------------------------
    // Control: no blanket pass-through
    // ------------------------------------------------------------------

    private static final String SRC_UNKNOWN = """
        import { SmartContract, assert } from 'runar-lang';

        class Probe extends SmartContract {
          readonly seed: bigint;

          constructor(seed: bigint) {
            super(seed);
            this.seed = seed;
          }

          public run(v: bigint) {
            assert(this.seed === this.seed);
            assert(definitelyNotARunarBuiltin(v) > 0n);
          }
        }
        """;

    @Test
    void unknownBuiltinIsStillRejected() {
        assertThrows(Exception.class, () -> PipelineTestSupport.hex(SRC_UNKNOWN, FILE));
    }

    private static final String SRC_UNKNOWN_EXTRACTOR = """
        import { SmartContract, assert } from 'runar-lang';
        import type { SigHashPreimage } from 'runar-lang';

        class Probe extends SmartContract {
          readonly seed: bigint;

          constructor(seed: bigint) {
            super(seed);
            this.seed = seed;
          }

          public run(p: SigHashPreimage) {
            assert(this.seed === this.seed);
            assert(extractNotARealField(p) > 0n);
          }
        }
        """;

    @Test
    void unknownExtractorIsStillRejected() {
        assertThrows(Exception.class, () -> PipelineTestSupport.hex(SRC_UNKNOWN_EXTRACTOR, FILE));
    }

    // ------------------------------------------------------------------
    // Minimal script interpreter covering exactly the reversal's opcodes.
    // ------------------------------------------------------------------

    private static final class MiniVm {

        /** Run {@code hex} over the given initial stack (bottom first); return the top as hex. */
        static String runOn(String hex, String... initialStackHex) {
            java.util.ArrayDeque<byte[]> stack = new java.util.ArrayDeque<>();
            for (String item : initialStackHex) stack.push(hexToBytes(item));
            run(hex, stack);
            return bytesToHex(stack.peek());
        }

        /** Run {@code loopHex} with {@code inputHex} on the stack; return the reversed top. */
        static String reverseWith(String loopHex, String inputHex) {
            java.util.ArrayDeque<byte[]> stack = new java.util.ArrayDeque<>();
            stack.push(hexToBytes(inputHex));
            run(loopHex, stack);
            return bytesToHex(stack.peek());
        }

        private static void run(String hex, java.util.ArrayDeque<byte[]> stack) {
            byte[] script = hexToBytes(hex);
            int pc = 0;
            while (pc < script.length) {
                int op = script[pc] & 0xff;
                pc++;
                switch (op) {
                    case 0x00 -> stack.push(new byte[0]);                 // OP_0
                    case 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,  // OP_1 .. OP_16
                         0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60 ->
                        stack.push(encodeNum(op - 0x50));
                    case 0x75 -> stack.pop();                             // OP_DROP
                    case 0x76 -> stack.push(stack.peek().clone());        // OP_DUP
                    case 0x77 -> {                                        // OP_NIP
                        byte[] top = stack.pop();
                        stack.pop();
                        stack.push(top);
                    }
                    case 0x7b -> {                                        // OP_ROT
                        byte[] a = stack.pop();
                        byte[] b = stack.pop();
                        byte[] c = stack.pop();
                        stack.push(b);
                        stack.push(a);
                        stack.push(c);
                    }
                    case 0x7c -> {                                        // OP_SWAP
                        byte[] a = stack.pop();
                        byte[] b = stack.pop();
                        stack.push(a);
                        stack.push(b);
                    }
                    case 0x7e -> {                                        // OP_CAT
                        byte[] a = stack.pop();
                        byte[] b = stack.pop();
                        byte[] out = new byte[b.length + a.length];
                        System.arraycopy(b, 0, out, 0, b.length);
                        System.arraycopy(a, 0, out, b.length, a.length);
                        stack.push(out);
                    }
                    case 0x7f -> {                                        // OP_SPLIT
                        int at = (int) decodeNum(stack.pop());
                        byte[] data = stack.pop();
                        stack.push(java.util.Arrays.copyOfRange(data, 0, at));
                        stack.push(java.util.Arrays.copyOfRange(data, at, data.length));
                    }
                    case 0x81 -> stack.push(minimalEncode(stack.pop()));   // OP_BIN2NUM
                    case 0x82 -> stack.push(encodeNum(stack.peek().length)); // OP_SIZE
                    case 0x94 -> {                                        // OP_SUB
                        long b = decodeNum(stack.pop());
                        long a = decodeNum(stack.pop());
                        stack.push(encodeNum(a - b));
                    }
                    case 0x63 -> {                                        // OP_IF
                        boolean taken = isTruthy(stack.pop());
                        if (!taken) pc = skipToEndif(script, pc);
                    }
                    case 0x68 -> { /* OP_ENDIF */ }
                    default -> {
                        if (op >= 0x01 && op <= 0x4b) {                   // direct push
                            stack.push(java.util.Arrays.copyOfRange(script, pc, pc + op));
                            pc += op;
                        } else {
                            throw new IllegalStateException(
                                "MiniVm: unsupported opcode 0x" + Integer.toHexString(op));
                        }
                    }
                }
            }
        }

        private static int skipToEndif(byte[] script, int pc) {
            int depth = 1;
            while (pc < script.length) {
                int op = script[pc] & 0xff;
                pc++;
                if (op == 0x63 || op == 0x64) depth++;
                else if (op == 0x68) {
                    depth--;
                    if (depth == 0) return pc;
                }
            }
            throw new IllegalStateException("MiniVm: unbalanced OP_IF");
        }

        private static boolean isTruthy(byte[] v) {
            for (int i = 0; i < v.length; i++) {
                if (v[i] == 0) continue;
                if (i == v.length - 1 && (v[i] & 0xff) == 0x80) continue;
                return true;
            }
            return false;
        }

        /** Strip trailing (high-order) zero bytes, as OP_BIN2NUM does. */
        private static byte[] minimalEncode(byte[] v) {
            int end = v.length;
            while (end > 0 && v[end - 1] == 0) end--;
            return java.util.Arrays.copyOfRange(v, 0, end);
        }

        private static byte[] encodeNum(long value) {
            if (value == 0) return new byte[0];
            byte[] tmp = new byte[9];
            int n = 0;
            long v = value;
            while (v > 0) {
                tmp[n++] = (byte) (v & 0xff);
                v >>= 8;
            }
            if ((tmp[n - 1] & 0x80) != 0) tmp[n++] = 0;
            return java.util.Arrays.copyOfRange(tmp, 0, n);
        }

        private static long decodeNum(byte[] v) {
            long out = 0;
            for (int i = v.length - 1; i >= 0; i--) out = (out << 8) | (v[i] & 0xff);
            return out;
        }

        private static byte[] hexToBytes(String hex) {
            byte[] out = new byte[hex.length() / 2];
            for (int i = 0; i < out.length; i++) {
                out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
            }
            return out;
        }

        private static String bytesToHex(byte[] v) {
            StringBuilder sb = new StringBuilder();
            for (byte b : v) sb.append(String.format("%02x", b));
            return sb.toString();
        }
    }
}
