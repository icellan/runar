package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.util.List;
import org.junit.jupiter.api.Test;
import runar.compiler.frontend.JavaParser;
import runar.compiler.ir.anf.AnfProgram;
import runar.compiler.ir.ast.ContractNode;
import runar.compiler.ir.stack.DropOp;
import runar.compiler.ir.stack.DupOp;
import runar.compiler.ir.stack.IfOp;
import runar.compiler.ir.stack.OpcodeOp;
import runar.compiler.ir.stack.PushOp;
import runar.compiler.ir.stack.PushValue;
import runar.compiler.ir.stack.StackMethod;
import runar.compiler.ir.stack.StackOp;
import runar.compiler.ir.stack.StackProgram;
import runar.compiler.ir.stack.SwapOp;

class EmitTest {

    // ---- individual ops ----

    @Test
    void dupEmits0x76() {
        String hex = Emit.run(singleMethod(List.of(new DupOp())));
        assertEquals("76", hex);
    }

    @Test
    void swapEmits0x7c() {
        String hex = Emit.run(singleMethod(List.of(new SwapOp())));
        assertEquals("7c", hex);
    }

    @Test
    void dropEmits0x75() {
        String hex = Emit.run(singleMethod(List.of(new DropOp())));
        assertEquals("75", hex);
    }

    @Test
    void checkSigOpcodeEmits0xAc() {
        String hex = Emit.run(singleMethod(List.of(new OpcodeOp("OP_CHECKSIG"))));
        assertEquals("ac", hex);
    }

    @Test
    void hash160OpcodeEmits0xA9() {
        String hex = Emit.run(singleMethod(List.of(new OpcodeOp("OP_HASH160"))));
        assertEquals("a9", hex);
    }

    @Test
    void equalOpcodeEmits0x87() {
        String hex = Emit.run(singleMethod(List.of(new OpcodeOp("OP_EQUAL"))));
        assertEquals("87", hex);
    }

    @Test
    void equalVerifyEmits0x88() {
        String hex = Emit.run(singleMethod(List.of(new OpcodeOp("OP_EQUALVERIFY"))));
        assertEquals("88", hex);
    }

    @Test
    void op1Emits0x51() {
        // PushValue.of(true) encodes to OP_TRUE (0x51)
        String hex = Emit.run(singleMethod(List.of(new PushOp(PushValue.of(true)))));
        assertEquals("51", hex);
    }

    @Test
    void op0Emits0x00() {
        String hex = Emit.run(singleMethod(List.of(new PushOp(PushValue.of(false)))));
        assertEquals("00", hex);
    }

    @Test
    void smallPositiveBigIntUsesOpcode() {
        // PUSH(5) → OP_5 = 0x55
        String hex = Emit.run(singleMethod(List.of(new PushOp(PushValue.of(5)))));
        assertEquals("55", hex);
    }

    @Test
    void negativeOneUsesOp1Negate() {
        String hex = Emit.run(singleMethod(List.of(new PushOp(PushValue.of(BigInteger.valueOf(-1))))));
        assertEquals("4f", hex);
    }

    @Test
    void largeBigIntUsesDirectPush() {
        // PUSH(1000) → 1000 encoded as script number (little-endian, sign-mag):
        // 1000 = 0x3E8 = bytes [e8, 03]. High bit clear → 2-byte payload.
        // Push length prefix 0x02 + payload = "02 e8 03".
        String hex = Emit.run(singleMethod(List.of(new PushOp(PushValue.of(1000)))));
        assertEquals("02e803", hex);
    }

    @Test
    void byteStringPushUsesCorrectLengthPrefix() {
        // Push a 20-byte byte string (e.g. a pubkey hash) → OP_PUSHBYTES_20 + data.
        StringBuilder data = new StringBuilder();
        for (int i = 0; i < 20; i++) data.append("aa");
        String hex = Emit.run(singleMethod(List.of(new PushOp(PushValue.ofHex(data.toString())))));
        // 0x14 = 20, then 20 bytes of 0xaa.
        StringBuilder expected = new StringBuilder("14");
        for (int i = 0; i < 20; i++) expected.append("aa");
        assertEquals(expected.toString(), hex);
    }

    @Test
    void byteString76PrefixesWithPushdata1() {
        StringBuilder data = new StringBuilder();
        for (int i = 0; i < 76; i++) data.append("bb");
        String hex = Emit.run(singleMethod(List.of(new PushOp(PushValue.ofHex(data.toString())))));
        // 0x4c (OP_PUSHDATA1) + 0x4c (len=76) + 76 bytes of 0xbb
        assertTrue(hex.startsWith("4c4c"), "hex should start with 4c4c: " + hex.substring(0, 8));
    }

    // ---- if emission ----

    @Test
    void ifOpEmitsOpIfThenOpEndif() {
        IfOp i = new IfOp(List.of(new OpcodeOp("OP_SHA256")));
        String hex = Emit.run(singleMethod(List.of(i)));
        // OP_IF = 0x63, OP_SHA256 = 0xa8, OP_ENDIF = 0x68
        assertEquals("63a868", hex);
    }

    @Test
    void ifElseOpEmitsOpIfThenOpElseOpEndif() {
        IfOp i = new IfOp(
            List.of(new OpcodeOp("OP_1ADD")),
            List.of(new OpcodeOp("OP_1SUB"))
        );
        String hex = Emit.run(singleMethod(List.of(i)));
        // 0x63, 0x8b, 0x67, 0x8c, 0x68
        assertEquals("638b678c68", hex);
    }

    // ---- script-number encoding ----

    @Test
    void scriptNumberEncodingRoundTrips() {
        // Positive small (no sign bit issue)
        assertEquals("", hex(Emit.encodeScriptNumber(BigInteger.ZERO)));
        assertEquals("7f", hex(Emit.encodeScriptNumber(BigInteger.valueOf(127))));
        assertEquals("8000", hex(Emit.encodeScriptNumber(BigInteger.valueOf(128))));
        // Negative
        assertEquals("ff", hex(Emit.encodeScriptNumber(BigInteger.valueOf(-127))));
        assertEquals("8080", hex(Emit.encodeScriptNumber(BigInteger.valueOf(-128))));
    }

    private static String hex(byte[] bs) {
        StringBuilder sb = new StringBuilder(bs.length * 2);
        for (byte b : bs) sb.append(String.format("%02x", b & 0xff));
        return sb.toString();
    }

    // ---- multi-method dispatch ----

    @Test
    void multipleMethodsEmitDispatchPreamble() {
        StackMethod a = new StackMethod("a", List.of(new OpcodeOp("OP_CHECKSIG")), 0L);
        StackMethod b = new StackMethod("b", List.of(new OpcodeOp("OP_CHECKSIG")), 0L);
        StackProgram p = new StackProgram("X", List.of(a, b));
        String hex = Emit.run(p);
        // Should start with OP_DUP (0x76) + OP_0 (0x00) + OP_NUMEQUAL (0x9c) + OP_IF (0x63)
        assertTrue(hex.startsWith("76009c63"),
            "multi-method dispatch should begin with DUP 0 NUMEQUAL IF: " + hex.substring(0, 8));
    }

    // ---- end-to-end P2PKH hex parity ----

    private static final String P2PKH_SRC = """
        package runar.examples.p2pkh;

        import runar.lang.*;

        public class P2PKH extends SmartContract {
            @Readonly Addr pubKeyHash;

            public P2PKH(Addr pubKeyHash) {
                super(pubKeyHash);
                this.pubKeyHash = pubKeyHash;
            }

            @Public
            public void unlock(Sig sig, PubKey pubKey) {
                assertThat(hash160(pubKey).equals(pubKeyHash));
                assertThat(checkSig(sig, pubKey));
            }
        }
        """;

    @Test
    void p2pkhFullPipelineMatchesReferenceHex() {
        ContractNode c = JavaParser.parse(P2PKH_SRC, "P2PKH.runar.java");
        Validate.run(c);
        Typecheck.run(c);
        AnfProgram anf = AnfLower.run(c);
        StackProgram stack = StackLower.run(anf);
        StackProgram opt = Peephole.run(stack);
        String hex = Emit.run(opt);
        // Reference hex from the Go compiler for the equivalent source. The
        // five bytes are: DUP (0x76) + HASH160 (0xa9) + placeholder (0x00) +
        // EQUALVERIFY (0x88) + CHECKSIG (0xac).
        assertEquals("76a90088ac", hex);
    }

    private static StackProgram singleMethod(List<StackOp> ops) {
        return new StackProgram("T", List.of(new StackMethod("unlock", ops, 0L)));
    }

    // -----------------------------------------------------------------
    // raw_script ANF JSON round-trip — load, lower, emit; the emitted
    // hex must contain the input bytes verbatim, and a RawScriptSpan
    // must be recorded.
    // -----------------------------------------------------------------

    @Test
    void rawScriptRoundTripPreservesBytesAndRecordsSpan() {
        // A minimal UnsafeSmartContract `unlock` method whose body is a
        // single raw_script binding (the ANF shape produced by
        // `asm({...})`). Bytes "5152935987" = OP_1 OP_2 OP_ADD OP_3
        // OP_EQUAL — an arbitrary opaque span the emitter must write
        // verbatim.
        String rawHex = "5152935987";
        String irJson = "{"
            + "\"contractName\": \"Anyone\","
            + "\"properties\": [],"
            + "\"methods\": ["
            + "  { \"name\": \"unlock\", \"params\": [], \"isPublic\": true,"
            + "    \"body\": ["
            + "      { \"name\": \"t0\","
            + "        \"value\": { \"kind\": \"raw_script\","
            + "                     \"bytes\": \"" + rawHex + "\","
            + "                     \"in_arity\": 0, \"out_arity\": 1 } }"
            + "    ] }"
            + "]}";

        AnfProgram program = AnfLoader.parse(irJson);

        // Round-trip the loader: in_arity 0 must survive.
        runar.compiler.ir.anf.AnfValue v = program.methods().get(0).body().get(0).value();
        assertTrue(v instanceof runar.compiler.ir.anf.RawScript,
            "loaded ANF value should be RawScript, got " + v.getClass().getSimpleName());
        runar.compiler.ir.anf.RawScript rs = (runar.compiler.ir.anf.RawScript) v;
        assertEquals(rawHex, rs.bytes(), "loaded raw_script bytes must match input");
        assertEquals(0, rs.inArity(), "loaded raw_script in_arity must be 0");
        assertEquals(1, rs.outArity(), "loaded raw_script out_arity must be 1");

        StackProgram stack = StackLower.run(program);

        // The lowered method must contain exactly one RawBytesOp.
        int rawOps = 0;
        for (StackMethod m : stack.methods()) {
            for (StackOp op : m.ops()) {
                if (op instanceof runar.compiler.ir.stack.RawBytesOp rb) {
                    rawOps++;
                    assertEquals(rawHex, bytesToHex(rb.bytes()),
                        "RawBytesOp bytes must match input");
                    assertEquals(0, rb.inArity(), "RawBytesOp in_arity must be 0");
                    assertEquals(1, rb.outArity(), "RawBytesOp out_arity must be 1");
                }
            }
        }
        assertEquals(1, rawOps, "expected exactly 1 RawBytesOp");

        Emit.EmitResult result = Emit.runResult(stack);

        // The emitted hex must equal the input bytes verbatim
        // (single-method contract, no dispatch preamble).
        assertEquals(rawHex, result.scriptHex(), "emitted hex must equal input bytes");

        // A RawScriptSpan covering the whole span must be recorded.
        assertEquals(1, result.rawScriptSpans().size(),
            "exactly 1 RawScriptSpan must be recorded");
        Emit.RawScriptSpan span = result.rawScriptSpans().get(0);
        assertEquals(0, span.offset(), "RawScriptSpan offset must be 0");
        assertEquals(rawHex.length() / 2, span.length(),
            "RawScriptSpan length must equal byte count");
        assertEquals(0, span.inArity(), "RawScriptSpan in_arity must be 0");
        assertEquals(1, span.outArity(), "RawScriptSpan out_arity must be 1");
    }

    private static String bytesToHex(byte[] bs) {
        StringBuilder sb = new StringBuilder(bs.length * 2);
        for (byte b : bs) sb.append(String.format("%02x", b & 0xff));
        return sb.toString();
    }
}
