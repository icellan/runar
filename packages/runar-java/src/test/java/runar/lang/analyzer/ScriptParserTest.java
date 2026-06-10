package runar.lang.analyzer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

class ScriptParserTest {

    @Test
    void parsesDirectPushAndOpcode() {
        // 0x03 (direct push of 3 bytes) + "aabbcc" + OP_DROP
        ScriptParser.Parsed p = ScriptParser.parse("03aabbcc75");
        assertEquals(2, p.opcodes.size());
        OpStep push = p.opcodes.get(0);
        assertEquals("PUSH_3", push.name);
        assertEquals("direct", push.pushEncoding);
        assertEquals(3, push.dataLength);
        OpStep drop = p.opcodes.get(1);
        assertEquals("OP_DROP", drop.name);
        assertNull(drop.pushEncoding);
        assertTrue(p.findings.isEmpty());
    }

    @Test
    void unknownByteRendersAsHex() {
        // 0x62 has no canonical name.
        ScriptParser.Parsed p = ScriptParser.parse("62");
        assertEquals(1, p.opcodes.size());
        assertEquals("OP_UNKNOWN(0x62)", p.opcodes.get(0).name);
    }

    @Test
    void inefficientPushdata1Emits_INEFFICIENT_PUSH() {
        // OP_PUSHDATA1 length=5 + 5 bytes of data
        ScriptParser.Parsed p = ScriptParser.parse("4c050102030405");
        assertEquals(1, p.opcodes.size());
        assertEquals("OP_PUSHDATA1", p.opcodes.get(0).name);
        assertEquals(1, p.findings.size());
        Finding f = p.findings.get(0);
        assertEquals("info", f.severity);
        assertEquals("INEFFICIENT_PUSH", f.code);
        assertTrue(f.message.contains("direct push (opcode 0x05)"));
        assertEquals(Integer.valueOf(0), f.offset);
    }

    @Test
    void inefficientPushdata2Emits_INEFFICIENT_PUSH() {
        // OP_PUSHDATA2 length=10 (0x0a 0x00 little-endian) + 10 bytes
        ScriptParser.Parsed p = ScriptParser.parse("4d0a00" + "00".repeat(10));
        assertEquals(1, p.opcodes.size());
        assertEquals(1, p.findings.size());
        Finding f = p.findings.get(0);
        assertEquals("INEFFICIENT_PUSH", f.code);
        assertTrue(f.message.contains("OP_PUSHDATA1 would be more efficient"));
    }

    @Test
    void inefficientPushdata4Emits_INEFFICIENT_PUSH() {
        // OP_PUSHDATA4 length=10 + 10 bytes
        ScriptParser.Parsed p = ScriptParser.parse("4e0a000000" + "00".repeat(10));
        assertEquals(1, p.opcodes.size());
        assertEquals(1, p.findings.size());
        Finding f = p.findings.get(0);
        assertEquals("INEFFICIENT_PUSH", f.code);
        assertTrue(f.message.contains("OP_PUSHDATA2 would be more efficient"));
    }

    @Test
    void truncatedDirectPushStopsParsing() {
        // 0x05 declared but only 2 bytes available.
        ScriptParser.Parsed p = ScriptParser.parse("05aabb");
        assertEquals(1, p.opcodes.size());
        OpStep op = p.opcodes.get(0);
        assertEquals("PUSH_5", op.name);
        // No additional finding per §6.1.
        assertEquals(0, p.findings.size());
    }

    @Test
    void collapseRawScriptSpansDropsOpsInsideSpan() {
        // OP_NOP at 0, OP_NOP at 1, OP_DROP at 2, OP_NOP at 3. Span: [0, 2).
        ScriptParser.Parsed p = ScriptParser.parse("61617561");
        RawScriptSpan span = new RawScriptSpan(0, 2, 1, 2);
        List<OpStep> collapsed = ScriptParser.collapseRawScriptSpans(
            p.opcodes, List.of(span));
        // 2 ops dropped, 1 synthetic, plus OP_DROP + OP_NOP = 3.
        assertEquals(3, collapsed.size());
        assertEquals("RAW_SPAN", collapsed.get(0).name);
        assertEquals(-1, collapsed.get(0).opcode);
        assertEquals(2, collapsed.get(0).size);
        assertEquals(1, collapsed.get(0).rawSpanIn);
        assertEquals(2, collapsed.get(0).rawSpanOut);
        assertEquals("OP_DROP", collapsed.get(1).name);
        assertEquals("OP_NOP", collapsed.get(2).name);
    }

    @Test
    void collapseRawScriptSpansEmptyReturnsInput() {
        ScriptParser.Parsed p = ScriptParser.parse("616175");
        List<OpStep> collapsed = ScriptParser.collapseRawScriptSpans(
            p.opcodes, List.of());
        assertEquals(p.opcodes, collapsed);
    }

    @Test
    void hexNormalizationIsCallerResponsibility() {
        // Parser assumes lowercase hex; uppercase A-F would be rejected.
        // (Normalization happens at the orchestrator level.)
        ScriptParser.Parsed p = ScriptParser.parse("ab");
        assertNotNull(p);
        assertEquals(1, p.opcodes.size());
        assertEquals("OP_CODESEPARATOR", p.opcodes.get(0).name);
    }
}
