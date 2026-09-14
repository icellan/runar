package runar.lang.sdk;

import java.util.List;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * N-043 — an ordinals inscription must not break the code-part length pin.
 *
 * <p>A stateful contract with a variable-length state section carries an
 * EQUALITY pin on the deployed code-part length, emitted as a fixed-width
 * nine-byte run:
 *
 * <pre>
 *   76 | 04 LL LL LL LL | 81 | (9c | a2) | 69
 *   OP_DUP  &lt;len LE32&gt;    OP_BIN2NUM  cmp  OP_VERIFY
 * </pre>
 *
 * <p>The rendered locking script concatenates the inscription envelope INTO the
 * code part, so attaching one makes the real code part longer than the pinned
 * number and every honest spend aborts at OP_VERIFY with the funds already
 * committed.
 *
 * <p>Each template below is a 10-byte script — {@code OP_1} followed by the
 * nine-byte pin run — except the unpinned one. The inscription is a two-byte
 * {@code text/plain} payload whose envelope is exactly 23 bytes, so an inscribed
 * code part is 10 + 23 = 33 bytes.
 */
class CodePartLengthPinTest {

    /** Exact pin of 10: correct WITHOUT an envelope, violated by one. Refuse. */
    private static final String PIN_TEMPLATE_EXACT_10 = "5176040a000000819c69";
    /**
     * Exact pin of 33 (0x21): correct WITH the envelope attached. Accept — and a
     * decoder that reads the length big-endian gets 0x21000000 here and wrongly
     * refuses.
     */
    private static final String PIN_TEMPLATE_EXACT_33 = "51760421000000819c69";
    /**
     * LOWER-BOUND pin (a2 = OP_GREATERTHANOREQUAL) of 10: extra bytes satisfy
     * it, so it must never trigger a refusal.
     */
    private static final String PIN_TEMPLATE_LOWER_BOUND_10 = "5176040a00000081a269";
    /** No pin at all (a bare P2PKH template). Accept. */
    private static final String PIN_TEMPLATE_NONE = "76a90088ac";

    private static RunarContract pinFixtureContract(String script) {
        RunarArtifact artifact = RunarArtifact.fromJson("""
            {
              "version": "runar-v1.0.0-rc.1",
              "compilerVersion": "1.0.0-rc.1",
              "contractName": "PinFixture",
              "parentClass": "StatefulSmartContract",
              "abi": {
                "constructor": { "params": [ { "name": "memo", "type": "ByteString" } ] },
                "methods": [
                  { "name": "post", "params": [ { "name": "newMemo", "type": "ByteString" } ], "isPublic": true }
                ]
              },
              "script": "%s",
              "stateFields": [
                { "name": "memo", "type": "ByteString", "index": 0, "encoding": "pushdata", "byteOffset": 0 }
              ]
            }
            """.formatted(script));
        return new RunarContract(artifact, List.of("48656c6c6f"));
    }

    private static Inscription pinFixtureInscription() {
        return new Inscription("text/plain", "6869");
    }

    @Test
    void refusesWhenEnvelopeBreaksExactPin() {
        RunarContract contract = pinFixtureContract(PIN_TEMPLATE_EXACT_10);

        IllegalArgumentException e = assertThrows(
            IllegalArgumentException.class,
            () -> contract.withInscription(pinFixtureInscription())
        );

        // Assert the REASON, not merely that something failed: a test that
        // accepts any error passes when an unrelated one fires.
        for (String want : List.of("pins SIZE(_codePart) == 10", "code part is 33 bytes", "inscription")) {
            assertTrue(e.getMessage().contains(want),
                "refusal message missing \"" + want + "\":\n  " + e.getMessage());
        }

        // The contract must be left un-inscribed rather than half-mutated.
        assertNull(contract.inscription());
        assertEquals(10, ContractScript.renderCodePart(
            contract.artifact(), List.of("48656c6c6f"), null).length() / 2);
    }

    /**
     * Control: a pin whose value already accounts for the envelope is honoured,
     * so the attach must be ACCEPTED. Also pins the little-endian decode.
     */
    @Test
    void acceptsWhenExactPinMatchesInscribedLength() {
        RunarContract contract = pinFixtureContract(PIN_TEMPLATE_EXACT_33);

        assertSame(contract, contract.withInscription(pinFixtureInscription()));
        assertNotNull(contract.inscription());
        assertEquals(33, ContractScript.renderCodePart(
            contract.artifact(), List.of("48656c6c6f"), pinFixtureInscription()).length() / 2);
    }

    /**
     * Control 1 (mandatory): a LOWER-BOUND pin is satisfied by the extra bytes,
     * so an inscription must still be accepted. Guarding {@code a2} would turn
     * this fix into an outage for every lower-bound contract.
     */
    @Test
    void acceptsLowerBoundPin() {
        RunarContract contract = pinFixtureContract(PIN_TEMPLATE_LOWER_BOUND_10);

        assertDoesNotThrow(() -> contract.withInscription(pinFixtureInscription()));
        assertNotNull(contract.inscription());
    }

    /**
     * Control 2 (mandatory): a contract with no pin at all (stateless, or a
     * fixed-size state layout) must still accept an inscription.
     */
    @Test
    void acceptsUnpinnedContract() {
        RunarContract contract = pinFixtureContract(PIN_TEMPLATE_NONE);

        assertDoesNotThrow(() -> contract.withInscription(pinFixtureInscription()));
        assertNotNull(contract.inscription());
    }
}
