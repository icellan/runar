package runar

import (
	"encoding/json"
	"strings"
	"testing"
)

// N-043 — an ordinals inscription must not be allowed to break the contract's
// own `SIZE(_codePart)` pin.
//
// A stateful contract with a variable-length state section carries an EQUALITY
// pin on the deployed code-part length, emitted as a fixed-width nine-byte run:
//
//	76 | 04 LL LL LL LL | 81 | (9c | a2) | 69
//	OP_DUP  <len LE32>    OP_BIN2NUM  cmp  OP_VERIFY
//
// `getCodePartHex` concatenates the inscription envelope INTO the code part, so
// attaching one makes the real code part longer than the pinned number and
// every honest spend aborts at OP_VERIFY with the funds already committed.
//
// The templates below are the four shapes the guard has to tell apart. Each is
// a 10-byte script — `OP_1` followed by the nine-byte pin run — except the
// unpinned one. The inscription used throughout is a two-byte `text/plain`
// payload, whose envelope is exactly 23 bytes, so an inscribed code part is
// 10 + 23 = 33 bytes.
const (
	// Exact pin of 10: correct WITHOUT an envelope, violated by one. Refuse.
	pinTemplateExact10 = "5176040a000000819c69"
	// Exact pin of 33 (0x21): correct WITH the envelope attached. Accept —
	// and a decoder that reads the length big-endian gets 0x21000000 here
	// and wrongly refuses.
	pinTemplateExact33 = "51760421000000819c69"
	// LOWER-BOUND pin (a2 = OP_GREATERTHANOREQUAL) of 10: extra bytes satisfy
	// it, so it must never trigger a refusal.
	pinTemplateLowerBound10 = "5176040a00000081a269"
	// No pin at all (a bare P2PKH template). Accept.
	pinTemplateNone = "76a90088ac"
)

const pinFixtureInscriptionData = "6869" // "hi"

func pinFixtureArtifactJSON(script string) string {
	return `{
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
  "script": "` + script + `",
  "stateFields": [
    { "name": "memo", "type": "ByteString", "index": 0, "encoding": "pushdata", "byteOffset": 0 }
  ]
}`
}

func newPinFixtureContract(t *testing.T, script string) *RunarContract {
	t.Helper()
	var artifact RunarArtifact
	if err := json.Unmarshal([]byte(pinFixtureArtifactJSON(script)), &artifact); err != nil {
		t.Fatalf("artifact fixture does not parse: %v", err)
	}
	return NewRunarContract(&artifact, []interface{}{"48656c6c6f"})
}

func pinFixtureInscription() *Inscription {
	return &Inscription{ContentType: "text/plain", Data: pinFixtureInscriptionData}
}

// The refusal case: an exact pin that the envelope would invalidate.
func TestWithInscription_RefusesWhenEnvelopeBreaksExactPin(t *testing.T) {
	c := newPinFixtureContract(t, pinTemplateExact10)

	got, err := c.WithInscription(pinFixtureInscription())
	if err == nil {
		t.Fatalf("expected a refusal; got locking script %s", c.GetLockingScript())
	}
	if got != nil {
		t.Errorf("a refused attach must not hand back a contract, got %p", got)
	}

	// Assert the REASON, not merely that something failed: a test that accepts
	// any error passes when an unrelated one fires.
	msg := err.Error()
	for _, want := range []string{
		"pins SIZE(_codePart) == 10",
		"code part is 33 bytes",
		"inscription",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("refusal message missing %q:\n  %s", want, msg)
		}
	}

	// The contract must be left un-inscribed rather than half-mutated.
	if c.GetInscription() != nil {
		t.Errorf("refused attach left the inscription applied")
	}
	if got := len(c.getCodePartHex()) / 2; got != 10 {
		t.Errorf("code part after a refused attach: got %d bytes, want 10", got)
	}
}

// Control: a pin whose value already accounts for the envelope is honoured, so
// the attach must be ACCEPTED. Also pins the little-endian decode.
func TestWithInscription_AcceptsWhenExactPinMatchesInscribedLength(t *testing.T) {
	c := newPinFixtureContract(t, pinTemplateExact33)

	got, err := c.WithInscription(pinFixtureInscription())
	if err != nil {
		t.Fatalf("pin equals the inscribed code-part length, must be accepted: %v", err)
	}
	if got == nil {
		t.Fatal("accepted attach returned a nil contract")
	}
	if c.GetInscription() == nil {
		t.Fatal("accepted attach did not store the inscription")
	}
	if n := len(c.getCodePartHex()) / 2; n != 33 {
		t.Errorf("inscribed code part: got %d bytes, want 33", n)
	}
}

// Control 1 (mandatory): a LOWER-BOUND pin is satisfied by the extra bytes, so
// an inscription must still be accepted. Guarding `a2` would turn this fix into
// an outage for every lower-bound contract.
func TestWithInscription_AcceptsLowerBoundPin(t *testing.T) {
	c := newPinFixtureContract(t, pinTemplateLowerBound10)

	if _, err := c.WithInscription(pinFixtureInscription()); err != nil {
		t.Fatalf("a lower-bound pin must not be guarded: %v", err)
	}
	if c.GetInscription() == nil {
		t.Fatal("accepted attach did not store the inscription")
	}
}

// Control 2 (mandatory): a contract with no pin at all (stateless, or a
// fixed-size state layout) must still accept an inscription.
func TestWithInscription_AcceptsUnpinnedContract(t *testing.T) {
	c := newPinFixtureContract(t, pinTemplateNone)

	if _, err := c.WithInscription(pinFixtureInscription()); err != nil {
		t.Fatalf("an unpinned contract must accept an inscription: %v", err)
	}
	if c.GetInscription() == nil {
		t.Fatal("accepted attach did not store the inscription")
	}
}
