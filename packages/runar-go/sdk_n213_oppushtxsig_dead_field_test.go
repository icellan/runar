package runar

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// TestPreparedCall_NoOpPushTxSigField_N213 is the Go half of N-213 ("Remove
// the dead PreparedCall.opPushTxSig field ... from Go/Rust/Python/Ruby/Zig
// SDKs, as F-369 did for TS").
//
// Since BUG-100 the unlocking script carries no spender-supplied OP_PUSH_TX
// signature: buildStatefulPrefix's first parameter is accepted for call-site
// compatibility but ignored ("_ = opSigHex" — see buildStatefulPrefix's
// docstring). OpPushTxSig was documented public surface on PreparedCall that
// backed nothing a caller could use: a caller who read the field, prepended
// it to the unlock as the field's doc comment implied, would have produced
// an INVALID unlock (one extra stack item).
//
// This test proves (a) the field is gone from the wire shape (JSON has no
// "opPushTxSig" key — PreparedCall is JSON-tagged for exactly this kind of
// external-signer coordination) and (b) the multi-signer PrepareCall ->
// external sign -> FinalizeCall flow still produces a transaction the real
// go-sdk script interpreter accepts (reusing the c19Deploy/c19ExecuteSpend
// harness from sdk_c19_prepared_sighash_test.go in this package).
//
// It does NOT prove anything about the other four SDKs (Rust/Python/Ruby/
// Zig) in scope for N-213 — each gets its own language-appropriate
// field-absence test — or about a real on-chain broadcast.
func TestPreparedCall_NoOpPushTxSigField_N213(t *testing.T) {
	c, provider, signer := c19Deploy(t)

	prepared, err := c.PrepareCall("inc", []interface{}{nil}, provider, signer, nil)
	if err != nil {
		t.Fatalf("PrepareCall: %v", err)
	}

	buf, err := json.Marshal(prepared)
	if err != nil {
		t.Fatalf("marshal PreparedCall: %v", err)
	}
	if strings.Contains(string(buf), "opPushTxSig") {
		t.Fatalf("PreparedCall JSON still carries the dead opPushTxSig key: %s", buf)
	}

	// End-to-end: an external signHash() wallet signs prepared.Sighash
	// directly (no opPushTxSig involved anywhere in this flow), FinalizeCall
	// assembles the tx, and the real go-sdk script interpreter must accept
	// the spend — removing the field must not disturb the actual unlock.
	if len(prepared.SigIndices) != 1 {
		t.Fatalf("expected exactly 1 external Sig index, got %v", prepared.SigIndices)
	}
	digest, err := hex.DecodeString(prepared.Sighash)
	if err != nil {
		t.Fatalf("decode prepared.Sighash: %v", err)
	}
	privKey, err := ec.PrivateKeyFromHex(c19PrivKeyHex)
	if err != nil {
		t.Fatalf("privkey: %v", err)
	}
	sig, err := privKey.Sign(digest)
	if err != nil {
		t.Fatalf("external sign: %v", err)
	}
	sigHex := hex.EncodeToString(append(sig.Serialize(), 0x41)) // ALL|FORKID

	if _, _, err := c.FinalizeCall(prepared, map[int]string{prepared.SigIndices[0]: sigHex}, provider); err != nil {
		t.Fatalf("FinalizeCall: %v", err)
	}
	if execErr := c19ExecuteSpend(t, provider); execErr != nil {
		t.Fatalf("multi-signer spend REJECTED by the go-sdk script interpreter after removing "+
			"PreparedCall.OpPushTxSig: %v", execErr)
	}
}
