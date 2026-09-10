package codegen

import (
	"strings"
	"testing"

	"github.com/icellan/runar/compilers/go/ir"
)

// ---------------------------------------------------------------------------
// R-054: checkMultiSig must reject a degenerate threshold at COMPILE time.
//
// `checkMultiSig([], [pk])` lowers to
//
//	OP_0 OP_0 <pk> OP_1 OP_CHECKMULTISIG
//
// i.e. nSigs = 0. OP_CHECKMULTISIG with zero required signatures pops the
// pubkeys, verifies nothing, and pushes TRUE — the deployed output is
// ANYONE-CAN-SPEND while the source reads like an authorization check.
// Confirmed byte-identically across all seven tiers before the guard landed:
// every one emitted `0000007b51ae`.
//
// The mirror image, more signatures than public keys, can never be satisfied
// by any witness: the output is permanently UNSPENDABLE.
//
// The guard lives in the lowerer rather than the typechecker so it also covers
// the `--ir` input path, and it is a compile-time refusal rather than extra
// emitted opcodes so it moves no bytes for existing valid contracts.
// ---------------------------------------------------------------------------

// multiSigThresholdProgram builds a minimal ANF program shaped like
//
//	sigN = load_param(sN); pkM = load_param(kM)
//	sigs = array_literal([sig0..]); pks = array_literal([pk0..])
//	r = checkMultiSig(sigs, pks); assert(r)
func multiSigThresholdProgram(nSigs, nPks int) *ir.ANFProgram {
	params := make([]ir.ANFParam, 0, nSigs+nPks)
	body := make([]ir.ANFBinding, 0, nSigs+nPks+4)
	sigRefs := make([]string, 0, nSigs)
	pkRefs := make([]string, 0, nPks)

	for i := 0; i < nSigs; i++ {
		p := "s" + string(rune('0'+i))
		params = append(params, ir.ANFParam{Name: p, Type: "Sig"})
		b := "sig" + string(rune('0'+i))
		body = append(body, ir.ANFBinding{Name: b, Value: ir.ANFValue{Kind: "load_param", Name: p}})
		sigRefs = append(sigRefs, b)
	}
	for i := 0; i < nPks; i++ {
		p := "k" + string(rune('0'+i))
		params = append(params, ir.ANFParam{Name: p, Type: "PubKey"})
		b := "pk" + string(rune('0'+i))
		body = append(body, ir.ANFBinding{Name: b, Value: ir.ANFValue{Kind: "load_param", Name: p}})
		pkRefs = append(pkRefs, b)
	}

	body = append(body,
		ir.ANFBinding{Name: "sigs", Value: ir.ANFValue{Kind: "array_literal", Elements: sigRefs}},
		ir.ANFBinding{Name: "pks", Value: ir.ANFValue{Kind: "array_literal", Elements: pkRefs}},
		ir.ANFBinding{Name: "r", Value: ir.ANFValue{
			Kind: "call", Func: "checkMultiSig", Args: []string{"sigs", "pks"},
		}},
		ir.ANFBinding{Name: "_assert", Value: ir.ANFValue{Kind: "assert", ValueRef: "r"}},
	)

	return &ir.ANFProgram{
		ContractName: "CheckMultiSigThresholdProbe",
		Properties:   []ir.ANFProperty{},
		Methods: []ir.ANFMethod{
			{Name: "unlock", Params: params, Body: body, IsPublic: true},
		},
	}
}

func TestCheckMultiSig_EmptySignatureArrayIsRejected(t *testing.T) {
	_, err := LowerToStack(multiSigThresholdProgram(0, 1))
	if err == nil {
		t.Fatal("checkMultiSig([], [pk]) lowered cleanly — that script is anyone-can-spend")
	}
	if !strings.Contains(err.Error(), "at least one signature") {
		t.Errorf("expected an 'at least one signature' diagnostic, got: %v", err)
	}
}

func TestCheckMultiSig_EmptyPubKeyArrayIsRejected(t *testing.T) {
	_, err := LowerToStack(multiSigThresholdProgram(1, 0))
	if err == nil {
		t.Fatal("checkMultiSig([sig], []) lowered cleanly")
	}
	if !strings.Contains(err.Error(), "at least one public key") {
		t.Errorf("expected an 'at least one public key' diagnostic, got: %v", err)
	}
}

func TestCheckMultiSig_MoreSigsThanPubKeysIsRejected(t *testing.T) {
	_, err := LowerToStack(multiSigThresholdProgram(2, 1))
	if err == nil {
		t.Fatal("checkMultiSig with m > n lowered cleanly — that script is unspendable")
	}
	if !strings.Contains(err.Error(), "cannot exceed") {
		t.Errorf("expected a 'cannot exceed' diagnostic, got: %v", err)
	}
}

// --- controls: the guard must not break any valid threshold ----------------

func TestCheckMultiSig_ValidThresholdsStillLower(t *testing.T) {
	for _, tc := range []struct{ nSigs, nPks int }{
		{1, 1}, // 1-of-1
		{2, 3}, // 2-of-3
		{3, 3}, // m == n
	} {
		methods, err := LowerToStack(multiSigThresholdProgram(tc.nSigs, tc.nPks))
		if err != nil {
			t.Fatalf("%d-of-%d must still lower: %v", tc.nSigs, tc.nPks, err)
		}
		var found bool
		for _, m := range methods {
			if m.Name != "unlock" {
				continue
			}
			for _, op := range m.Ops {
				if op.Op == "opcode" && op.Code == "OP_CHECKMULTISIG" {
					found = true
				}
			}
		}
		if !found {
			t.Errorf("%d-of-%d must emit OP_CHECKMULTISIG", tc.nSigs, tc.nPks)
		}
	}
}
