package runar

import (
	"math/big"
	"strings"
	"testing"

	sdkscript "github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"

	"github.com/icellan/runar/packages/runar-go/bn254witness"
)

// ---------------------------------------------------------------------------
// Unit tests for sdk_groth16.go
//
// These tests are fast and do NOT broadcast to regtest. They verify:
//   - NewGroth16WAContract accepts a valid Groth16 WA artifact
//   - NewGroth16WAContract panics on nil or non-Groth16 artifacts
//   - Metadata accessors (NumPubInputs, VKDigest) expose the embedded fields
//   - serializeWitnessToUnlock produces a non-empty hex stream of push ops
//   - CallWithWitness input validation (no UTXO, nil witness, etc.) errors
//     cleanly without panicking
//   - Deploy + spend can be driven end-to-end against MockProvider so we
//     exercise the full Groth16WAContract control flow without leaving the
//     unit-test harness.
// ---------------------------------------------------------------------------

// buildFakeGroth16WAArtifact returns a minimal RunarArtifact with the
// Groth16WA metadata field populated. The script is a trivial
// OP_1/OP_TRUE locking script so that MockProvider deploy/spend round
// trips succeed without running the real ~700 KB verifier.
func buildFakeGroth16WAArtifact() *RunarArtifact {
	return &RunarArtifact{
		Version:         "1",
		CompilerVersion: "test",
		ContractName:    "Groth16Verifier",
		Script:          "51", // OP_1 — always-true locking script
		ABI: ABI{
			Constructor: ABIConstructor{Params: []ABIParam{}},
			Methods: []ABIMethod{
				{Name: "verify", Params: []ABIParam{}, IsPublic: true},
			},
		},
		Groth16WA: &Groth16WAMeta{
			NumPubInputs: 5,
			VKDigest:     "ba315d87303b212ac0c221881a34468013e6afc6b865e2abe3d68ad1c500c1d7",
		},
	}
}

// buildFakeWitness returns a minimal Witness with every slot populated.
// This is enough to exercise ToStackOps → serializeWitnessToUnlock → push
// data encoding without needing to regenerate a real witness from a
// proof (which costs ~1 s).
func buildFakeWitness() *bn254witness.Witness {
	mk := func(v int64) *big.Int { return big.NewInt(v) }
	w := &bn254witness.Witness{
		Q: mk(21888),
	}
	// Miller gradients: one loop iteration worth = 6 values.
	w.MillerGradients = []*big.Int{mk(1), mk(2), mk(3), mk(4), mk(5), mk(6)}
	// Final exp witnesses: 4 × 12 Fp values.
	for i := 0; i < 12; i++ {
		w.FinalExpFInv[i] = mk(int64(i + 100))
		w.FinalExpA[i] = mk(int64(i + 200))
		w.FinalExpB[i] = mk(int64(i + 300))
		w.FinalExpC[i] = mk(int64(i + 400))
	}
	w.PreparedInputs = [2]*big.Int{mk(11), mk(22)}
	w.ProofA = [2]*big.Int{mk(1001), mk(1002)}
	w.ProofB = [4]*big.Int{mk(2001), mk(2002), mk(2003), mk(2004)}
	w.ProofC = [2]*big.Int{mk(3001), mk(3002)}
	return w
}

func TestGroth16WASDK_NewGroth16WAContract_Happy(t *testing.T) {
	artifact := buildFakeGroth16WAArtifact()
	g := NewGroth16WAContract(artifact)
	if g == nil {
		t.Fatalf("NewGroth16WAContract returned nil")
	}
	if g.Artifact() != artifact {
		t.Errorf("Artifact() did not return the wrapped artifact")
	}
	if g.NumPubInputs() != 5 {
		t.Errorf("NumPubInputs = %d, want 5", g.NumPubInputs())
	}
	if g.VKDigest() != "ba315d87303b212ac0c221881a34468013e6afc6b865e2abe3d68ad1c500c1d7" {
		t.Errorf("VKDigest mismatch: %s", g.VKDigest())
	}
	if g.CurrentUTXO() != nil {
		t.Errorf("CurrentUTXO on fresh contract should be nil")
	}
	if g.LockingScript() != "51" {
		t.Errorf("LockingScript mismatch: %s", g.LockingScript())
	}
}

func TestGroth16WASDK_NewGroth16WAContract_NilArtifactPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("expected panic on nil artifact")
		}
	}()
	_ = NewGroth16WAContract(nil)
}

func TestGroth16WASDK_NewGroth16WAContract_NoMetadataPanics(t *testing.T) {
	// A normal Rúnar artifact has Groth16WA == nil; NewGroth16WAContract
	// must reject it.
	artifact := &RunarArtifact{
		Version:      "1",
		ContractName: "P2PKH",
		Script:       "51",
		ABI: ABI{
			Constructor: ABIConstructor{Params: []ABIParam{}},
			Methods: []ABIMethod{
				{Name: "unlock", IsPublic: true},
			},
		},
	}
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("expected panic on artifact with no Groth16WA metadata")
		}
	}()
	_ = NewGroth16WAContract(artifact)
}

func TestGroth16WASDK_SerializeWitnessToUnlock_NonEmpty(t *testing.T) {
	w := buildFakeWitness()
	hex, err := serializeWitnessToUnlock(w)
	if err != nil {
		t.Fatalf("serializeWitnessToUnlock: %v", err)
	}
	if hex == "" {
		t.Fatalf("serializeWitnessToUnlock returned empty string")
	}
	// Each of the 1 (Q) + 6 (gradients) + 48 (final exp) + 2 (prepared) +
	// 8 (proof) = 65 values is pushed. Small values 1..16 encode as a
	// single byte (OP_1..OP_16). Larger values encode as pushdata
	// opcode + payload. Just sanity-check the length is in a sensible
	// range (at least 65 bytes, at most ~200 bytes for this fake input).
	byteLen := len(hex) / 2
	if byteLen < 65 {
		t.Errorf("serialized unlock too short: %d bytes", byteLen)
	}
	if byteLen > 400 {
		t.Errorf("serialized unlock suspiciously long: %d bytes", byteLen)
	}
}

func TestGroth16WASDK_SerializeWitnessToUnlock_NilWitness(t *testing.T) {
	if _, err := serializeWitnessToUnlock(nil); err == nil {
		t.Errorf("expected error for nil witness")
	}
}

func TestGroth16WASDK_CallWithWitness_NoUtxo(t *testing.T) {
	g := NewGroth16WAContract(buildFakeGroth16WAArtifact())
	provider := NewAlwaysAckMockProvider("mocknet")
	signer := NewMockSigner("", "")
	w := buildFakeWitness()
	_, _, err := g.CallWithWitness(provider, signer, w, "fakeaddr", "")
	if err == nil {
		t.Fatalf("expected error (no UTXO) but CallWithWitness returned nil")
	}
	if !strings.Contains(err.Error(), "no current UTXO") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestGroth16WASDK_CallWithWitness_NoProvider(t *testing.T) {
	g := NewGroth16WAContract(buildFakeGroth16WAArtifact())
	g.SetCurrentUTXO(&UTXO{
		Txid:        strings.Repeat("aa", 32),
		OutputIndex: 0,
		Satoshis:    50000,
		Script:      "51",
	})
	_, _, err := g.CallWithWitness(nil, nil, buildFakeWitness(), "fakeaddr", "")
	if err == nil {
		t.Fatalf("expected error when neither provider argument nor Connect() are set")
	}
	if !strings.Contains(err.Error(), "no provider") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestGroth16WASDK_CallWithWitness_NilWitness(t *testing.T) {
	g := NewGroth16WAContract(buildFakeGroth16WAArtifact())
	g.SetCurrentUTXO(&UTXO{
		Txid:        strings.Repeat("aa", 32),
		OutputIndex: 0,
		Satoshis:    50000,
		Script:      "51",
	})
	provider := NewAlwaysAckMockProvider("mocknet")
	signer := NewMockSigner("", "")
	_, _, err := g.CallWithWitness(provider, signer, nil, "fakeaddr", "")
	if err == nil {
		t.Fatalf("expected error on nil witness")
	}
}

func TestGroth16WASDK_CallWithWitness_BothDestinationsError(t *testing.T) {
	g := NewGroth16WAContract(buildFakeGroth16WAArtifact())
	g.SetCurrentUTXO(&UTXO{
		Txid:        strings.Repeat("aa", 32),
		OutputIndex: 0,
		Satoshis:    50000,
		Script:      "51",
	})
	provider := NewAlwaysAckMockProvider("mocknet")
	signer := NewMockSigner("", "")
	_, _, err := g.CallWithWitness(provider, signer, buildFakeWitness(), "fakeaddr", "deadbeef")
	if err == nil {
		t.Fatalf("expected error when both changeAddress and outputScriptHex are set")
	}
	if !strings.Contains(err.Error(), "only one of") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestGroth16WASDK_CallWithWitness_NeitherDestinationError(t *testing.T) {
	g := NewGroth16WAContract(buildFakeGroth16WAArtifact())
	g.SetCurrentUTXO(&UTXO{
		Txid:        strings.Repeat("aa", 32),
		OutputIndex: 0,
		Satoshis:    50000,
		Script:      "51",
	})
	provider := NewAlwaysAckMockProvider("mocknet")
	signer := NewMockSigner("", "")
	_, _, err := g.CallWithWitness(provider, signer, buildFakeWitness(), "", "")
	if err == nil {
		t.Fatalf("expected error when no destination is provided")
	}
}

func TestGroth16WASDK_CallWithWitness_EndToEndMock(t *testing.T) {
	// Drive the entire wrapper lifecycle through MockProvider:
	//   1. Simulate a pre-funded contract UTXO.
	//   2. Call CallWithWitness with a P2PKH output destination.
	//   3. Assert the spend was broadcast exactly once and that the
	//      contract's tracked UTXO was cleared.
	g := NewGroth16WAContract(buildFakeGroth16WAArtifact())
	utxo := &UTXO{
		Txid:        strings.Repeat("bb", 32),
		OutputIndex: 0,
		Satoshis:    50_000,
		Script:      "51",
	}
	g.SetCurrentUTXO(utxo)

	provider := NewAlwaysAckMockProvider("mocknet")
	signer := NewMockSigner("", "")

	// Use a raw P2PKH-ish script hex as the destination; we don't care
	// about its validity on mocknet.
	destScript := "76a914" + strings.Repeat("00", 20) + "88ac"
	txid, txData, err := g.CallWithWitness(provider, signer, buildFakeWitness(), "", destScript)
	if err != nil {
		t.Fatalf("CallWithWitness: %v", err)
	}
	if txid == "" {
		t.Errorf("empty txid after broadcast")
	}
	if txData == nil {
		t.Fatalf("nil txData")
	}
	if len(txData.Outputs) != 1 {
		t.Fatalf("expected 1 output, got %d", len(txData.Outputs))
	}
	if txData.Outputs[0].Script != destScript {
		t.Errorf("output script mismatch: %s", txData.Outputs[0].Script)
	}
	if txData.Outputs[0].Satoshis <= 0 || txData.Outputs[0].Satoshis >= utxo.Satoshis {
		t.Errorf("output satoshis out of range: %d", txData.Outputs[0].Satoshis)
	}
	if len(provider.GetBroadcastedTxs()) != 1 {
		t.Errorf("expected exactly 1 broadcast, got %d", len(provider.GetBroadcastedTxs()))
	}
	if g.CurrentUTXO() != nil {
		t.Errorf("CurrentUTXO should be nil after successful spend")
	}
}

// TestGroth16WASDK_CallWithWitness_OwnerSignedSpendCannotBeReplayed is the
// SDK half of F-233.
//
// The UTXO is locked by `<ownerPubKey> OP_CHECKSIGVERIFY` — exactly the owner
// binding CompileGroth16WA now prepends to the verifier (here with no proof
// check behind it, so the test isolates the signature half). The spend is
// broadcast through a VALIDATING MockProvider, which runs every known input
// through the go-sdk interpreter with full transaction context, so
// OP_CHECKSIG verifies a real BIP-143 signature.
//
// Proves: CallWithWitness signs the spend with the supplied signer (the
// owner's spend is ACCEPTED), and an observer who copies that broadcast
// transaction's unlocking script into a transaction paying themselves is
// REJECTED by the same interpreter.
//
// Does not prove: that the real ~700 KB verifier accepts the proof (see
// compilers/go/compiler/groth16_wa_replay_test.go, which runs the compiled
// artifact), or anything about regtest acceptance.
func TestGroth16WASDK_CallWithWitness_OwnerSignedSpendCannotBeReplayed(t *testing.T) {
	owner, err := NewLocalSigner("0000000000000000000000000000000000000000000000000000000000000003")
	if err != nil {
		t.Fatalf("NewLocalSigner: %v", err)
	}
	ownerPub, err := owner.GetPublicKey()
	if err != nil {
		t.Fatalf("GetPublicKey: %v", err)
	}
	lock := "21" + ownerPub + "ad" // <ownerPubKey> OP_CHECKSIGVERIFY
	newUtxo := func() *UTXO {
		return &UTXO{Txid: strings.Repeat("cc", 32), OutputIndex: 0, Satoshis: 50_000, Script: lock}
	}

	provider := NewMockProvider("testnet")
	provider.AddContractUtxo("groth16-owner-bound", newUtxo())

	g := NewGroth16WAContract(buildFakeGroth16WAArtifact())
	g.SetCurrentUTXO(newUtxo())

	ownerDest := "76a914" + strings.Repeat("11", 20) + "88ac"
	if _, _, err := g.CallWithWitness(provider, owner, buildFakeWitness(), "", ownerDest); err != nil {
		t.Fatalf("the owner's own spend was refused by the validating MockProvider: %v", err)
	}
	broadcast := provider.GetBroadcastedTxs()
	if len(broadcast) != 1 {
		t.Fatalf("expected exactly 1 broadcast, got %d", len(broadcast))
	}

	// The observer's replay: same input, same unlocking bytes, new payee.
	replay, err := transaction.NewTransactionFromHex(broadcast[0])
	if err != nil {
		t.Fatalf("parse broadcast tx: %v", err)
	}
	attackerScript, err := sdkscript.NewFromHex("76a914" + strings.Repeat("ee", 20) + "88ac")
	if err != nil {
		t.Fatalf("attacker script: %v", err)
	}
	replay.Outputs[0].LockingScript = attackerScript

	// A fresh provider that knows the same (still-unspent from its point of
	// view) outpoint, so the only thing that can reject the replay is the
	// script itself — not double-spend bookkeeping.
	observerView := NewMockProvider("testnet")
	observerView.AddContractUtxo("groth16-owner-bound", newUtxo())
	_, err = observerView.Broadcast(replay)
	if err == nil {
		t.Fatal("REPLAY ACCEPTED: the observed unlocking script, re-attached to a transaction paying the attacker, passed the interpreter")
	}
	if !strings.Contains(err.Error(), "REJECTED by the go-sdk interpreter") {
		t.Fatalf("replay refused for an unexpected reason (want a script rejection): %v", err)
	}
}

// buildOwnerBoundGroth16WAArtifact mirrors the shape CompileGroth16WA emits
// since F-233 — one PubKey constructor slot at byte 0 followed by
// OP_CHECKSIGVERIFY — with the ~700 KB verifier body left out.
func buildOwnerBoundGroth16WAArtifact() *RunarArtifact {
	art := buildFakeGroth16WAArtifact()
	art.Script = "00ad" // <ownerPubKey placeholder> OP_CHECKSIGVERIFY
	art.ABI.Constructor.Params = []ABIParam{{Name: "ownerPubKey", Type: "PubKey"}}
	art.ConstructorSlots = []ConstructorSlot{{ParamIndex: 0, ByteOffset: 0}}
	return art
}

// TestGroth16WASDK_Deploy_RefusesWithoutAValidOwner proves Deploy fails
// closed — before touching the provider — when the owner key is missing or
// malformed, or when the artifact predates F-233 and has no owner slot (its
// output would be spendable by any observer of a valid witness). It does not
// prove anything about the spend path.
func TestGroth16WASDK_Deploy_RefusesWithoutAValidOwner(t *testing.T) {
	signer := NewMockSigner("", "")
	provider := NewAlwaysAckMockProvider("mocknet")
	pub, _ := signer.GetPublicKey()

	cases := []struct {
		name     string
		artifact *RunarArtifact
		owner    string
		wantErr  string
	}{
		{"missing owner", buildOwnerBoundGroth16WAArtifact(), "", "owner public key is required"},
		{"not hex", buildOwnerBoundGroth16WAArtifact(), "zz" + strings.Repeat("00", 32), "not hex"},
		{"uncompressed length", buildOwnerBoundGroth16WAArtifact(), "04" + strings.Repeat("11", 64), "33-byte compressed"},
		{"off-curve x (x = 0: 7 is not a square mod p)", buildOwnerBoundGroth16WAArtifact(), "02" + strings.Repeat("00", 32), "not a valid secp256k1 point"},
		{"non-canonical x >= p", buildOwnerBoundGroth16WAArtifact(), "02" + strings.Repeat("ff", 32), "canonical"},
		{"owner param without a constructor slot", func() *RunarArtifact {
			a := buildOwnerBoundGroth16WAArtifact()
			a.ConstructorSlots = nil // would deploy OP_0 OP_CHECKSIGVERIFY: unspendable
			return a
		}(), pub, "no owner-pubkey constructor slot"},
		{"legacy unbound artifact", buildFakeGroth16WAArtifact(), pub, "no owner-pubkey constructor slot"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewGroth16WAContract(tc.artifact)
			_, _, err := g.Deploy(provider, signer, tc.owner, DeployOptions{Satoshis: 10_000})
			if err == nil {
				t.Fatalf("Deploy accepted owner %q", tc.owner)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Deploy error = %v, want it to mention %q", err, tc.wantErr)
			}
		})
	}
	if n := len(provider.GetBroadcastedTxs()); n != 0 {
		t.Fatalf("a refused Deploy broadcast %d transaction(s)", n)
	}
}

// TestGroth16WASDK_DeployThenCall_BindsTheDeployTimeOwner drives the real
// Deploy → CallWithWitness lifecycle through a validating MockProvider.
//
// Proves: Deploy splices the owner key into the artifact's slot (the deployed
// output is `<ownerPub> OP_CHECKSIGVERIFY`), and the spend CallWithWitness
// builds is accepted by the go-sdk interpreter only because it carries that
// owner's signature — a spend signed by a different key is refused.
// Does not prove: proof verification (no verifier body in this artifact).
func TestGroth16WASDK_DeployThenCall_BindsTheDeployTimeOwner(t *testing.T) {
	owner, err := NewLocalSigner("0000000000000000000000000000000000000000000000000000000000000003")
	if err != nil {
		t.Fatalf("NewLocalSigner: %v", err)
	}
	stranger, err := NewLocalSigner("0000000000000000000000000000000000000000000000000000000000000005")
	if err != nil {
		t.Fatalf("NewLocalSigner: %v", err)
	}
	ownerPub, _ := owner.GetPublicKey()
	ownerAddr, _ := owner.GetAddress()

	deployAndSpend := func(spender Signer) error {
		provider := NewMockProvider("testnet")
		provider.AddUtxo(ownerAddr, UTXO{
			Txid:        strings.Repeat("aa", 32),
			OutputIndex: 0,
			Satoshis:    500_000,
			Script:      BuildP2PKHScript(ownerAddr),
		})
		g := NewGroth16WAContract(buildOwnerBoundGroth16WAArtifact())
		if _, _, err := g.Deploy(provider, owner, ownerPub, DeployOptions{Satoshis: 50_000}); err != nil {
			t.Fatalf("Deploy: %v", err)
		}
		if got, want := g.CurrentUTXO().Script, "21"+ownerPub+"ad"; got != want {
			t.Fatalf("deployed locking script = %s, want %s", got, want)
		}
		_, _, err := g.CallWithWitness(provider, spender, buildFakeWitness(), ownerAddr, "")
		return err
	}

	if err := deployAndSpend(owner); err != nil {
		t.Fatalf("owner-signed spend refused: %v", err)
	}
	err = deployAndSpend(stranger)
	if err == nil {
		t.Fatal("a spend signed by a key other than the deploy-time owner was accepted")
	}
	if !strings.Contains(err.Error(), "REJECTED by the go-sdk interpreter") {
		t.Fatalf("stranger's spend refused for an unexpected reason (want a script rejection): %v", err)
	}
}
