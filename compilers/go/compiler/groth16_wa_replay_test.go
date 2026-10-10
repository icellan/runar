package compiler

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/script/interpreter"
	"github.com/bsv-blockchain/go-sdk/transaction"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"

	"github.com/icellan/runar/compilers/go/codegen"
	"github.com/icellan/runar/packages/runar-go/bn254witness"
)

// ---------------------------------------------------------------------------
// F-233 — a standalone groth16-wa UTXO must not be spendable by whoever sees
// a valid spend's witness.
//
// A Groth16 witness proves a STATEMENT; it says nothing about which
// transaction it is attached to. If the locking script checks only the proof,
// the ~700 KB unlocking script of an honest spend is public the moment it
// reaches the mempool, and any observer can copy it verbatim into a
// transaction paying themselves. CompileGroth16WA therefore binds the spend to
// an owner key chosen at deploy time (a PubKey constructor slot followed by
// OP_CHECKSIGVERIFY): the unlock is `witness ‖ <ownerSig>`, and the signature
// commits (BIP-143, SIGHASH_ALL|FORKID) to the spending transaction's outputs.
//
// Every spend below runs through the go-sdk script interpreter WITH a real
// transaction context, so OP_CHECKSIG verifies a real secp256k1 signature
// over a real sighash — no mock crypto.
// ---------------------------------------------------------------------------

// groth16TestKey returns a deterministic secp256k1 key derived from `fill`.
func groth16TestKey(fill byte) *ec.PrivateKey {
	priv, _ := ec.PrivateKeyFromBytes(bytes.Repeat([]byte{fill}, 32))
	return priv
}

// groth16DeployedLockHex is what the SDK deploys: the artifact template with
// its owner-pubkey constructor slot (if it has one) replaced by a push of
// `ownerPub`. An artifact with no constructor slot is deployed verbatim.
func groth16DeployedLockHex(t *testing.T, art *Artifact, ownerPub []byte) string {
	t.Helper()
	if len(art.ConstructorSlots) == 0 {
		return art.Script
	}
	if len(art.ConstructorSlots) != 1 || art.ConstructorSlots[0].ParamIndex != 0 {
		t.Fatalf("expected exactly one constructor slot (ownerPubKey, param 0), got %+v", art.ConstructorSlots)
	}
	off := art.ConstructorSlots[0].ByteOffset * 2
	if art.Script[off:off+2] != "00" {
		t.Fatalf("constructor slot at byte %d is %q, want the OP_0 placeholder", off/2, art.Script[off:off+2])
	}
	push := hex.EncodeToString([]byte{byte(len(ownerPub))}) + hex.EncodeToString(ownerPub)
	return art.Script[:off] + push + art.Script[off+2:]
}

// groth16WitnessHex serializes a witness bundle as raw unlocking pushes.
func groth16WitnessHex(t *testing.T, w *bn254witness.Witness) string {
	t.Helper()
	res, err := codegen.Emit([]codegen.StackMethod{{Name: "witness", Ops: w.ToStackOps()}})
	if err != nil {
		t.Fatalf("emit witness pushes: %v", err)
	}
	return res.ScriptHex
}

// groth16SpendTx builds a one-input / one-output transaction spending a
// 100 000-sat UTXO locked by lockHex to payTo. The unlocking script is left
// empty; set it with groth16SetUnlock.
func groth16SpendTx(t *testing.T, lockHex string, payTo *script.Script) (*transaction.Transaction, *transaction.TransactionOutput) {
	t.Helper()
	lock, err := script.NewFromHex(lockHex)
	if err != nil {
		t.Fatalf("parse locking script: %v", err)
	}
	prevOut := &transaction.TransactionOutput{Satoshis: 100_000, LockingScript: lock}
	srcTxid, err := chainhash.NewHash(bytes.Repeat([]byte{0xab}, 32))
	if err != nil {
		t.Fatalf("chainhash: %v", err)
	}
	tx := transaction.NewTransaction()
	tx.AddInputWithOutput(&transaction.TransactionInput{
		SourceTXID:       srcTxid,
		SourceTxOutIndex: 0,
		SequenceNumber:   transaction.DefaultSequenceNumber,
	}, prevOut)
	tx.AddOutput(&transaction.TransactionOutput{Satoshis: 99_000, LockingScript: payTo})
	return tx, prevOut
}

// groth16SigPushHex signs input 0 of tx (SIGHASH_ALL|FORKID) with priv and
// returns the signature as a push-data hex fragment.
func groth16SigPushHex(t *testing.T, tx *transaction.Transaction, priv *ec.PrivateKey) string {
	t.Helper()
	h, err := tx.CalcInputSignatureHash(0, sighash.AllForkID)
	if err != nil {
		t.Fatalf("sighash: %v", err)
	}
	sig, err := priv.Sign(h)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	der := append(sig.Serialize(), byte(sighash.AllForkID))
	s := &script.Script{}
	if err := s.AppendPushData(der); err != nil {
		t.Fatalf("push sig: %v", err)
	}
	return hex.EncodeToString(*s)
}

// groth16HonestUnlockHex is the owner's unlock for tx: the witness, followed
// by the owner's signature over tx when the artifact binds an owner key.
func groth16HonestUnlockHex(t *testing.T, art *Artifact, tx *transaction.Transaction, witnessHex string, owner *ec.PrivateKey) string {
	t.Helper()
	if len(art.ConstructorSlots) == 0 {
		return witnessHex
	}
	return witnessHex + groth16SigPushHex(t, tx, owner)
}

func groth16SetUnlock(t *testing.T, tx *transaction.Transaction, unlockHex string) {
	t.Helper()
	u, err := script.NewFromHex(unlockHex)
	if err != nil {
		t.Fatalf("parse unlocking script: %v", err)
	}
	tx.Inputs[0].UnlockingScript = u
}

// groth16ExecuteSpend runs input 0 of tx against prevOut through the go-sdk
// interpreter with full transaction context (real OP_CHECKSIG).
func groth16ExecuteSpend(tx *transaction.Transaction, prevOut *transaction.TransactionOutput) error {
	return interpreter.NewEngine().Execute(
		interpreter.WithTx(tx, 0, prevOut),
		interpreter.WithAfterGenesis(),
		interpreter.WithAfterChronicle(),
		interpreter.WithForkID(),
	)
}

func groth16PayTo(fill byte) *script.Script {
	s, _ := script.NewFromHex("76a914" + strings.Repeat(hex.EncodeToString([]byte{fill}), 20) + "88ac")
	return s
}

// TestCompileGroth16WA_ObservedWitnessCannotBeReplayedToAnotherPayee is the
// F-233 gate.
//
// Proves: (1) the owner's honest spend of a CompileGroth16WA output — a valid
// proof of the pinned statement plus the owner's signature over that exact
// transaction — is ACCEPTED by the go-sdk interpreter; (2) an observer who
// copies that spend's unlocking script byte-for-byte into a transaction
// paying themselves is REJECTED; (3) the observer cannot rescue the replay by
// re-signing with their own key, nor by dropping the signature.
//
// Does not prove: anything about the proof-verification half of the script
// (that is groth16_wa_binding_test.go's job), on-chain acceptance by a real
// node (integration/go covers regtest), or the Mode-3 stateful path, which
// binds via checkPreimage and does not go through CompileGroth16WA.
func TestCompileGroth16WA_ObservedWitnessCannotBeReplayedToAnotherPayee(t *testing.T) {
	s := newSynthGroth16(t)
	honest := honestPublicInputs(t)
	proof := s.proofFor(honest)
	s.sanityCheck(t, proof, honest)

	art, err := CompileGroth16WA(s.vkPath, Groth16WAOpts{PublicInputs: honest})
	if err != nil {
		t.Fatalf("CompileGroth16WA: %v", err)
	}

	owner := groth16TestKey(0x11)
	attacker := groth16TestKey(0x22)
	lockHex := groth16DeployedLockHex(t, art, owner.PubKey().Compressed())
	witnessHex := groth16WitnessHex(t, buildWitness(t, layoutMSM, s.vk, proof, honest))

	// 1. The owner's honest spend, paying the owner.
	honestTx, prevOut := groth16SpendTx(t, lockHex, groth16PayTo(0x11))
	honestUnlock := groth16HonestUnlockHex(t, art, honestTx, witnessHex, owner)
	groth16SetUnlock(t, honestTx, honestUnlock)
	if err := groth16ExecuteSpend(honestTx, prevOut); err != nil {
		t.Fatalf("the owner's honest spend was REJECTED, so no conclusion about replay is possible: %v", err)
	}

	// 2. The replay: the observed unlocking script, verbatim, in a
	//    transaction that pays the attacker instead.
	replayTx, prevOut := groth16SpendTx(t, lockHex, groth16PayTo(0x22))
	groth16SetUnlock(t, replayTx, honestUnlock)
	err = groth16ExecuteSpend(replayTx, prevOut)
	if err == nil {
		t.Fatal("REPLAY ACCEPTED: an observer copied the honest spend's unlocking script into a transaction paying themselves and the standalone Groth16 verifier accepted it — the UTXO is front-runnable by anyone who sees the mempool")
	}
	// The replay must die on the owner signature, not on something incidental
	// (a malformed tx, a stack-layout accident) that a later change could fix.
	if !strings.Contains(err.Error(), "OP_CHECKSIGVERIFY") {
		t.Fatalf("replay rejected, but not by the owner-signature check: %v", err)
	}

	// 3a. The attacker re-signs the replay with their own key.
	resignTx, prevOut := groth16SpendTx(t, lockHex, groth16PayTo(0x22))
	groth16SetUnlock(t, resignTx, witnessHex+groth16SigPushHex(t, resignTx, attacker))
	if err := groth16ExecuteSpend(resignTx, prevOut); err == nil {
		t.Fatal("REPLAY ACCEPTED: the verifier accepted the observed witness signed by a key other than the deploy-time owner")
	}

	// 3b. The attacker drops the signature and pushes only the witness.
	stripTx, prevOut := groth16SpendTx(t, lockHex, groth16PayTo(0x22))
	groth16SetUnlock(t, stripTx, witnessHex)
	if err := groth16ExecuteSpend(stripTx, prevOut); err == nil {
		t.Fatal("REPLAY ACCEPTED: the verifier accepted the bare observed witness with no owner signature")
	}
}
