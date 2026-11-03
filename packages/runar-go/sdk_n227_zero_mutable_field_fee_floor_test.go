package runar

import (
	"encoding/json"
	"math"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/bsv-blockchain/go-sdk/transaction"
)

// N-227 (port of sdk:ts N-085): a zero-mutable-field `StatefulSmartContract`
// call underpays MockProvider's 100 sat/KB fee floor.
//
// `AllReadonlyCleanstack` has ZERO mutable fields, so its `StateFields` is
// empty and `PrepareCall`'s `isStateful` is `false` — even though the
// contract IS `parentStateful` (ParentClass == "StatefulSmartContract") and
// still auto-injects `checkPreimage` / OP_CODESEPARATOR at method entry
// (its `claim` method carries a visible `txPreimage` ABI param, so
// `needsOpPushTx` is true via `preimageIndex >= 0`). That routes the call
// through `PrepareCall`'s "stateless" branch (`else if needsOpPushTx ||
// len(sigIndices) > 0`), which — before this fix — never recomputed
// fee/change from the REAL (final) unlocking script the way the
// `isStateful` branch's rebuild does.
//
// The injected OP_CODESEPARATOR sits right at method entry (index 1), so the
// BIP-143 scriptCode (everything after it) is almost the WHOLE locking
// script — far bigger than the 181-byte placeholder preimage the earlier
// sizing pass assumed. The real unlocking script ends up hundreds of bytes
// bigger than what fee/change were computed against, so the broadcast tx
// pays less than the fee its own (larger) byte size requires.
//
// What this test proves: the Go SDK's `claim()` call on a zero-mutable-field
// StatefulSmartContract broadcasts a tx whose actual fee (computed from the
// REAL broadcast bytes: sum(known input satoshis) - sum(output satoshis))
// meets the 100 sat/KB floor `MockProvider.GetFeeRate()` reports. It also
// relies on `MockProvider.Broadcast`'s default-on script-interpreter
// validation (see sdk_provider.go) to prove the rebuilt unlock is still a
// VALID spend of the locking script — not just correctly sized.
//
// What this test does NOT prove: the same fix in TypeScript (already fixed,
// N-085), Rust, Python, Zig, Ruby or Java — each tier is a separate item
// slot. It also does not prove anything about continuation-bearing
// (non-empty StateFields) stateful calls, which already take the
// `isStateful` branch and were unaffected by this bug, nor about a
// zero-mutable-field call that also merges `additionalContractInputs`
// (N-227 Part 2 — a separate fail-closed guard, not a fee question).
func TestN227_ZeroMutableFieldStatefulContract_CallPaysFeeFloor(t *testing.T) {
	src := `import { StatefulSmartContract, PubKey, Sig, assert, checkSig } from 'runar-lang';

class AllReadonlyCleanstack extends StatefulSmartContract {
  readonly owner: PubKey;

  constructor(owner: PubKey) {
    super(owner);
    this.owner = owner;
  }

  public claim(sig: Sig): void {
    const ownerCopy = this.owner;
    assert(checkSig(sig, this.owner));
  }
}
`
	tmp := t.TempDir() + "/AllReadonlyCleanstack.runar.ts"
	if err := os.WriteFile(tmp, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("go", "run", "../../compilers/go", "--source", tmp).Output()
	if err != nil {
		t.Fatalf("compile AllReadonlyCleanstack: %v", err)
	}
	var art RunarArtifact
	if err := json.Unmarshal(out, &art); err != nil {
		t.Fatalf("unmarshal artifact: %v", err)
	}

	// Sanity on the premise: zero mutable state fields, but still a real
	// StatefulSmartContract (auto-injects checkPreimage).
	if art.ParentClass != "StatefulSmartContract" {
		t.Fatalf("expected ParentClass StatefulSmartContract, got %q", art.ParentClass)
	}
	if len(art.StateFields) != 0 {
		t.Fatalf("expected zero StateFields, got %d", len(art.StateFields))
	}
	if art.CodeSeparatorIndex == nil {
		t.Fatalf("expected a non-nil CodeSeparatorIndex (checkPreimage must auto-inject OP_CODESEPARATOR)")
	}

	signer, err := NewLocalSigner("0000000000000000000000000000000000000000000000000000000000000003")
	if err != nil {
		t.Fatal(err)
	}
	addr, err := signer.GetAddress()
	if err != nil {
		t.Fatal(err)
	}
	pubKey, err := signer.GetPublicKey()
	if err != nil {
		t.Fatal(err)
	}

	provider := NewMockProvider("testnet") // Broadcast validation default-on (A5)
	provider.AddUtxo(addr, UTXO{
		Txid:        strings.Repeat("aa", 32),
		OutputIndex: 0,
		Satoshis:    100000,
		Script:      BuildP2PKHScript(addr),
	})

	contract := NewRunarContract(&art, []interface{}{pubKey})
	if _, _, err := contract.Deploy(provider, signer, DeployOptions{Satoshis: 5000, ChangeAddress: addr}); err != nil {
		t.Fatalf("deploy: %v", err)
	}

	// claim(sig, txPreimage): both auto-resolved (nil => SDK fills Sig +
	// SigHashPreimage). isStateful is false here, so neither param is
	// hidden from the caller — mirrors the TS N-085 repro's [null, null].
	if _, _, err := contract.Call("claim", []interface{}{nil, nil}, provider, signer, nil); err != nil {
		t.Fatalf("call claim: %v", err)
	}

	txs := provider.GetBroadcastedTxs()
	callHex := txs[len(txs)-1]
	callTx, parseErr := transaction.NewTransactionFromHex(callHex)
	if parseErr != nil {
		t.Fatalf("parse broadcast tx: %v", parseErr)
	}

	var totalOut int64
	for _, o := range callTx.Outputs {
		totalOut += int64(o.Satoshis)
	}

	// Total input value: the contract's own deployed UTXO (5000 sats) plus,
	// if a second input is present, the ONE funding UTXO this test registered
	// (100000 sats) — this test controls the entire UTXO universe, so the
	// input count alone determines which UTXOs were actually spent.
	totalIn := int64(5000)
	if len(callTx.Inputs) > 1 {
		totalIn += 100000
	}

	actualFee := totalIn - totalOut
	feeRate, _ := provider.GetFeeRate()
	txSizeBytes := int64(len(callHex) / 2)
	requiredFee := int64(math.Ceil(float64(txSizeBytes) * float64(feeRate) / 1000.0))

	if actualFee < requiredFee {
		t.Fatalf(
			"fee too low: paid %d sats, required >= %d sats (tx size %d bytes, fee rate %d sat/KB)",
			actualFee, requiredFee, txSizeBytes, feeRate,
		)
	}
}

// N-227 Part 2, retargeted by N-258 (user decision R99): a call that spends
// AdditionalContractInputs on a path with NO real per-input unlock builder
// must fail closed rather than broadcast an invalid tx.
//
// N-227 originally pinned this on the zero-mutable-field AllReadonlyCleanstack.
// N-258 gave that path real per-input unlocks (TestN258_..._MergeIsSpendValid
// proves the merge passes the go-sdk interpreter on every input) and narrowed
// the guard to the paths that still only have the SIZING placeholder: a plain
// SmartContract (no auto-injected checkPreimage, so no per-input preimage) or a
// caller-supplied preimage. This test pins the plain-SmartContract case.
//
// What this test proves: Call returns the guard's error, and broadcasts
// nothing, when AdditionalContractInputs is set on a plain SmartContract call.
// Both contract outpoints are known to the provider, so the error can only
// come from the guard.
//
// What this test does NOT prove: the caller-supplied-preimage case.
func TestN227_MergeWithoutPerInputUnlockBuilderIsRefused(t *testing.T) {
	src := `import { SmartContract, PubKey, Sig, assert, checkSig } from 'runar-lang';

class P2PKOnly extends SmartContract {
  readonly owner: PubKey;
  constructor(owner: PubKey) { super(owner); this.owner = owner; }
  public unlock(sig: Sig): void { assert(checkSig(sig, this.owner)); }
}
`
	tmp := t.TempDir() + "/P2PKOnly.runar.ts"
	if err := os.WriteFile(tmp, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("go", "run", "../../compilers/go", "--source", tmp).Output()
	if err != nil {
		t.Fatalf("compile P2PKOnly: %v", err)
	}
	var art RunarArtifact
	if err := json.Unmarshal(out, &art); err != nil {
		t.Fatalf("unmarshal artifact: %v", err)
	}
	if art.ParentClass != "SmartContract" {
		t.Fatalf("expected ParentClass SmartContract, got %q", art.ParentClass)
	}

	signer, err := NewLocalSigner("0000000000000000000000000000000000000000000000000000000000000003")
	if err != nil {
		t.Fatal(err)
	}
	addr, _ := signer.GetAddress()
	pubKey, _ := signer.GetPublicKey()
	lockingHex := NewRunarContract(&art, []interface{}{pubKey}).GetLockingScript()
	primary := UTXO{Txid: strings.Repeat("aa", 32), OutputIndex: 0, Satoshis: 5000, Script: lockingHex}
	extraUtxo := UTXO{Txid: strings.Repeat("cc", 32), OutputIndex: 1, Satoshis: 7000, Script: lockingHex}

	provider := NewMockProvider("testnet")
	provider.AddUtxo(addr, UTXO{Txid: strings.Repeat("bb", 32), OutputIndex: 0, Satoshis: 100000, Script: BuildP2PKHScript(addr)})
	provider.AddContractUtxo(lockingHex, &primary)
	provider.AddContractUtxo(lockingHex+":extra", &extraUtxo)

	contract, err := FromUtxo(&art, primary)
	if err != nil {
		t.Fatal(err)
	}
	_, _, callErr := contract.Call("unlock", []interface{}{nil}, provider, signer, &CallOptions{
		AdditionalContractInputs: []*UTXO{&extraUtxo},
	})
	if callErr == nil || !strings.Contains(callErr.Error(), "additionalContractInputs is not supported") {
		t.Fatalf("expected the additionalContractInputs guard to refuse, got %v", callErr)
	}
	if n := len(provider.GetBroadcastedTxs()); n != 0 {
		t.Fatalf("expected nothing broadcast, got %d tx(s)", n)
	}
}
