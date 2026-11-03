package runar

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/bsv-blockchain/go-sdk/transaction"
)

// F-247 (CL-BUG-136, MEDIUM/P2): FinalizeCall broadcasts a 72-byte all-zero
// placeholder when a declared SigIndices slot is left unfilled.
//
// PrepareCall stubs every auto-signed Sig param with a 72-zero-byte
// placeholder and records its arg index in SigIndices. FinalizeCall only
// overwrote resolvedArgs[idx] for the indices actually present in the
// caller-supplied signatures map — nothing checked that every entry in
// prepared.SigIndices was covered before the primary unlocking script was
// assembled and handed to provider.Broadcast(). Ported from the TS fix in
// packages/runar-sdk/src/contract.ts.
//
// This test deliberately avoids MockProvider's always-ack constructor /
// validation toggle (which would need an always_ack_allowlist.json
// entry and the default validating MockProvider would mask the bug by
// rejecting the placeholder-signed broadcast for the WRONG reason — script
// invalidity caught AT broadcast time — rather than showing whether
// FinalizeCall refuses BEFORE calling provider.Broadcast() at all). Instead
// it hand-rolls a minimal Provider wrapper whose Broadcast acks anything,
// like a real network node that does not pre-validate scripts.

const f247SigCounterSrc = `import { StatefulSmartContract, assert, checkSig } from 'runar-lang';
import type { PubKey, Sig } from 'runar-lang';

class F247SigCounter extends StatefulSmartContract {
  count: bigint;
  readonly owner: PubKey;

  constructor(count: bigint, owner: PubKey) {
    super(count, owner);
    this.count = count;
    this.owner = owner;
  }

  public inc(sig: Sig) {
    assert(checkSig(sig, this.owner));
    this.count = this.count + 1n;
  }
}`

const f247PrivKeyHex = "0000000000000000000000000000000000000000000000000000000000000008"

// ackAnythingProvider delegates every read to an underlying MockProvider but
// Broadcast acks unconditionally — no script validation — mirroring a real
// network provider. Not a MockProvider always-ack usage: a plain hand-rolled
// Provider.
type ackAnythingProvider struct {
	inner         *MockProvider
	broadcastedTx []string
}

func (p *ackAnythingProvider) GetTransaction(txid string) (*TransactionData, error) {
	return p.inner.GetTransaction(txid)
}
func (p *ackAnythingProvider) GetUtxos(address string) ([]UTXO, error) {
	return p.inner.GetUtxos(address)
}
func (p *ackAnythingProvider) GetContractUtxo(scriptHash string) (*UTXO, error) {
	return p.inner.GetContractUtxo(scriptHash)
}
func (p *ackAnythingProvider) GetNetwork() string { return p.inner.GetNetwork() }
func (p *ackAnythingProvider) GetFeeRate() (int64, error) { return p.inner.GetFeeRate() }
func (p *ackAnythingProvider) GetRawTransaction(txid string) (string, error) {
	return p.inner.GetRawTransaction(txid)
}
func (p *ackAnythingProvider) Broadcast(tx *transaction.Transaction) (string, error) {
	rawTx := tx.Hex()
	p.broadcastedTx = append(p.broadcastedTx, rawTx)
	txid := tx.TxID().String()
	// Register with the inner mock (no validation) so subsequent lookups
	// resolve normally, same as a real provider would once accepted.
	p.inner.AddTransaction(broadcastTxData(txid, tx, rawTx))
	return txid, nil
}

func f247Deploy(t *testing.T) (*RunarContract, *ackAnythingProvider, *LocalSigner) {
	t.Helper()

	tmp := t.TempDir() + "/F247SigCounter.runar.ts"
	if err := os.WriteFile(tmp, []byte(f247SigCounterSrc), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("go", "run", "../../compilers/go", "--source", tmp).Output()
	if err != nil {
		t.Fatalf("compile F247SigCounter: %v", err)
	}
	var art RunarArtifact
	if err := json.Unmarshal(out, &art); err != nil {
		t.Fatalf("unmarshal artifact: %v", err)
	}

	signer, err := NewLocalSigner(f247PrivKeyHex)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	addr, _ := signer.GetAddress()
	pubKey, _ := signer.GetPublicKey()

	mock := NewMockProvider("testnet")
	mock.AddUtxo(addr, UTXO{
		Txid:        strings.Repeat("bb", 32),
		OutputIndex: 0,
		Satoshis:    500000,
		Script:      BuildP2PKHScript(addr),
	})
	provider := &ackAnythingProvider{inner: mock}

	c := NewRunarContract(&art, []interface{}{int64(0), pubKey})
	if _, _, err := c.Deploy(provider, signer, DeployOptions{Satoshis: 50000}); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	return c, provider, signer
}

// TestFinalizeCall_MissingSigIndex_Refuses_F247 is the RED/GREEN pin for the
// bug: with an unfilled declared SigIndices slot and no dry-run equivalent,
// FinalizeCall must refuse before reaching provider.Broadcast.
//
// What this test proves: calling FinalizeCall with an empty signatures map
// for a method with one declared SigIndices entry returns an error naming
// the missing index/method, and provider.Broadcast is never reached (the
// broadcastedTx slice does not grow).
//
// What this test does NOT prove: multi-signer (2+ SigIndices) coverage with
// SOME but not all slots filled — covered logically by the same missing-
// index scan in the fix, but not exercised by a dedicated fixture here.
func TestFinalizeCall_MissingSigIndex_Refuses_F247(t *testing.T) {
	c, provider, signer := f247Deploy(t)

	prepared, err := c.PrepareCall("inc", []interface{}{nil}, provider, signer, nil)
	if err != nil {
		t.Fatalf("PrepareCall: %v", err)
	}
	if len(prepared.SigIndices) != 1 {
		t.Fatalf("expected exactly 1 external Sig index, got %v", prepared.SigIndices)
	}

	broadcastCountBefore := len(provider.broadcastedTx)

	// Caller forgets the one declared signature slot entirely.
	_, _, err = c.FinalizeCall(prepared, map[int]string{}, provider)
	if err == nil {
		t.Fatal("FinalizeCall succeeded with a missing signature for a declared SigIndices slot; " +
			"want a refusal naming the missing index before broadcasting")
	}
	if !strings.Contains(err.Error(), "SigIndices") && !strings.Contains(strings.ToLower(err.Error()), "signature") {
		t.Fatalf("error does not name the missing signature slot: %v", err)
	}

	if len(provider.broadcastedTx) != broadcastCountBefore {
		t.Fatalf("provider.Broadcast was called despite the missing signature: "+
			"before=%d after=%d", broadcastCountBefore, len(provider.broadcastedTx))
	}
}
