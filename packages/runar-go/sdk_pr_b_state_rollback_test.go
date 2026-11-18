package runar

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"

	"github.com/bsv-blockchain/go-sdk/transaction"
)

// prBDeployGate compiles Gate, funds the signer on provider and deploys n = 0.
func prBDeployGate(t *testing.T, provider Provider, mock *MockProvider) (*RunarContract, Signer) {
	t.Helper()
	src := `import { StatefulSmartContract, assert } from 'runar-lang';
class Gate extends StatefulSmartContract {
  n: bigint;
  constructor(n: bigint) { super(n); this.n = n; }
  public bump(k: bigint) {
    assert(k === 7n);
    this.n = this.n + 1n;
  }
}`
	tmp := t.TempDir() + "/Gate.runar.ts"
	if err := os.WriteFile(tmp, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("go", "run", "../../compilers/go", "--source", tmp).Output()
	if err != nil {
		t.Fatalf("compile Gate: %v", err)
	}
	var art RunarArtifact
	if err := json.Unmarshal(out, &art); err != nil {
		t.Fatalf("unmarshal artifact: %v", err)
	}

	signer, err := NewLocalSigner(strings.Repeat("11", 32))
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	addr, _ := signer.GetAddress()
	mock.AddUtxo(addr, UTXO{
		Txid:        strings.Repeat("aa", 32),
		OutputIndex: 0,
		Satoshis:    5_000_000,
		Script:      BuildP2PKHScript(addr),
	})

	c := NewRunarContract(&art, []interface{}{int64(0)})
	if _, _, err := c.Deploy(provider, signer, DeployOptions{Satoshis: 50_000}); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	return c, signer
}

// PrepareCall advances the contract's local state to the post-call state
// BEFORE FinalizeCall broadcasts. When the broadcast was refused nothing put
// it back, so the next call was built from a state the chain never reached
// (same bug as the TS SDK, packages/runar-sdk/src/__tests__/pr-b-state-rollback.test.ts).
//
// Proves: after MockProvider refuses a call (its script replay fails the
// covenant), GetState() and GetCurrentUtxo() equal their pre-call values, and
// an honest follow-up call commits n = 1.
func TestPrBStateRollback_RefusedBroadcastLeavesStateUntouched(t *testing.T) {
	provider := NewMockProvider("testnet")
	c, signer := prBDeployGate(t, provider, provider)
	stateBefore := c.GetState()
	utxoBefore := c.GetCurrentUtxo()

	// k = 8 fails the covenant's assert: MockProvider refuses the broadcast.
	if _, _, err := c.Call("bump", []interface{}{int64(8)}, provider, signer, nil); err == nil {
		t.Fatalf("bump(8) succeeded, want a refused broadcast")
	}
	if got := c.GetState(); !reflect.DeepEqual(got, stateBefore) {
		t.Fatalf("state after refused bump(8) = %v, want %v (unchanged)", got, stateBefore)
	}
	if got := c.GetCurrentUtxo(); !reflect.DeepEqual(got, utxoBefore) {
		t.Fatalf("tracked UTXO after refused bump(8) = %+v, want %+v (unchanged)", got, utxoBefore)
	}

	if _, _, err := c.Call("bump", []interface{}{int64(7)}, provider, signer, nil); err != nil {
		t.Fatalf("bump(7): %v", err)
	}
	if got := anfToBigInt(c.GetState()["n"]).Int64(); got != 1 {
		t.Fatalf("state n after bump(7) = %d, want 1", got)
	}
}

// prBRefusingProvider is a MockProvider whose Broadcast fails while refuse is
// set, like a node rejecting the transaction.
type prBRefusingProvider struct {
	*MockProvider
	refuse bool
}

func (p *prBRefusingProvider) Broadcast(tx *transaction.Transaction) (string, error) {
	if p.refuse {
		return "", fmt.Errorf("node refused the transaction")
	}
	return p.MockProvider.Broadcast(tx)
}

// A PreparedCall whose broadcast was refused can be finalized again: the retry
// commits the post-call state. A further finalize of the now-committed
// PreparedCall that fails must not rewind the state the chain reached.
func TestPrBStateRollback_RetriedAndRepeatedFinalize(t *testing.T) {
	provider := &prBRefusingProvider{MockProvider: NewMockProvider("testnet")}
	c, signer := prBDeployGate(t, provider, provider.MockProvider)
	utxoBefore := c.GetCurrentUtxo()

	prepared, err := c.PrepareCall("bump", []interface{}{int64(7)}, provider, signer, nil)
	if err != nil {
		t.Fatalf("prepare bump(7): %v", err)
	}
	provider.refuse = true
	if _, _, err := c.FinalizeCall(prepared, map[int]string{}, provider); err == nil {
		t.Fatalf("finalize succeeded, want a refused broadcast")
	}
	if got := anfToBigInt(c.GetState()["n"]).Int64(); got != 0 {
		t.Fatalf("n after refused finalize = %d, want 0", got)
	}
	if got := c.GetCurrentUtxo(); !reflect.DeepEqual(got, utxoBefore) {
		t.Fatalf("tracked UTXO after refused finalize = %+v, want %+v", got, utxoBefore)
	}

	provider.refuse = false
	if _, _, err := c.FinalizeCall(prepared, map[int]string{}, provider); err != nil {
		t.Fatalf("retried finalize: %v", err)
	}
	if got := anfToBigInt(c.GetState()["n"]).Int64(); got != 1 {
		t.Fatalf("n after retried finalize = %d, want 1", got)
	}
	utxoAfter := c.GetCurrentUtxo()

	provider.refuse = true
	if _, _, err := c.FinalizeCall(prepared, map[int]string{}, provider); err == nil {
		t.Fatalf("repeated finalize succeeded, want a refused broadcast")
	}
	if got := anfToBigInt(c.GetState()["n"]).Int64(); got != 1 {
		t.Fatalf("n after a refused repeat of a committed finalize = %d, want 1", got)
	}
	if got := c.GetCurrentUtxo(); !reflect.DeepEqual(got, utxoAfter) {
		t.Fatalf("tracked UTXO after refused repeat = %+v, want %+v", got, utxoAfter)
	}
}
