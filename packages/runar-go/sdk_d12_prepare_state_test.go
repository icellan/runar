package runar

import (
	"fmt"
	"testing"

	"github.com/bsv-blockchain/go-sdk/transaction"
)

// d12FlakyProvider fails one provider call on demand, like a 503 from the
// fee-rate endpoint or an ECONNRESET on the UTXO lookup.
type d12FlakyProvider struct {
	*MockProvider
	failUtxos   bool
	failFeeRate bool
	refuse      bool
}

func (p *d12FlakyProvider) GetUtxos(address string) ([]UTXO, error) {
	if p.failUtxos {
		return nil, fmt.Errorf("ECONNRESET")
	}
	return p.MockProvider.GetUtxos(address)
}

func (p *d12FlakyProvider) GetFeeRate() (int64, error) {
	if p.failFeeRate {
		return 0, fmt.Errorf("503")
	}
	return p.MockProvider.GetFeeRate()
}

func (p *d12FlakyProvider) Broadcast(tx *transaction.Transaction) (string, error) {
	if p.refuse {
		return "", fmt.Errorf("node refused the transaction")
	}
	return p.MockProvider.Broadcast(tx)
}

// d12DecliningSigner declines every signature (hardware wallet "user declined").
type d12DecliningSigner struct{ Signer }

func (d12DecliningSigner) Sign(string, int, string, int64, *int) (string, error) {
	return "", fmt.Errorf("user declined")
}

func d12N(t *testing.T, c *RunarContract) int64 {
	t.Helper()
	return anfToBigInt(c.GetState()["n"]).Int64()
}

// D12 SDK-F1: a PrepareCall that fails after deriving the post-call state
// (UTXO lookup, fee rate, funding signer, maxFundingInputs) must leave the
// tracked state at the pre-call value, so the next honest call is accepted by
// the validating MockProvider (go-sdk interpreter replay).
func TestD12_PrepareCallErrorLeavesStateUntouched(t *testing.T) {
	cases := []struct {
		name string
		arm  func(p *d12FlakyProvider, s Signer) *CallOptions
	}{
		{"getUtxos", func(p *d12FlakyProvider, s Signer) *CallOptions { p.failUtxos = true; return nil }},
		{"getFeeRate", func(p *d12FlakyProvider, s Signer) *CallOptions { p.failFeeRate = true; return nil }},
		{"fundingSignerDeclines", func(p *d12FlakyProvider, s Signer) *CallOptions {
			return &CallOptions{FundingSigner: d12DecliningSigner{s}}
		}},
		{"maxFundingInputs0", func(p *d12FlakyProvider, s Signer) *CallOptions {
			zero := 0
			return &CallOptions{MaxFundingInputs: &zero}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			provider := &d12FlakyProvider{MockProvider: NewMockProvider("testnet")}
			c, signer := prBDeployGate(t, provider, provider.MockProvider)
			opts := tc.arm(provider, signer)
			if _, _, err := c.Call("bump", []interface{}{int64(7)}, provider, signer, opts); err == nil {
				t.Fatalf("call succeeded, want the injected %s failure", tc.name)
			}
			if got := d12N(t, c); got != 0 {
				t.Fatalf("n after failed call = %d, want 0 (chain is still at 0)", got)
			}
			provider.failUtxos, provider.failFeeRate = false, false
			if _, _, err := c.Call("bump", []interface{}{int64(7)}, provider, signer, nil); err != nil {
				t.Fatalf("follow-up honest call refused: %v", err)
			}
			if got := d12N(t, c); got != 1 {
				t.Fatalf("n after follow-up = %d, want 1", got)
			}
		})
	}
}

// D12 SDK-F2: PrepareCall does not change the tracked state; FinalizeCall
// commits on success. An abandoned PreparedCall needs no cleanup, and a
// failed finalize of one PreparedCall cannot clobber another's commit.
func TestD12_AbandonedAndSupersededPreparedCall(t *testing.T) {
	provider := &d12FlakyProvider{MockProvider: NewMockProvider("testnet")}
	c, signer := prBDeployGate(t, provider, provider.MockProvider)

	if _, err := c.PrepareCall("bump", []interface{}{int64(7)}, provider, signer, nil); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if got := d12N(t, c); got != 0 {
		t.Fatalf("n after an abandoned PrepareCall = %d, want 0", got)
	}

	a, err := c.PrepareCall("bump", []interface{}{int64(7)}, provider, signer, nil)
	if err != nil {
		t.Fatalf("prepare A: %v", err)
	}
	b, err := c.PrepareCall("bump", []interface{}{int64(7)}, provider, signer, nil)
	if err != nil {
		t.Fatalf("prepare B: %v", err)
	}
	if got := d12N(t, c); got != 0 {
		t.Fatalf("n after two PrepareCalls = %d, want 0", got)
	}
	provider.refuse = true
	if _, _, err := c.FinalizeCall(b, map[int]string{}, provider); err == nil {
		t.Fatalf("finalize B succeeded, want refused")
	}
	if got := d12N(t, c); got != 0 {
		t.Fatalf("n after refused finalize B = %d, want 0", got)
	}
	provider.refuse = false
	if _, _, err := c.FinalizeCall(a, map[int]string{}, provider); err != nil {
		t.Fatalf("finalize A: %v", err)
	}
	if got := d12N(t, c); got != 1 {
		t.Fatalf("n after finalize A = %d, want 1", got)
	}
	// B now spends the UTXO A consumed (a real node refuses it; MockProvider
	// tracks no spends). Either way it must not move the tracked state off A.
	provider.refuse = true
	_, _, _ = c.FinalizeCall(b, map[int]string{}, provider)
	provider.refuse = false
	if got := d12N(t, c); got != 1 {
		t.Fatalf("n after refused stale finalize B = %d, want 1", got)
	}
	if _, _, err := c.Call("bump", []interface{}{int64(7)}, provider, signer, nil); err != nil {
		t.Fatalf("follow-up call refused: %v", err)
	}
	if got := d12N(t, c); got != 2 {
		t.Fatalf("n after follow-up = %d, want 2", got)
	}
}
