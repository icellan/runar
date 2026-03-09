package contract

import (
	"testing"
	runar "github.com/icellan/runar/packages/runar-go"
)

func newVault() *CovenantVault {
	return &CovenantVault{
		Owner:     runar.MockPubKey(),
		Recipient: runar.Hash160(runar.MockPubKey()),
		MinAmount: 1000,
	}
}

// Native execution tests for CovenantVault are limited because the
// covenant rule (hash256(output) == extractOutputHash(txPreimage))
// requires a real sighash preimage with matching hashOutputs. The
// mock preimage doesn't produce a meaningful hashOutputs, so we
// only test compilation here. The contract logic is fully verified
// by the TS test suite and conformance golden files.

func TestCovenantVault_Compile(t *testing.T) {
	if err := runar.CompileCheck("CovenantVault.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}
