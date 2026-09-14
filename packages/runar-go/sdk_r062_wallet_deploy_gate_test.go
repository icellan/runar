package runar

import (
	"errors"
	"strings"
	"testing"
)

// R-062 — the unsound-primitive deploy gate must cover the WALLET funding path.
//
// RunarContract.Deploy refuses to fund an artifact the compiler marked unsound
// unless the caller names every listed primitive, and it bounds the script size
// first. DeployWithWallet is a SECOND funding path — a BRC-100 wallet creates
// and funds the transaction via CreateAction — and it ran NEITHER guard.
//
// Three cases per guard, because over-rejection here breaks every legitimate
// wallet deploy: the refusal, an ordinary artifact, and an acknowledged
// unsound one.

func unsoundWalletContract(primitives ...string) (*RunarContract, *MockWalletClient) {
	mockWallet := newMockWalletClient("")
	wp := NewWalletProvider(WalletProviderOptions{
		Wallet: mockWallet,
		Basket: "tokens",
	})
	artifact := makeArtifact("51", ABI{
		Constructor: ABIConstructor{Params: []ABIParam{}},
		Methods:     []ABIMethod{},
	}, func(a *RunarArtifact) {
		a.ContractName = "Sp1Rollup"
		a.UnsoundPrimitives = primitives
	})
	contract := NewRunarContract(artifact, []interface{}{})
	contract.Connect(wp, nil)
	return contract, mockWallet
}

func TestR062_DeployWithWallet_RefusesUnacknowledgedUnsoundArtifact(t *testing.T) {
	contract, mockWallet := unsoundWalletContract("verifySP1FRI")

	_, err := contract.DeployWithWallet(&DeployWithWalletOptions{Satoshis: 1000})
	if err == nil {
		t.Fatal("DeployWithWallet funded an artifact reaching an unacknowledged unsound primitive")
	}
	for _, want := range []string{"verifySP1FRI", "Sp1Rollup.DeployWithWallet", "AcknowledgeUnsound"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal does not mention %q: %v", want, err)
		}
	}
	if len(mockWallet.createdActions) != 0 {
		t.Errorf("the wallet was asked for coins before the gate ran: %d actions", len(mockWallet.createdActions))
	}
}

func TestR062_DeployWithWallet_ControlOrdinaryArtifactStillFunds(t *testing.T) {
	contract, mockWallet := unsoundWalletContract()

	result, err := contract.DeployWithWallet(&DeployWithWalletOptions{Satoshis: 1000})
	if err != nil {
		t.Fatalf("CONTROL: an ordinary artifact must still fund through the wallet: %v", err)
	}
	if result.Txid == "" {
		t.Error("expected non-empty txid")
	}
	if len(mockWallet.createdActions) != 1 {
		t.Errorf("expected 1 wallet action, got %d", len(mockWallet.createdActions))
	}
}

func TestR062_DeployWithWallet_ControlAcknowledgedUnsoundArtifactStillFunds(t *testing.T) {
	contract, mockWallet := unsoundWalletContract("verifySP1FRI")

	result, err := contract.DeployWithWallet(&DeployWithWalletOptions{
		Satoshis:           1000,
		AcknowledgeUnsound: []string{"verifySP1FRI"},
	})
	if err != nil {
		t.Fatalf("CONTROL: an acknowledged unsound artifact must still fund: %v", err)
	}
	if result.Txid == "" {
		t.Error("expected non-empty txid")
	}
	if len(mockWallet.createdActions) != 1 {
		t.Errorf("expected 1 wallet action, got %d", len(mockWallet.createdActions))
	}
}

func TestR062_DeployWithWallet_PartialAcknowledgementIsStillARefusal(t *testing.T) {
	contract, mockWallet := unsoundWalletContract("verifySP1FRI", "someFutureStub")

	_, err := contract.DeployWithWallet(&DeployWithWalletOptions{
		Satoshis:           1000,
		AcknowledgeUnsound: []string{"verifySP1FRI"},
	})
	if err == nil || !strings.Contains(err.Error(), "someFutureStub") {
		t.Fatalf("a partial acknowledgement must still be refused, naming the unnamed primitive: %v", err)
	}
	if len(mockWallet.createdActions) != 0 {
		t.Errorf("the wallet was asked for coins before the gate ran: %d actions", len(mockWallet.createdActions))
	}
}

// R-062 sibling: DeployWithWallet skipped the DoS script-size bound that
// Deploy runs. A pathological locking script reached the wallet unchecked.
func TestR062_DeployWithWallet_RefusesOversizeScript(t *testing.T) {
	mockWallet := newMockWalletClient("")
	wp := NewWalletProvider(WalletProviderOptions{Wallet: mockWallet, Basket: "tokens"})
	oversize := strings.Repeat("51", MaxScriptBytes+1)
	artifact := makeArtifact(oversize, ABI{
		Constructor: ABIConstructor{Params: []ABIParam{}},
		Methods:     []ABIMethod{},
	})
	contract := NewRunarContract(artifact, []interface{}{})
	contract.Connect(wp, nil)

	_, err := contract.DeployWithWallet(&DeployWithWalletOptions{Satoshis: 1000})
	var sizeErr *ScriptSizeExceededError
	if !errors.As(err, &sizeErr) {
		t.Fatalf("expected *ScriptSizeExceededError, got %v", err)
	}
	if !strings.Contains(sizeErr.Context, "DeployWithWallet") {
		t.Errorf("size error does not name the wallet deploy path: %q", sizeErr.Context)
	}
	if len(mockWallet.createdActions) != 0 {
		t.Errorf("the wallet was asked for coins before the bound ran: %d actions", len(mockWallet.createdActions))
	}
}
