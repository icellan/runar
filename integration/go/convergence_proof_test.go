//go:build integration

package integration

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"

	"runar-integration/helpers"

	runar "github.com/icellan/runar/packages/runar-go"
)

func TestConvergenceProof_Compile(t *testing.T) {
	artifact, err := helpers.CompileToSDKArtifact(
		"examples/ts/convergence-proof/ConvergenceProof.runar.ts",
		map[string]interface{}{},
	)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if artifact.ContractName != "ConvergenceProof" {
		t.Fatalf("expected contract name ConvergenceProof, got %s", artifact.ContractName)
	}
	t.Logf("ConvergenceProof compiled: %d bytes", len(artifact.Script)/2)
}

func TestConvergenceProof_Deploy(t *testing.T) {
	a, _ := rand.Int(rand.Reader, ecN)
	b, _ := rand.Int(rand.Reader, ecN)

	rAx, rAy := ecMul(ecGx, ecGy, a)
	rBx, rBy := ecMul(ecGx, ecGy, b)

	rAHex := fmt.Sprintf("%064x%064x", rAx, rAy)
	rBHex := fmt.Sprintf("%064x%064x", rBx, rBy)

	artifact, err := helpers.CompileToSDKArtifact(
		"examples/ts/convergence-proof/ConvergenceProof.runar.ts",
		map[string]interface{}{},
	)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	contract := runar.NewRunarContract(artifact, []interface{}{rAHex, rBHex})

	wallet := helpers.NewWallet()
	helpers.RPCCall("importaddress", wallet.Address, "", false)
	_, err = helpers.FundWallet(wallet, 1.0)
	if err != nil {
		t.Fatalf("fund: %v", err)
	}

	provider := helpers.NewRPCProvider()
	signer, err := helpers.SDKSignerFromWallet(wallet)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	txid, _, err := contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 500000})
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if len(txid) != 64 {
		t.Fatalf("expected 64-char txid, got %d", len(txid))
	}
	t.Logf("deployed: %s", txid)
}

func TestConvergenceProof_ValidProof(t *testing.T) {
	// ConvergenceProof: SmartContract with EC point operations
	// proveConvergence(deltaO: bigint) — proves rA - rB = deltaO * G

	// Pick random scalars a and b, compute rA = a*G, rB = b*G
	a, _ := rand.Int(rand.Reader, ecN)
	b, _ := rand.Int(rand.Reader, ecN)
	deltaO := new(big.Int).Sub(a, b)
	deltaO.Mod(deltaO, ecN)

	rAx, rAy := ecMul(ecGx, ecGy, a)
	rBx, rBy := ecMul(ecGx, ecGy, b)

	rAHex := fmt.Sprintf("%064x%064x", rAx, rAy)
	rBHex := fmt.Sprintf("%064x%064x", rBx, rBy)

	artifact, err := helpers.CompileToSDKArtifact(
		"examples/ts/convergence-proof/ConvergenceProof.runar.ts",
		map[string]interface{}{},
	)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	t.Logf("ConvergenceProof script: %d bytes", len(artifact.Script)/2)

	// Constructor args in declaration order: rA, rB
	contract := runar.NewRunarContract(artifact, []interface{}{rAHex, rBHex})

	wallet := helpers.NewWallet()
	helpers.RPCCall("importaddress", wallet.Address, "", false)
	_, err = helpers.FundWallet(wallet, 1.0)
	if err != nil {
		t.Fatalf("fund: %v", err)
	}

	provider := helpers.NewRPCProvider()
	signer, err := helpers.SDKSignerFromWallet(wallet)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	deployTxid, _, err := contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 500000})
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	t.Logf("deployed: %s", deployTxid)

	callTxid, _, err := contract.Call("proveConvergence", []interface{}{deltaO}, provider, signer, nil)
	if err != nil {
		t.Fatalf("call proveConvergence: %v", err)
	}
	t.Logf("proveConvergence TX confirmed: %s", callTxid)
}

func TestConvergenceProof_WrongDelta_Rejected(t *testing.T) {
	a, _ := rand.Int(rand.Reader, ecN)
	b, _ := rand.Int(rand.Reader, ecN)

	rAx, rAy := ecMul(ecGx, ecGy, a)
	rBx, rBy := ecMul(ecGx, ecGy, b)

	rAHex := fmt.Sprintf("%064x%064x", rAx, rAy)
	rBHex := fmt.Sprintf("%064x%064x", rBx, rBy)

	artifact, err := helpers.CompileToSDKArtifact(
		"examples/ts/convergence-proof/ConvergenceProof.runar.ts",
		map[string]interface{}{},
	)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	contract := runar.NewRunarContract(artifact, []interface{}{rAHex, rBHex})

	wallet := helpers.NewWallet()
	helpers.RPCCall("importaddress", wallet.Address, "", false)
	_, err = helpers.FundWallet(wallet, 1.0)
	if err != nil {
		t.Fatalf("fund: %v", err)
	}

	provider := helpers.NewRPCProvider()
	signer, err := helpers.SDKSignerFromWallet(wallet)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	_, _, err = contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 500000})
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}

	// Wrong deltaO — should be rejected
	wrongDelta := big.NewInt(42)
	_, _, err = contract.Call("proveConvergence", []interface{}{wrongDelta}, provider, signer, nil)
	if err == nil {
		t.Fatalf("expected call with wrong delta to be rejected, but it succeeded")
	}
	t.Logf("correctly rejected: %v", err)
}

// bigIntToScriptNumHex encodes a *big.Int as a Bitcoin Script number hex string.
func bigIntToScriptNumHex(n *big.Int) string {
	if n.Sign() == 0 {
		return ""
	}

	abs := new(big.Int).Abs(n)
	absBytes := abs.Bytes() // big-endian
	le := make([]byte, len(absBytes))
	for i, b := range absBytes {
		le[len(absBytes)-1-i] = b
	}

	if le[len(le)-1]&0x80 != 0 {
		if n.Sign() < 0 {
			le = append(le, 0x80)
		} else {
			le = append(le, 0x00)
		}
	} else if n.Sign() < 0 {
		le[len(le)-1] |= 0x80
	}

	return hex.EncodeToString(le)
}
