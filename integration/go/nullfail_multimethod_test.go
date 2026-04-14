//go:build integration

package integration

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"testing"

	"runar-integration/helpers"

	runar "github.com/icellan/runar/packages/runar-go"
)

// 4-method contract: advanceState (no checkSig) + freeze/unfreeze/upgrade (checkSig)
// Regression test for NULLFAIL bug in multi-method stateful contracts.
const fourMethodSource = `
import {
  StatefulSmartContract, assert, checkSig, hash256, cat,
} from 'runar-lang';
import type { PubKey, Sig, ByteString } from 'runar-lang';

class RollupContract extends StatefulSmartContract {
  stateRoot: ByteString;
  blockNumber: bigint;
  frozen: bigint;
  readonly governanceKey: PubKey;
  readonly verifyingKeyHash: ByteString;

  constructor(stateRoot: ByteString, blockNumber: bigint, frozen: bigint,
              governanceKey: PubKey, verifyingKeyHash: ByteString) {
    super(stateRoot, blockNumber, frozen, governanceKey, verifyingKeyHash);
    this.stateRoot = stateRoot;
    this.blockNumber = blockNumber;
    this.frozen = frozen;
    this.governanceKey = governanceKey;
    this.verifyingKeyHash = verifyingKeyHash;
  }

  public advanceState(newStateRoot: ByteString, newBlockNumber: bigint,
                      batchData: ByteString, proofBlob: ByteString) {
    assert(this.frozen === 0n);
    assert(newBlockNumber > this.blockNumber);
    const expectedHash = hash256(cat(this.stateRoot, newStateRoot));
    assert(hash256(batchData) === expectedHash);
    this.stateRoot = newStateRoot;
    this.blockNumber = newBlockNumber;
  }

  public freeze(sig: Sig) {
    assert(checkSig(sig, this.governanceKey));
    this.frozen = 1n;
  }

  public unfreeze(sig: Sig) {
    assert(checkSig(sig, this.governanceKey));
    assert(this.frozen === 1n);
    this.frozen = 0n;
  }

  public upgrade(sig: Sig, newVerifyingKeyHash: ByteString) {
    assert(checkSig(sig, this.governanceKey));
  }
}
`

func nfSha256(data string) string {
	b, _ := hex.DecodeString(data)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func nfStateRoot(n int) string {
	return nfSha256("aa" + hex.EncodeToString([]byte{byte(n)}))
}

// TestNullFailMultiMethod_Chain10Advances chains 10 advanceState calls on
// a 4-method contract where 3 methods use checkSig. This reproduces a
// NULLFAIL bug where float64→int64 truncation in UTXO satoshi conversion
// caused the P2PKH funding input's BIP-143 sighash to be wrong by 1 sat.
var nfArtifact *runar.RunarArtifact
var nfOnce sync.Once

func getNFArtifact(t *testing.T) *runar.RunarArtifact {
	nfOnce.Do(func() {
		var err error
		nfArtifact, err = helpers.CompileSourceStringToSDKArtifact(
			fourMethodSource, "RollupContract.runar.ts", nil,
		)
		if err != nil {
			t.Fatalf("compile RollupContract: %v", err)
		}
	})
	return nfArtifact
}

func TestNullFailMultiMethod_Chain10Advances(t *testing.T) {
	artifact := getNFArtifact(t)

	wallet := helpers.NewWallet()
	helpers.RPCCall("importaddress", wallet.Address, "", false)
	if _, err := helpers.FundWallet(wallet, 5.0); err != nil {
		t.Fatalf("fund: %v", err)
	}

	provider := helpers.NewBatchRPCProvider()
	defer provider.MineAll()
	signer, err := helpers.SDKSignerFromWallet(wallet)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	pubKey, _ := signer.GetPublicKey()
	vkHash := "cc" + "0000000000000000000000000000000000000000000000000000000000000000"[0:62]
	initialRoot := "0000000000000000000000000000000000000000000000000000000000000000"

	contract := runar.NewRunarContract(artifact, []interface{}{
		initialRoot, int64(0), int64(0), pubKey, vkHash,
	})

	if _, _, err := contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 1000000}); err != nil {
		t.Fatalf("deploy: %v", err)
	}

	prevRoot := initialRoot
	proofBlob := "ff" + "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
	for block := int64(1); block <= 10; block++ {
		newRoot := nfStateRoot(int(block))
		batchData := prevRoot + newRoot

		txid, _, err := contract.Call("advanceState", []interface{}{newRoot, block, batchData, proofBlob}, provider, signer, nil)
		if err != nil {
			t.Fatalf("advance to block %d FAILED: %v", block, err)
		}
		t.Logf("block %d: %s", block, txid)
		prevRoot = newRoot
	}
}

// TestNullFailMultiMethod_Freeze tests calling a checkSig method (freeze)
// after an advanceState call.
func TestNullFailMultiMethod_Freeze(t *testing.T) {
	artifact := getNFArtifact(t)

	wallet := helpers.NewWallet()
	helpers.RPCCall("importaddress", wallet.Address, "", false)
	if _, err := helpers.FundWallet(wallet, 1.0); err != nil {
		t.Fatalf("fund: %v", err)
	}

	provider := helpers.NewBatchRPCProvider()
	defer provider.MineAll()
	signer, err := helpers.SDKSignerFromWallet(wallet)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	pubKey, _ := signer.GetPublicKey()
	vkHash := "cc" + "0000000000000000000000000000000000000000000000000000000000000000"[0:62]
	initialRoot := "0000000000000000000000000000000000000000000000000000000000000000"

	contract := runar.NewRunarContract(artifact, []interface{}{
		initialRoot, int64(0), int64(0), pubKey, vkHash,
	})

	if _, _, err := contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 100000}); err != nil {
		t.Fatalf("deploy: %v", err)
	}

	// Advance state first
	newRoot := nfStateRoot(1)
	batchData := initialRoot + newRoot
	if _, _, err := contract.Call("advanceState", []interface{}{newRoot, int64(1), batchData, "ff"}, provider, signer, nil); err != nil {
		t.Fatalf("advanceState: %v", err)
	}

	// Then freeze (checkSig method)
	txid, _, err := contract.Call("freeze", []interface{}{nil}, provider, signer, nil)
	if err != nil {
		t.Fatalf("freeze: %v", err)
	}
	t.Logf("freeze tx: %s", txid)
}
