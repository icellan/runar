//go:build integration

package integration

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"testing"

	"runar-integration/helpers"

	runar "github.com/icellan/runar/packages/runar-go"
)

// 4-method contract: advanceState (no checkSig) + freeze/unfreeze/upgrade (checkSig)
// Matches the NULLFAIL reproduction pattern from the bsv-evm bug report.
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

func nfHash256(data string) string {
	return nfSha256(nfSha256(data))
}

func nfStateRoot(n int) string {
	return nfSha256("aa" + hex.EncodeToString([]byte{byte(n)}))
}

func TestNullFailMultiMethod_Chain10Advances(t *testing.T) {
	artifact, err := helpers.CompileSourceStringToSDKArtifact(
		fourMethodSource, "RollupContract.runar.ts", nil,
	)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	t.Logf("script: %d bytes, constructorSlots: %d, codeSepIndexSlots: %d",
		len(artifact.Script)/2,
		len(artifact.ConstructorSlots),
		len(artifact.CodeSepIndexSlots))

	wallet := helpers.NewWallet()
	helpers.RPCCall("importaddress", wallet.Address, "", false)
	if _, err := helpers.FundWallet(wallet, 5.0); err != nil {
		t.Fatalf("fund: %v", err)
	}

	provider := helpers.NewRPCProvider()
	signer, err := helpers.SDKSignerFromWallet(wallet)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	pubKey, _ := signer.GetPublicKey()
	vkHash := "cc" + "0000000000000000000000000000000000000000000000000000000000000000"[0:62]
	initialRoot := "0000000000000000000000000000000000000000000000000000000000000000"

	contract := runar.NewRunarContract(artifact, []interface{}{
		initialRoot,
		int64(0),
		int64(0),
		pubKey,
		vkHash,
	})

	txid, _, err := contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 1000000})
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	t.Logf("deployed: %s", txid)

	prevRoot := initialRoot
	for block := int64(1); block <= 10; block++ {
		newRoot := nfStateRoot(int(block))
		batchData := prevRoot + newRoot // cat(prevRoot, newRoot)
		proofBlob := "ff" + "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" // 100-byte dummy proof

		args := []interface{}{
			newRoot,
			block,
			batchData,
			proofBlob,
		}

		// Diagnostic: print UTXO being spent
		utxo := contract.GetCurrentUtxo()
		t.Logf("block %d: spending UTXO %s:%d (sats=%d, script_len=%d)",
			block, utxo.Txid, utxo.OutputIndex, utxo.Satoshis, len(utxo.Script)/2)
		t.Logf("block %d: locking script tail (last 40 hex): ...%s", block, utxo.Script[max(0, len(utxo.Script)-40):])

		// Log the new locking script BEFORE the call (what will be the output)
		newLockingBefore := contract.GetLockingScript()
		t.Logf("block %d: newLocking len=%d tail=...%s",
			block, len(newLockingBefore)/2,
			newLockingBefore[max(0, len(newLockingBefore)-60):])

		prepared, prepErr := contract.PrepareCall("advanceState", args, provider, signer, nil)
		if prepErr != nil {
			t.Fatalf("advance to block %d PrepareCall FAILED: %v", block, prepErr)
		}
		// Decode BIP-143 preimage fields
		pre := prepared.Preimage
		if len(pre) >= 208*2 { // min preimage is 104+ bytes
			t.Logf("block %d: preimage len=%d bytes", block, len(pre)/2)
			t.Logf("  nVersion:      %s", pre[0:8])
			t.Logf("  hashPrevouts:  %s", pre[8:8+64])
			t.Logf("  hashSequence:  %s", pre[72:72+64])
			t.Logf("  outpoint:      %s", pre[136:136+72])
			// scriptCode has varint length prefix
			scLenByte, _ := hex.DecodeString(pre[208:210])
			scLen := int(scLenByte[0])
			scVarIntSize := 2 // 1 byte varint
			if scLenByte[0] == 0xfd {
				lo, _ := hex.DecodeString(pre[210:212])
				hi, _ := hex.DecodeString(pre[212:214])
				scLen = int(lo[0]) | int(hi[0])<<8
				scVarIntSize = 6
			}
			scStart := 208 + scVarIntSize
			scEnd := scStart + scLen*2
			t.Logf("  scriptCode:    len=%d, first40=%s... last40=...%s", scLen, pre[scStart:min(scStart+40, scEnd)], pre[max(scStart, scEnd-40):scEnd])
			rest := scEnd
			t.Logf("  value:         %s", pre[rest:rest+16])
			t.Logf("  nSequence:     %s", pre[rest+16:rest+24])
			t.Logf("  hashOutputs:   %s", pre[rest+24:rest+24+64])
			t.Logf("  nLocktime:     %s", pre[rest+88:rest+96])
			t.Logf("  sighashType:   %s", pre[rest+96:rest+104])
		}

		// Dump the TX that would be broadcast
		t.Logf("block %d: prepared.TxHex len=%d", block, len(prepared.TxHex)/2)
		os.WriteFile(fmt.Sprintf("/tmp/nullfail-tx-block%d.hex", block), []byte(prepared.TxHex), 0644)
		os.WriteFile(fmt.Sprintf("/tmp/nullfail-preimage-block%d.hex", block), []byte(prepared.Preimage), 0644)
		os.WriteFile(fmt.Sprintf("/tmp/nullfail-utxoscript-block%d.hex", block), []byte(utxo.Script), 0644)

		// Verify the sighash matches what we'd compute manually from the preimage
		preBytes, _ := hex.DecodeString(prepared.Preimage)
		manualHash := sha256.Sum256(preBytes)
		manualHashHex := hex.EncodeToString(manualHash[:])
		t.Logf("block %d: sighash=%s, manual=%s, match=%v",
			block, prepared.Sighash, manualHashHex, prepared.Sighash == manualHashHex)

		// Manually compute hashOutputs from prepared.TxHex and compare with preimage
		txHashOutputs := helpers.ComputeHashOutputsFromTxHex(prepared.TxHex)
		pHex := prepared.Preimage
		pScLenByte, _ := hex.DecodeString(pHex[208:210])
		pScLen := int(pScLenByte[0])
		pScVI := 2
		if pScLenByte[0] == 0xfd {
			pLo, _ := hex.DecodeString(pHex[210:212])
			pHi, _ := hex.DecodeString(pHex[212:214])
			pScLen = int(pLo[0]) | int(pHi[0])<<8
			pScVI = 6
		}
		restPos := 208 + pScVI + pScLen*2 + 16 + 8
		preimageHashOutputs := pHex[restPos : restPos+64]
		t.Logf("block %d: hashOutputs from TX=%s, from preimage=%s, match=%v",
			block, txHashOutputs, preimageHashOutputs, txHashOutputs == preimageHashOutputs)

		txid, _, err := contract.FinalizeCall(prepared, map[int]string{}, provider)
		if err != nil {
			t.Fatalf("advance to block %d FAILED: %v", block, err)
		}
		t.Logf("block %d: %s", block, txid)
		// Log what UTXO we're now tracking
		newUtxo := contract.GetCurrentUtxo()
		t.Logf("block %d: new utxo script len=%d tail=...%s",
			block, len(newUtxo.Script)/2,
			newUtxo.Script[max(0, len(newUtxo.Script)-60):])
		// Check consistency: newUtxo.Script should equal the locking script we'd compute now
		currentLocking := contract.GetLockingScript()
		if newUtxo.Script != currentLocking {
			t.Logf("block %d: MISMATCH: utxo.Script != GetLockingScript()", block)
			t.Logf("  utxo:    ...%s", newUtxo.Script[max(0, len(newUtxo.Script)-80):])
			t.Logf("  current: ...%s", currentLocking[max(0, len(currentLocking)-80):])
		}
		prevRoot = newRoot
	}
	t.Log("all 10 advances passed")
}

func TestNullFailMultiMethod_Freeze(t *testing.T) {
	artifact, err := helpers.CompileSourceStringToSDKArtifact(
		fourMethodSource, "RollupContract.runar.ts", nil,
	)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	wallet := helpers.NewWallet()
	helpers.RPCCall("importaddress", wallet.Address, "", false)
	if _, err := helpers.FundWallet(wallet, 1.0); err != nil {
		t.Fatalf("fund: %v", err)
	}

	provider := helpers.NewRPCProvider()
	signer, err := helpers.SDKSignerFromWallet(wallet)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	pubKey, _ := signer.GetPublicKey()
	vkHash := "cc" + "0000000000000000000000000000000000000000000000000000000000000000"[0:62]
	initialRoot := "0000000000000000000000000000000000000000000000000000000000000000"

	contract := runar.NewRunarContract(artifact, []interface{}{
		initialRoot,
		int64(0),
		int64(0),
		pubKey,
		vkHash,
	})

	if _, _, err := contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 100000}); err != nil {
		t.Fatalf("deploy: %v", err)
	}

	// First advance state
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
