//go:build integration

package integration

import (
	"encoding/hex"
	"testing"

	"runar-integration/helpers"

	runar "github.com/icellan/runar/packages/runar-go"

	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/script/interpreter"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// scriptDebugger captures state around OP_CHECKSIG operations
type scriptDebugger struct {
	t           *testing.T
	stepCount   int
	lastOp      string
	failedAt    int
	failedOp    string
	stackAtFail [][]byte
}

func (d *scriptDebugger) BeforeExecute(s *interpreter.State)                {}
func (d *scriptDebugger) AfterExecute(s *interpreter.State)                 {}
func (d *scriptDebugger) BeforeScriptChange(s *interpreter.State)           {}
func (d *scriptDebugger) AfterScriptChange(s *interpreter.State)            {}
func (d *scriptDebugger) AfterSuccess(s *interpreter.State)                 {}
func (d *scriptDebugger) BeforeStackPush(s *interpreter.State, data []byte) {}
func (d *scriptDebugger) AfterStackPush(s *interpreter.State, data []byte)  {}
func (d *scriptDebugger) BeforeStackPop(s *interpreter.State)               {}
func (d *scriptDebugger) AfterStackPop(s *interpreter.State, data []byte)   {}

func (d *scriptDebugger) BeforeStep(s *interpreter.State) {}

func (d *scriptDebugger) AfterStep(s *interpreter.State) {
	d.stepCount++
}

func (d *scriptDebugger) BeforeExecuteOpcode(s *interpreter.State) {
	op := s.Opcode()
	opName := op.Name()

	// Log checksig-related operations
	if opName == "OP_CHECKSIG" || opName == "OP_CHECKSIGVERIFY" ||
		opName == "OP_CODESEPARATOR" || opName == "OP_IF" ||
		opName == "OP_ELSE" || opName == "OP_ENDIF" {
		d.t.Logf("  step %d: %s (script=%d, opIdx=%d, condStack=%v, stackDepth=%d)",
			d.stepCount, opName, s.ScriptIdx, s.OpcodeIdx, s.CondStack, len(s.DataStack))
	}

	// For CHECKSIG/CHECKSIGVERIFY, log the top 2 stack elements (sig + pubkey)
	if opName == "OP_CHECKSIG" || opName == "OP_CHECKSIGVERIFY" {
		if len(s.DataStack) >= 2 {
			sig := s.DataStack[len(s.DataStack)-2]
			pk := s.DataStack[len(s.DataStack)-1]
			d.t.Logf("    sig: len=%d, hex=%s", len(sig), hex.EncodeToString(sig)[:min(40, len(hex.EncodeToString(sig)))])
			d.t.Logf("    pk:  len=%d, hex=%s", len(pk), hex.EncodeToString(pk)[:min(40, len(hex.EncodeToString(pk)))])
		}
		d.t.Logf("    lastCodeSep=%d", s.LastCodeSeparatorIdx)
	}
	d.lastOp = opName
}

func (d *scriptDebugger) AfterExecuteOpcode(s *interpreter.State) {}

func (d *scriptDebugger) AfterError(s *interpreter.State, err error) {
	d.failedAt = d.stepCount
	d.failedOp = d.lastOp
	d.stackAtFail = s.DataStack
	d.t.Logf("SCRIPT ERROR at step %d, op=%s: %v", d.stepCount, d.lastOp, err)
	d.t.Logf("  scriptIdx=%d, opcodeIdx=%d, condStack=%v", s.ScriptIdx, s.OpcodeIdx, s.CondStack)
	d.t.Logf("  lastCodeSep=%d", s.LastCodeSeparatorIdx)
	d.t.Logf("  stack depth=%d", len(s.DataStack))
	for i, item := range s.DataStack {
		h := hex.EncodeToString(item)
		if len(h) > 60 {
			h = h[:30] + "..." + h[len(h)-30:]
		}
		d.t.Logf("  stack[%d]: len=%d %s", i, len(item), h)
	}
}

func TestNullFailDebug_ScriptExecution(t *testing.T) {
	artifact, err := helpers.CompileSourceStringToSDKArtifact(
		fourMethodSource, "RollupContract.runar.ts", nil,
	)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

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
		initialRoot, int64(0), int64(0), pubKey, vkHash,
	})

	if _, _, err := contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 1000000}); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	t.Log("deployed")

	// Advance block 1 (should succeed)
	newRoot := nfStateRoot(1)
	batchData := initialRoot + newRoot
	proofBlob := "ff" + "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
	if _, _, err := contract.Call("advanceState", []interface{}{newRoot, int64(1), batchData, proofBlob}, provider, signer, nil); err != nil {
		t.Fatalf("block 1: %v", err)
	}
	t.Log("block 1 succeeded")

	// Block 2: prepare but don't broadcast — run through interpreter instead
	prevRoot := newRoot
	newRoot2 := nfStateRoot(2)
	batchData2 := prevRoot + newRoot2

	prepared, err := contract.PrepareCall("advanceState", []interface{}{
		newRoot2, int64(2), batchData2, proofBlob,
	}, provider, signer, nil)
	if err != nil {
		t.Fatalf("block 2 prepare: %v", err)
	}

	// FinalizeCall to get the actual broadcast TX (it will fail, but we get the hex)
	// Actually, let's just use the prepared TX directly — it already has the unlock
	tx, err := transaction.NewTransactionFromHex(prepared.TxHex)
	if err != nil {
		t.Fatalf("parse tx: %v", err)
	}

	// Get the locking script of the UTXO being spent
	utxo := contract.GetCurrentUtxo()
	lockScript, _ := script.NewFromHex(utxo.Script)

	// Set the source output for the input
	tx.Inputs[0].SetSourceTxOutput(&transaction.TransactionOutput{
		Satoshis:      uint64(utxo.Satoshis),
		LockingScript: lockScript,
	})

	// Run through interpreter with debugger
	dbg := &scriptDebugger{t: t}
	eng := interpreter.NewEngine()
	t.Log("=== Running script through interpreter ===")
	execErr := eng.Execute(
		interpreter.WithTx(tx, 0, tx.Inputs[0].SourceTxOutput()),
		interpreter.WithAfterGenesis(),
		interpreter.WithForkID(),
		interpreter.WithDebugger(dbg),
	)
	if execErr != nil {
		t.Logf("Script execution failed: %v", execErr)
		t.Logf("Failed at step %d, op=%s", dbg.failedAt, dbg.failedOp)
	} else {
		t.Log("Script execution SUCCEEDED")
	}
}
