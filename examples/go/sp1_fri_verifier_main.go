//go:build ignore

// SP1 FRI verifier — end-to-end deploy and spend example against a BSV regtest
// node.
//
// Companion to `examples/go/sp1_verifier_main.go` (the SP1 Groth16 example);
// this program does the same thing for the SP1 FRI/STARK PoC contract:
//
//   1. Compile `integration/go/contracts/Sp1FriVerifierPoc.runar.go` via
//      `compiler.CompileFromSource` (~242 KB locking script).
//   2. Wrap the artifact in a `runar.RunarContract` with the constructor
//      `sp1VKeyHash` ByteString set to the empty value (PoC fixture has no
//      SP1 outer wrapper, see `sp1fri.MinimalGuestParams()` line 121).
//   3. Fund a fresh wallet via the regtest node's pre-funded coins.
//   4. Deploy the verifier UTXO via `RunarContract.Deploy()`.
//   5. Decode the canonical Plonky3 minimal-guest fixture
//      (`tests/vectors/sp1/fri/minimal-guest/proof.postcard`) and run the
//      off-chain reference verifier (`sp1fri.Verify`) as a sanity check.
//   6. Build the unlocking script via `sp1fri.EncodeUnlockingScript`.
//   7. Hand-build a spend transaction (no method selector — the contract has
//      a single public method `verify`) and broadcast it.
//   8. Mine a confirmation block and print txids/sizes/wall-clock measurements
//      in markdown table form ready to paste into
//      `docs/fri-verifier-measurements.md`.
//
// Prerequisites:
//   - BSV regtest node running (./integration/regtest.sh start). The node
//     wallet must hold spendable coins.
//   - Fixture present at `tests/vectors/sp1/fri/minimal-guest/proof.postcard`.
//
// Usage:
//   go run ./examples/go/sp1_fri_verifier_main.go
//
// Env overrides:
//   RPC_URL  (default http://localhost:18332)
//   RPC_USER (default bitcoin)
//   RPC_PASS (default bitcoin)
//   FIXTURE  (default minimal-guest; use evm-guest to attempt the
//            production-scale fixture — see fallback note in
//            docs/sp1-fri-verifier.md §5).
//
// The //go:build ignore tag keeps this file out of normal `go build ./...`.
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	sdkscript "github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"

	"github.com/icellan/runar/compilers/go/codegen"
	"github.com/icellan/runar/compilers/go/compiler"
	runar "github.com/icellan/runar/packages/runar-go"
	"github.com/icellan/runar/packages/runar-go/sp1fri"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "\nERROR: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	fixtureName := envOr("FIXTURE", "minimal-guest")
	fmt.Printf("==> SP1 FRI end-to-end regtest run (fixture=%s)\n", fixtureName)

	// ---------------------------------------------------------------
	// 1. Locate fixture + load proof.
	// ---------------------------------------------------------------
	fixDir, err := sp1FriFixtureDir(fixtureName)
	if err != nil {
		return fmt.Errorf("locate fixtures: %w", err)
	}
	proofPath := filepath.Join(fixDir, "proof.postcard")
	fmt.Printf("    fixture dir: %s\n", fixDir)

	proofBlob, err := os.ReadFile(proofPath)
	if err != nil {
		return fmt.Errorf("read proof: %w", err)
	}
	fmt.Printf("    proof.postcard size: %d bytes\n", len(proofBlob))

	proof, err := sp1fri.DecodeProof(proofBlob)
	if err != nil {
		return fmt.Errorf("DecodeProof: %w", err)
	}

	// Per-fixture: publicValues bytes + locking script.
	//
	// The PoC path goes through `compiler.CompileFromSource` which produces
	// a deployable artifact wired to the Sp1FriVerifierPoc.runar.go ABI.
	// The production-scale path bypasses the compiler and composes a body
	// directly via `EmitFullSP1FriVerifierBody` with the evm-guest param
	// tuple (the compiler frontend has no surface for non-default params
	// today — `compilers/go/codegen/sp1_fri.go::DefaultSP1FriParams()` is
	// hardcoded; see B1 in docs/fri-verifier-measurements.md).
	var (
		publicValues    []byte
		publicValuesU32 []uint32
		lockingScript   string
		params          sp1fri.ParamSet
		compileDur      time.Duration
	)

	switch fixtureName {
	case "minimal-guest":
		publicValues = []byte{
			0x00, 0x00, 0x00, 0x00,
			0x01, 0x00, 0x00, 0x00,
			0x15, 0x00, 0x00, 0x00,
		}
		publicValuesU32 = []uint32{0, 1, 21}
		params = sp1fri.MinimalGuestParams()

		// ---------- Compile via the deployable artifact path. ----------
		contractPath := filepath.Join(repoRoot(), "integration", "go", "contracts", "Sp1FriVerifierPoc.runar.go")
		fmt.Println("==> Compiling Sp1FriVerifierPoc.runar.go (compiler.CompileFromSource)")
		t1 := time.Now()
		artifact, err := compiler.CompileFromSource(contractPath)
		if err != nil {
			return fmt.Errorf("CompileFromSource: %w", err)
		}
		compileDur = time.Since(t1)
		fmt.Printf("    compile time: %s\n", compileDur)
		// Wrap with empty sp1VKeyHash (PoC). encodeArg([]byte{})=OP_0.
		contract := runar.NewRunarContract(compilerArtifactToRunar(artifact), []interface{}{[]byte{}})
		lockingScript = contract.GetLockingScript()

	case "evm-guest":
		var x uint32 = 377841674
		publicValues = []byte{
			0x00, 0x00, 0x00, 0x00,
			0x01, 0x00, 0x00, 0x00,
			byte(x), byte(x >> 8), byte(x >> 16), byte(x >> 24),
		}
		publicValuesU32 = []uint32{0, 1, x}
		params = evmGuestParams(len(publicValues))

		// ---------- Compose body bytes via direct codegen helper. ----------
		// This bypasses `compiler.CompileFromSource` because the compiler
		// frontend hardcodes `DefaultSP1FriParams()` (PoC tuple). The
		// resulting `lockingScript` is the body bytes directly — no
		// inscription envelope, no state section, no constructor splice.
		// `params.SP1VKeyHashByteSize == 0` so the sp1VKeyHash constructor
		// arg path is N/A here.
		fmt.Println("==> Composing evm-guest verifier body (codegen.EmitFullSP1FriVerifierBody, custom params)")
		codeParams := evmGuestCodegenParams(len(publicValues))
		t1 := time.Now()
		bodyOps := gatherStackOps(func(emit func(codegen.StackOp)) {
			codegen.EmitFullSP1FriVerifierBody(emit, codeParams)
		})
		emitRes, err := codegen.Emit([]codegen.StackMethod{{Name: "verify", Ops: bodyOps}})
		if err != nil {
			return fmt.Errorf("codegen.Emit: %w", err)
		}
		compileDur = time.Since(t1)
		lockingScript = emitRes.ScriptHex
		fmt.Printf("    body emit time: %s\n", compileDur)

	default:
		return fmt.Errorf("unknown FIXTURE=%s (want minimal-guest or evm-guest)", fixtureName)
	}

	scriptBytes := len(lockingScript) / 2
	fmt.Printf("    locking script: %d bytes (%.2f KB)\n", scriptBytes, float64(scriptBytes)/1024.0)

	// ---------------------------------------------------------------
	// 2. Off-chain reference verify (sanity gate).
	// ---------------------------------------------------------------
	fmt.Println("==> Off-chain reference verify (sp1fri.Verify*)")
	t0 := time.Now()
	if fixtureName == "minimal-guest" {
		if err := sp1fri.Verify(proof, publicValuesU32); err != nil {
			return fmt.Errorf("off-chain Verify: %w", err)
		}
	} else {
		// `sp1fri.Verify` is hard-coded to minimalGuestConfig; the evm-guest
		// production-scale config goes through VerifyWithConfig. The
		// off-chain reference path for production is currently not part of
		// the public sp1fri surface (see verify.go line 24 vs line 34) so
		// we skip the gate here and rely on the script-VM acceptance
		// established by codegen.TestSp1FriVerifier_AcceptsEvmGuestFixture.
		fmt.Println("    skipped (sp1fri.Verify is PoC-only; see verify.go:23)")
	}
	if fixtureName == "minimal-guest" {
		fmt.Printf("    accepted in %s\n", time.Since(t0))
	}

	// ---------------------------------------------------------------
	// 5. Connect to regtest, fund a fresh wallet.
	// ---------------------------------------------------------------
	rpcURL := envOr("RPC_URL", "http://localhost:18332")
	rpcUser := envOr("RPC_USER", "bitcoin")
	rpcPass := envOr("RPC_PASS", "bitcoin")
	provider := runar.NewRegtestRPCProvider(rpcURL, rpcUser, rpcPass)
	rpc := &simpleRPC{url: rpcURL, user: rpcUser, pass: rpcPass}

	priv, err := ec.NewPrivateKey()
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}
	inner, err := runar.NewLocalSigner(hex.EncodeToString(priv.Serialize()))
	if err != nil {
		return fmt.Errorf("NewLocalSigner: %w", err)
	}
	regtestAddrObj, err := sdkscript.NewAddressFromPublicKey(priv.PubKey(), false)
	if err != nil {
		return fmt.Errorf("derive regtest address: %w", err)
	}
	addr := regtestAddrObj.AddressString
	pubHex := hex.EncodeToString(priv.PubKey().Compressed())
	signer := runar.NewExternalSigner(pubHex, addr, inner.Sign)
	fmt.Printf("==> Funding address: %s\n", addr)

	if _, err := rpc.call("importaddress", addr, "", false); err != nil {
		return fmt.Errorf("importaddress: %w", err)
	}
	// 0.05 BTC = 5,000,000 sats. The deploy needs ~24,200 sats (242 KB at
	// 100 sat/KB) plus the contract output value (50,000 sats) plus change
	// fee. 5M sats covers everything with comfortable headroom.
	if _, err := rpc.call("sendtoaddress", addr, 0.05); err != nil {
		return fmt.Errorf("sendtoaddress: %w", err)
	}
	if err := rpcMineOne(rpc); err != nil {
		return fmt.Errorf("mine: %w", err)
	}

	utxos, err := provider.GetUtxos(addr)
	if err != nil {
		return fmt.Errorf("GetUtxos: %w", err)
	}
	if len(utxos) == 0 {
		return fmt.Errorf("no UTXOs for %s after funding", addr)
	}
	var totalSats int64
	for _, u := range utxos {
		totalSats += u.Satoshis
	}
	fmt.Printf("    funded with %d UTXO(s), total %d sats\n", len(utxos), totalSats)

	// ---------------------------------------------------------------
	// 6. Deploy the verifier UTXO.
	//
	// We bypass `RunarContract.Deploy` because the production-scale
	// (evm-guest) path doesn't go through the SDK's RunarContract wrapper
	// (it has no ABI / constructor slots / inscription envelope to
	// thread). Both paths reduce to: take a fully-formed lockingScript
	// hex, build a 1-output deploy tx funded from the wallet's UTXOs,
	// sign + broadcast.
	// ---------------------------------------------------------------
	fmt.Println("==> Deploying verifier UTXO")
	deployStart := time.Now()
	const contractValue = int64(50_000)
	feeRate, err := provider.GetFeeRate()
	if err != nil {
		return fmt.Errorf("GetFeeRate: %w", err)
	}
	selected := runar.SelectUtxos(utxos, contractValue, len(lockingScript)/2, feeRate)
	if len(selected) == 0 {
		return fmt.Errorf("UTXO selection returned empty set (need %d sats + fee for %d-byte locking script)",
			contractValue, len(lockingScript)/2)
	}
	deployTx, _, err := runar.BuildDeployTransaction(
		lockingScript, selected, contractValue, addr,
		runar.BuildP2PKHScript(addr), feeRate,
	)
	if err != nil {
		return fmt.Errorf("BuildDeployTransaction: %w", err)
	}
	for i := range selected {
		sig, err := signer.Sign(deployTx.Hex(), i, selected[i].Script, selected[i].Satoshis, nil)
		if err != nil {
			return fmt.Errorf("sign deploy input %d: %w", i, err)
		}
		pubKey, err := signer.GetPublicKey()
		if err != nil {
			return fmt.Errorf("GetPublicKey: %w", err)
		}
		unlockHex := runar.EncodePushData(sig) + runar.EncodePushData(pubKey)
		ls, err := sdkscript.NewFromHex(unlockHex)
		if err != nil {
			return fmt.Errorf("decode P2PKH unlock: %w", err)
		}
		deployTx.Inputs[i].UnlockingScript = ls
	}
	deployTxid, err := provider.Broadcast(deployTx)
	if err != nil {
		return fmt.Errorf("Broadcast deploy: %w", err)
	}
	deployData, err := provider.GetTransaction(deployTxid)
	if err != nil {
		// Fallback to local hex (autoMine in NewRegtestRPCProvider already
		// minted a block; the tx must exist on-chain).
		deployData = &runar.TransactionData{Txid: deployTxid, Raw: deployTx.Hex()}
	}
	deployWall := time.Since(deployStart)
	deployTxBytes := 0
	if deployData != nil {
		deployTxBytes = len(deployData.Raw) / 2
	}
	fmt.Printf("    deploy txid: %s\n", deployTxid)
	fmt.Printf("    deploy tx size: %d bytes (%.1f KB)\n", deployTxBytes, float64(deployTxBytes)/1024.0)
	fmt.Printf("    deploy wall-clock (build+sign+broadcast+1-confirm): %s\n", deployWall)

	deployBlockHeight, deployAccepted, err := txBlockInfo(rpc, deployTxid)
	if err != nil {
		return fmt.Errorf("txBlockInfo deploy: %w", err)
	}
	fmt.Printf("    deploy mined in block %d (accepted=%v)\n", deployBlockHeight, deployAccepted)

	// ---------------------------------------------------------------
	// 7. Build unlocking script.
	// ---------------------------------------------------------------
	fmt.Println("==> Building unlocking script (sp1fri.EncodeUnlockingScript)")
	unlockBytes, err := sp1fri.EncodeUnlockingScript(proof, proofBlob, publicValues, []byte{}, params)
	if err != nil {
		return fmt.Errorf("EncodeUnlockingScript: %w", err)
	}
	fmt.Printf("    unlocking script: %d bytes (%.2f KB)\n", len(unlockBytes), float64(len(unlockBytes))/1024.0)

	// ---------------------------------------------------------------
	// 8. Build + broadcast spend transaction.
	//
	// The PoC contract has a single public method (`verify`); no method
	// selector is appended. The unlocking script is exactly the bytes
	// returned by EncodeUnlockingScript above.
	// ---------------------------------------------------------------
	fmt.Println("==> Building + broadcasting spend transaction")
	spendStart := time.Now()
	spendTxid, spendTxBytes, err := buildAndBroadcastSpend(
		rpc, provider, addr, deployTxid, lockingScript, 50_000, unlockBytes, priv,
	)
	if err != nil {
		return fmt.Errorf("spend: %w", err)
	}
	if err := rpcMineOne(rpc); err != nil {
		return fmt.Errorf("mine after spend: %w", err)
	}
	spendWall := time.Since(spendStart)
	fmt.Printf("    spend txid: %s\n", spendTxid)
	fmt.Printf("    spend tx size: %d bytes (%.1f KB)\n", spendTxBytes, float64(spendTxBytes)/1024.0)
	fmt.Printf("    spend wall-clock (build+broadcast+1-confirm): %s\n", spendWall)

	spendBlockHeight, spendAccepted, err := txBlockInfo(rpc, spendTxid)
	if err != nil {
		return fmt.Errorf("txBlockInfo spend: %w", err)
	}
	fmt.Printf("    spend mined in block %d (accepted=%v)\n", spendBlockHeight, spendAccepted)

	// ---------------------------------------------------------------
	// 9. Print measurements summary.
	// ---------------------------------------------------------------
	fmt.Println()
	fmt.Println("==> MEASUREMENTS (markdown row, ready to paste)")
	fmt.Println()
	fmt.Printf("Locking-script size:    %d B (%.2f KB)\n", scriptBytes, float64(scriptBytes)/1024.0)
	fmt.Printf("Unlocking-script size:  %d B (%.2f KB)\n", len(unlockBytes), float64(len(unlockBytes))/1024.0)
	fmt.Printf("Deploy tx size:         %d B (%.2f KB)\n", deployTxBytes, float64(deployTxBytes)/1024.0)
	fmt.Printf("Spend tx size:          %d B (%.2f KB)\n", spendTxBytes, float64(spendTxBytes)/1024.0)
	fmt.Printf("Deploy wall-clock:      %s\n", deployWall)
	fmt.Printf("Spend wall-clock:       %s\n", spendWall)
	fmt.Printf("Deploy block accepted:  %v (height %d)\n", deployAccepted, deployBlockHeight)
	fmt.Printf("Spend block accepted:   %v (height %d)\n", spendAccepted, spendBlockHeight)
	fmt.Println()
	fmt.Printf("==> DONE. SP1 FRI %s fixture verified end-to-end on BSV regtest.\n", fixtureName)
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// evmGuestParams returns the production-scale ParamSet that pairs with the
// `tests/vectors/sp1/fri/evm-guest/proof.postcard` fixture. Mirrors the
// param tuple used by `codegen.TestSp1FriVerifier_AcceptsEvmGuestFixture`
// (sp1_fri_test.go:2226-2251). `pubValuesByteSize` is the length of the
// publicValues blob — passed in so the caller's bytes stay the source of
// truth.
func evmGuestParams(pubValuesByteSize int) sp1fri.ParamSet {
	p := sp1fri.MinimalGuestParams()
	p.LogBlowup = 1
	p.NumQueries = 100
	p.LogFinalPolyLen = 9 // bumped to satisfy numRounds=1 invariant; see B1
	p.CommitPoWBits = 16
	p.QueryPoWBits = 16
	p.DegreeBits = 10
	p.BaseDegreeBits = 10
	p.PublicValuesByteSize = pubValuesByteSize
	p.SP1VKeyHashByteSize = 0
	// NumChunks = 8 inherited from MinimalGuestParams (matches
	// EmitFullSP1FriVerifierBody hardcoded numChunks).
	return p
}

// evmGuestCodegenParams returns the matching codegen-side params struct.
// We mirror the sp1fri.ParamSet field-for-field rather than depending on
// any conversion helper (none exists in the public API today).
func evmGuestCodegenParams(pubValuesByteSize int) codegen.SP1FriVerifierParams {
	p := codegen.DefaultSP1FriParams()
	p.LogBlowup = 1
	p.NumQueries = 100
	p.LogFinalPolyLen = 9
	p.CommitPoWBits = 16
	p.QueryPoWBits = 16
	p.DegreeBits = 10
	p.BaseDegreeBits = 10
	p.PublicValuesByteSize = pubValuesByteSize
	p.SP1VKeyHashByteSize = 0
	return p
}

// gatherStackOps collects StackOps emitted by `emitFn` (mirrors
// `compilers/go/codegen/script_correctness_test.go::gatherOps` line 48).
func gatherStackOps(emitFn func(func(codegen.StackOp))) []codegen.StackOp {
	var ops []codegen.StackOp
	emitFn(func(op codegen.StackOp) { ops = append(ops, op) })
	return ops
}

// compilerArtifactToRunar copies the relevant fields from a compiler.Artifact
// into a runar.RunarArtifact, including the ABI surface (constructor +
// public method `verify`) and constructor slot table required for the
// `sp1VKeyHash` ByteString splice. Mirrors the helper in
// `examples/go/sp1_verifier_main.go` but adapted for the
// Sp1FriVerifierPoc ABI shape.
func compilerArtifactToRunar(a *compiler.Artifact) *runar.RunarArtifact {
	out := &runar.RunarArtifact{
		Version:         a.Version,
		CompilerVersion: a.CompilerVersion,
		ContractName:    a.ContractName,
		Script:          a.Script,
		ASM:             a.ASM,
		BuildTimestamp:  a.BuildTimestamp,
		ABI: runar.ABI{
			Constructor: runar.ABIConstructor{
				Params: []runar.ABIParam{
					{Name: "sp1VKeyHash", Type: "ByteString"},
				},
			},
			Methods: []runar.ABIMethod{
				{
					Name: "verify",
					Params: []runar.ABIParam{
						{Name: "proofBlob", Type: "ByteString"},
						{Name: "publicValues", Type: "ByteString"},
					},
					IsPublic: true,
				},
			},
		},
	}
	for _, slot := range a.ConstructorSlots {
		out.ConstructorSlots = append(out.ConstructorSlots, runar.ConstructorSlot{
			ParamIndex: slot.ParamIndex,
			ByteOffset: slot.ByteOffset,
		})
	}
	return out
}

func repoRoot() string {
	_, thisFile, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(thisFile), "..", "..")
}

func sp1FriFixtureDir(name string) (string, error) {
	dir := filepath.Join(repoRoot(), "tests", "vectors", "sp1", "fri", name)
	if _, err := os.Stat(dir); err != nil {
		return "", fmt.Errorf("fixture dir %s not found: %w", dir, err)
	}
	return dir, nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// buildAndBroadcastSpend hand-builds a spend transaction for the deployed
// verifier UTXO. The unlocking script is `unlockBytes` verbatim (no Sig
// argument — the PoC contract's `verify` method takes only proofBlob and
// publicValues). The transaction sends the contract output value back to the
// caller's funding address minus the fee.
//
// Returns (spendTxid, spendTxSizeBytes, error).
func buildAndBroadcastSpend(
	rpc *simpleRPC,
	provider runar.Provider,
	addr, deployTxid, deployLockingScript string,
	deployValue int64,
	unlockBytes []byte,
	priv *ec.PrivateKey,
) (string, int, error) {
	// Build a single-input transaction that spends the deployed UTXO.
	tx := transaction.NewTransaction()
	deployScript, err := sdkscript.NewFromHex(deployLockingScript)
	if err != nil {
		return "", 0, fmt.Errorf("decode deploy script: %w", err)
	}
	if err := tx.AddInputFrom(deployTxid, 0, deployLockingScript, uint64(deployValue), nil); err != nil {
		return "", 0, fmt.Errorf("add input: %w", err)
	}
	_ = deployScript

	// Output: send (deployValue - fee) back to caller address.
	// Fee estimate: 100 sat/KB applied to (input ~= unlockBytes + 41 overhead) +
	// (output ~= 34 P2PKH) + tx overhead. The unlocking script dominates.
	estTxBytes := len(unlockBytes) + 200
	fee := int64(estTxBytes/1000+1) * 100
	if fee < 200 {
		fee = 200
	}
	if fee >= deployValue {
		return "", 0, fmt.Errorf("fee %d >= deployValue %d", fee, deployValue)
	}
	change := deployValue - fee
	changeScript, err := sdkscript.NewFromHex(runar.BuildP2PKHScript(addr))
	if err != nil {
		return "", 0, fmt.Errorf("decode change script: %w", err)
	}
	tx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      uint64(change),
		LockingScript: changeScript,
	})

	// Set unlocking script to the encoded prelude bytes (raw, no sigs).
	unlockingLS := sdkscript.Script(unlockBytes)
	tx.Inputs[0].UnlockingScript = &unlockingLS

	txHex := tx.Hex()
	rawTxBytes := len(txHex) / 2

	// Broadcast via provider (handles autoMine).
	txid, err := provider.Broadcast(tx)
	if err != nil {
		return "", rawTxBytes, fmt.Errorf("broadcast: %w", err)
	}
	return txid, rawTxBytes, nil
}

// txBlockInfo queries the node for a transaction's containing block height
// and acceptance status (any tx returned by getrawtransaction with
// `blockhash` is by definition mined into a connected block, hence accepted).
func txBlockInfo(rpc *simpleRPC, txid string) (int, bool, error) {
	res, err := rpc.call("getrawtransaction", txid, true)
	if err != nil {
		return 0, false, err
	}
	var info struct {
		BlockHash string `json:"blockhash"`
	}
	if err := json.Unmarshal(res, &info); err != nil {
		return 0, false, fmt.Errorf("unmarshal getrawtransaction: %w", err)
	}
	if info.BlockHash == "" {
		return 0, false, nil
	}
	res2, err := rpc.call("getblockheader", info.BlockHash)
	if err != nil {
		return 0, false, err
	}
	var hdr struct {
		Height int `json:"height"`
	}
	if err := json.Unmarshal(res2, &hdr); err != nil {
		return 0, false, fmt.Errorf("unmarshal getblockheader: %w", err)
	}
	return hdr.Height, true, nil
}

// ---------------------------------------------------------------------------
// Minimal JSON-RPC client (mirrors examples/go/sp1_verifier_main.go).
// ---------------------------------------------------------------------------

type simpleRPC struct {
	url  string
	user string
	pass string
	id   int
}

type rpcReqBody struct {
	JSONRPC string        `json:"jsonrpc"`
	ID      string        `json:"id"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
}

type rpcRespBody struct {
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func (c *simpleRPC) call(method string, params ...interface{}) (json.RawMessage, error) {
	if params == nil {
		params = []interface{}{}
	}
	c.id++
	body, err := json.Marshal(rpcReqBody{
		JSONRPC: "1.0",
		ID:      fmt.Sprintf("sp1fri-%d", c.id),
		Method:  method,
		Params:  params,
	})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("POST", c.url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(c.user, c.pass)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 10 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out rpcRespBody
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("rpc %s: parse: %v (body=%s)", method, err, string(raw))
	}
	if out.Error != nil {
		return nil, fmt.Errorf("rpc %s: %s", method, out.Error.Message)
	}
	return out.Result, nil
}

func rpcMineOne(c *simpleRPC) error {
	if _, err := c.call("generate", 1); err == nil {
		return nil
	}
	addrRes, err := c.call("getnewaddress")
	if err != nil {
		return err
	}
	var addr string
	if err := json.Unmarshal(addrRes, &addr); err != nil {
		return err
	}
	_, err = c.call("generatetoaddress", 1, addr)
	return err
}
