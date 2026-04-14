//go:build ignore

// SP1 Groth16 verifier — end-to-end deploy and spend example.
//
// Reference documentation for how downstream consumers (bsv-evm, sCrypt
// users, any team deploying SP1 Groth16 proofs on BSV) use Rúnar's
// Groth16 WA SDK wrapper to put a verifier on-chain and then spend it
// with a real proof.
//
// What this program does:
//  1. Loads an SP1 v6.0.0 VK + raw proof + public inputs from
//     tests/vectors/sp1/v6.0.0/
//  2. Compiles a Rúnar artifact via compiler.CompileGroth16WA (the Phase 6
//     compiler backend — bakes the VK into the locking script).
//  3. Wraps the artifact in a runar.Groth16WAContract.
//  4. Funds a fresh wallet via the regtest node's built-in wallet.
//  5. Deploys the verifier UTXO to the regtest node.
//  6. Generates a witness bundle from the real SP1 proof.
//  7. Spends the deployed UTXO via Groth16WAContract.CallWithWitness.
//  8. Prints txids, sizes and timings.
//
// Prerequisites:
//   - BSV regtest node running (./integration/regtest.sh start).
//   - Node wallet has coins (regtest.sh pre-funds it by mining 101 blocks).
//   - SP1 fixtures present in tests/vectors/sp1/v6.0.0/.
//
// Usage:
//   go run ./examples/go/sp1_verifier_main.go
//
// Env overrides:
//   RPC_URL  (default http://localhost:18332)
//   RPC_USER (default bitcoin)
//   RPC_PASS (default bitcoin)
//
// The //go:build ignore tag keeps this file out of normal `go build ./...`
// runs. It is a standalone program — invoke it with `go run` only.
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
	"strings"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	sdkscript "github.com/bsv-blockchain/go-sdk/script"

	"github.com/icellan/runar/compilers/go/compiler"
	runar "github.com/icellan/runar/packages/runar-go"
	"github.com/icellan/runar/packages/runar-go/bn254witness"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "\nERROR: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// ---------------------------------------------------------------
	// 1. Locate SP1 fixtures.
	// ---------------------------------------------------------------
	fixDir, err := sp1FixtureDir()
	if err != nil {
		return fmt.Errorf("locate fixtures: %w", err)
	}
	vkPath := filepath.Join(fixDir, "vk.json")
	rawProofPath := filepath.Join(fixDir, "groth16_raw_proof.hex")
	pubInputsPath := filepath.Join(fixDir, "groth16_public_inputs.txt")

	fmt.Println("==> SP1 Groth16 end-to-end example")
	fmt.Printf("    fixture dir: %s\n", fixDir)

	// ---------------------------------------------------------------
	// 2. Compile the verifier artifact.
	// ---------------------------------------------------------------
	fmt.Println("==> Compiling Groth16 WA verifier (runarc groth16-wa backend)")
	t0 := time.Now()
	compArtifact, err := compiler.CompileGroth16WA(vkPath, compiler.Groth16WAOpts{})
	if err != nil {
		return fmt.Errorf("CompileGroth16WA: %w", err)
	}
	compileDur := time.Since(t0)
	scriptBytes := len(compArtifact.Script) / 2
	fmt.Printf("    locking script: %d bytes (%.1f KB)\n", scriptBytes, float64(scriptBytes)/1024.0)
	fmt.Printf("    numPubInputs: %d\n", compArtifact.Groth16WA.NumPubInputs)
	fmt.Printf("    vkDigest: %s\n", compArtifact.Groth16WA.VKDigest)
	fmt.Printf("    compile time: %s\n", compileDur)

	artifact := compilerArtifactToRunar(compArtifact)

	// ---------------------------------------------------------------
	// 3. Wrap it in the SDK helper.
	// ---------------------------------------------------------------
	g := runar.NewGroth16WAContract(artifact)
	fmt.Printf("==> Groth16WAContract ready (NumPubInputs=%d, VKDigest=%s)\n", g.NumPubInputs(), g.VKDigest())

	// ---------------------------------------------------------------
	// 4. Load VK + proof + public inputs and generate the witness.
	// ---------------------------------------------------------------
	vk, err := bn254witness.LoadSP1VKFromFile(vkPath)
	if err != nil {
		return fmt.Errorf("LoadSP1VKFromFile: %w", err)
	}
	rawHex, err := os.ReadFile(rawProofPath)
	if err != nil {
		return fmt.Errorf("read raw proof: %w", err)
	}
	proof, err := bn254witness.ParseSP1RawProof(strings.TrimSpace(string(rawHex)))
	if err != nil {
		return fmt.Errorf("ParseSP1RawProof: %w", err)
	}
	publicInputs, err := bn254witness.LoadSP1PublicInputs(pubInputsPath)
	if err != nil {
		return fmt.Errorf("LoadSP1PublicInputs: %w", err)
	}
	if len(publicInputs) != g.NumPubInputs() {
		return fmt.Errorf("public input count mismatch: %d vs VK expects %d", len(publicInputs), g.NumPubInputs())
	}

	fmt.Printf("==> Generating witness bundle (%d public inputs)\n", len(publicInputs))
	t1 := time.Now()
	witness, err := bn254witness.GenerateWitness(vk, proof, publicInputs)
	if err != nil {
		return fmt.Errorf("GenerateWitness: %w", err)
	}
	fmt.Printf("    miller gradients: %d fp values\n", len(witness.MillerGradients))
	fmt.Printf("    generation time: %s\n", time.Since(t1))

	// ---------------------------------------------------------------
	// 5. Connect to regtest and fund a fresh wallet.
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
	// LocalSigner.GetAddress() returns a mainnet address; regtest needs a
	// testnet-prefixed address (m/n...). Wrap LocalSigner in an
	// ExternalSigner that delegates Sign() but overrides GetAddress()
	// to return the regtest form. This is the cleanest way to use the
	// SDK Deploy() path against a regtest node without forking the
	// signer.
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

	// importaddress so listunspent sees incoming coins at this address.
	if _, err := rpc.call("importaddress", addr, "", false); err != nil {
		return fmt.Errorf("importaddress: %w", err)
	}
	// sendtoaddress from node wallet.
	if _, err := rpc.call("sendtoaddress", addr, 0.01); err != nil {
		return fmt.Errorf("sendtoaddress: %w", err)
	}
	// generate 1 confirmation.
	if err := rpcMineOne(rpc); err != nil {
		return fmt.Errorf("mine: %w", err)
	}

	utxos, err := provider.GetUtxos(addr)
	if err != nil {
		return fmt.Errorf("GetUtxos: %w", err)
	}
	if len(utxos) == 0 {
		return fmt.Errorf("no UTXOs for %s after funding; is the node wallet pre-funded?", addr)
	}
	fmt.Printf("    funded with %d UTXO(s), total %d sats\n", len(utxos), sumSats(utxos))

	// ---------------------------------------------------------------
	// 6. Deploy the verifier contract.
	// ---------------------------------------------------------------
	fmt.Println("==> Deploying verifier UTXO")
	t2 := time.Now()
	deployTxid, deployData, err := g.Deploy(provider, signer, runar.DeployOptions{
		Satoshis:      50_000,
		ChangeAddress: addr,
	})
	if err != nil {
		return fmt.Errorf("Deploy: %w", err)
	}
	deployBytes := 0
	if deployData != nil {
		deployBytes = len(deployData.Raw) / 2
	}
	fmt.Printf("    deploy txid: %s\n", deployTxid)
	fmt.Printf("    deploy tx size: %d bytes (%.1f KB)\n", deployBytes, float64(deployBytes)/1024.0)
	fmt.Printf("    deploy broadcast+confirm: %s\n", time.Since(t2))

	if g.CurrentUTXO() == nil {
		return fmt.Errorf("Deploy returned but CurrentUTXO is nil")
	}

	// ---------------------------------------------------------------
	// 7. Spend the verifier with the witness bundle.
	// ---------------------------------------------------------------
	receiverScript := runar.BuildP2PKHScript(addr)
	fmt.Println("==> Spending verifier UTXO with real SP1 witness")
	t3 := time.Now()
	spendTxid, spendData, err := g.CallWithWitness(provider, signer, witness, "", receiverScript)
	if err != nil {
		return fmt.Errorf("CallWithWitness: %w", err)
	}
	spendDur := time.Since(t3)
	spendBytes := 0
	if spendData != nil {
		spendBytes = len(spendData.Raw) / 2
	}
	fmt.Printf("    spend txid: %s\n", spendTxid)
	fmt.Printf("    spend tx size: %d bytes (%.1f KB)\n", spendBytes, float64(spendBytes)/1024.0)
	fmt.Printf("    spend broadcast+confirm: %s\n", spendDur)
	fmt.Println()
	fmt.Println("==> DONE. Real SP1 Groth16 proof verified on a BSV regtest node.")
	return nil
}

// ---------------------------------------------------------------------------
// Helpers (inline, kept tiny)
// ---------------------------------------------------------------------------

// sp1FixtureDir returns the absolute path to tests/vectors/sp1/v6.0.0/
// relative to this source file.
func sp1FixtureDir() (string, error) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("runtime.Caller failed")
	}
	dir := filepath.Join(filepath.Dir(thisFile), "..", "..", "tests", "vectors", "sp1", "v6.0.0")
	if _, err := os.Stat(dir); err != nil {
		return "", fmt.Errorf("fixture dir %s not found: %w", dir, err)
	}
	return dir, nil
}

// compilerArtifactToRunar copies the relevant fields from a
// compiler.Artifact into a runar.RunarArtifact. The two types have the
// same JSON shape; only the fields the SDK actually reads for a
// Groth16 WA contract are copied here.
func compilerArtifactToRunar(a *compiler.Artifact) *runar.RunarArtifact {
	out := &runar.RunarArtifact{
		Version:         a.Version,
		CompilerVersion: a.CompilerVersion,
		ContractName:    a.ContractName,
		Script:          a.Script,
		ASM:             a.ASM,
		BuildTimestamp:  a.BuildTimestamp,
		ABI: runar.ABI{
			Constructor: runar.ABIConstructor{Params: []runar.ABIParam{}},
			Methods: []runar.ABIMethod{
				{Name: "verify", Params: []runar.ABIParam{}, IsPublic: true},
			},
		},
	}
	if a.Groth16WA != nil {
		out.Groth16WA = &runar.Groth16WAMeta{
			NumPubInputs: a.Groth16WA.NumPubInputs,
			VKDigest:     a.Groth16WA.VKDigest,
		}
	}
	return out
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func sumSats(utxos []runar.UTXO) int64 {
	var total int64
	for _, u := range utxos {
		total += u.Satoshis
	}
	return total
}

// ---------------------------------------------------------------------------
// Minimal JSON-RPC client used only for regtest node-wallet operations
// (importaddress, sendtoaddress, generate). The runar.RPCProvider
// intentionally does not expose these; they are node-specific
// automation helpers, not production SDK surface. This client is kept
// inline so the example has no dependency on integration/go/helpers.
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
		ID:      fmt.Sprintf("sp1-%d", c.id),
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
	client := &http.Client{Timeout: 5 * time.Minute}
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
