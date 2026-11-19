package runar

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	bsvscript "github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/script/interpreter"
	"github.com/bsv-blockchain/go-sdk/transaction"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"
)

// Deep-review finding C19 (P1): `PreparedCall.Sighash` stored only
// sha256(preimage) — a SINGLE hash — instead of the true BIP-143 digest
// hash256(preimage) = sha256(sha256(preimage)) that OP_CHECKSIG actually
// verifies against on-chain.
//
// The default Call() path hid the bug: it never reads PreparedCall.Sighash at
// all — it re-derives the digest via LocalSigner.Sign -> go-sdk
// CalcInputSignatureHash (which returns Sha256d) and signs that. Only the
// documented multi-signer path (PrepareCall -> external `signHash(digest)`
// wallet -> FinalizeCall), which hands PreparedCall.Sighash to a signer that
// ECDSA-signs the 32 bytes DIRECTLY, is affected. Such a signer signs the
// wrong message and the node's real OP_CHECKSIG rejects the spend.
//
// Ported from the TS reference fix in packages/runar-sdk/src/contract.ts
// (computeBip143Sighash).

const c19SigCounterSrc = `import { StatefulSmartContract, assert, checkSig } from 'runar-lang';
import type { PubKey, Sig } from 'runar-lang';

class SigCounter extends StatefulSmartContract {
  count: bigint;
  readonly owner: PubKey;

  constructor(count: bigint, owner: PubKey) {
    super(count, owner);
    this.count = count;
    this.owner = owner;
  }

  public inc(sig: Sig) {
    assert(checkSig(sig, this.owner));
    this.count = this.count + 1n;
  }
}`

// c19PrivKeyHex is the signer key used for both the contract owner and the
// funding UTXO in the C19 tests.
const c19PrivKeyHex = "0000000000000000000000000000000000000000000000000000000000000003"

// c19Deploy compiles + deploys SigCounter and returns the live contract, the
// provider and the signer.
func c19Deploy(t *testing.T) (*RunarContract, *MockProvider, *LocalSigner) {
	t.Helper()

	tmp := t.TempDir() + "/SigCounter.runar.ts"
	if err := os.WriteFile(tmp, []byte(c19SigCounterSrc), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("go", "run", "../../compilers/go", "--source", tmp).Output()
	if err != nil {
		t.Fatalf("compile SigCounter: %v", err)
	}
	var art RunarArtifact
	if err := json.Unmarshal(out, &art); err != nil {
		t.Fatalf("unmarshal artifact: %v", err)
	}

	signer, err := NewLocalSigner(c19PrivKeyHex)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	addr, _ := signer.GetAddress()
	pubKey, _ := signer.GetPublicKey()

	provider := NewMockProvider("testnet")
	provider.AddUtxo(addr, UTXO{
		Txid:        strings.Repeat("aa", 32),
		OutputIndex: 0,
		Satoshis:    500000,
		Script:      BuildP2PKHScript(addr),
	})

	c := NewRunarContract(&art, []interface{}{int64(5), pubKey})
	if _, _, err := c.Deploy(provider, signer, DeployOptions{Satoshis: 50000}); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	return c, provider, signer
}

// c19ExecuteSpend replays the call tx's input 0 through the go-sdk script
// interpreter with full transaction context (the engine
// packages/runar-go/script_vm.go wraps). This is the real OP_CHECKSIG —
// a signature over the wrong digest fails here.
func c19ExecuteSpend(t *testing.T, provider *MockProvider) error {
	t.Helper()
	txs := provider.GetBroadcastedTxs()
	if len(txs) != 2 {
		t.Fatalf("expected 2 broadcasts (deploy+call), got %d", len(txs))
	}
	deployTx, err := transaction.NewTransactionFromHex(txs[0])
	if err != nil {
		t.Fatalf("parse deploy tx: %v", err)
	}
	callTx, err := transaction.NewTransactionFromHex(txs[1])
	if err != nil {
		t.Fatalf("parse call tx: %v", err)
	}
	return interpreter.NewEngine().Execute(
		interpreter.WithTx(callTx, 0, deployTx.Outputs[0]),
		interpreter.WithAfterGenesis(),
		interpreter.WithAfterChronicle(),
		interpreter.WithForkID(),
	)
}

// TestPreparedCall_Sighash_IsBip143Hash256_C19 pins the exposed digest value.
func TestPreparedCall_Sighash_IsBip143Hash256_C19(t *testing.T) {
	c, provider, signer := c19Deploy(t)

	prepared, err := c.PrepareCall("inc", []interface{}{nil}, provider, signer, nil)
	if err != nil {
		t.Fatalf("PrepareCall: %v", err)
	}
	if prepared.Preimage == "" {
		t.Fatal("expected a non-empty BIP-143 preimage for a stateful call")
	}

	// D25: SigCounter is mutate-only, so its covenant preimage is
	// SIGHASH_SINGLE (0x43); a user Sig is ALL|FORKID, so its digest comes
	// from the ALL preimage of the same tx and subscript, built here by the
	// go-sdk itself (not by the SDK helper under test).
	callTx, err := transaction.NewTransactionFromHex(prepared.TxHex)
	if err != nil {
		t.Fatalf("parse prepared tx: %v", err)
	}
	utxo := c.GetCurrentUtxo()
	sep := c.getCodeSepIndex(c.findMethodIndex("inc"))
	if sep < 0 {
		t.Fatal("no OP_CODESEPARATOR for inc")
	}
	sub, err := bsvscript.NewFromHex(utxo.Script[(sep+1)*2:])
	if err != nil {
		t.Fatalf("subscript: %v", err)
	}
	callTx.Inputs[0].SetSourceTxOutput(&transaction.TransactionOutput{Satoshis: uint64(utxo.Satoshis), LockingScript: sub})
	preimageBytes, err := callTx.CalcInputPreimage(0, sighash.AllForkID)
	if err != nil {
		t.Fatalf("ALL|FORKID preimage: %v", err)
	}
	single := sha256.Sum256(preimageBytes)
	double := sha256.Sum256(single[:])
	wantHash256 := hex.EncodeToString(double[:])
	wrongSingle := hex.EncodeToString(single[:])

	if prepared.Sighash == wrongSingle {
		t.Fatalf("PreparedCall.Sighash is sha256(preimage) — an external signHash() wallet "+
			"would ECDSA-sign the WRONG digest.\n  got  %s (single sha256)\n  want %s (hash256)",
			prepared.Sighash, wantHash256)
	}
	if prepared.Sighash != wantHash256 {
		t.Fatalf("PreparedCall.Sighash = %s, want hash256(ALL|FORKID preimage) = %s", prepared.Sighash, wantHash256)
	}
}

// TestPreparedCall_ExternalSignHashWallet_C19 is the end-to-end proof: an
// external BRC-100-style wallet ECDSA-signs PreparedCall.Sighash DIRECTLY
// (no further hashing), FinalizeCall assembles the tx, and the go-sdk script
// interpreter validates the spend. Pre-fix the digest is single-hashed and
// the interpreter rejects the spend with a CHECKSIG failure.
func TestPreparedCall_ExternalSignHashWallet_C19(t *testing.T) {
	c, provider, signer := c19Deploy(t)

	prepared, err := c.PrepareCall("inc", []interface{}{nil}, provider, signer, nil)
	if err != nil {
		t.Fatalf("PrepareCall: %v", err)
	}
	if len(prepared.SigIndices) != 1 {
		t.Fatalf("expected exactly 1 external Sig index, got %v", prepared.SigIndices)
	}

	// --- the external wallet: signHash(digest) -> DER sig, NO extra hashing ---
	digest, err := hex.DecodeString(prepared.Sighash)
	if err != nil {
		t.Fatalf("decode prepared.Sighash: %v", err)
	}
	if len(digest) != 32 {
		t.Fatalf("prepared.Sighash is %d bytes, want a 32-byte digest", len(digest))
	}
	privKey, err := ec.PrivateKeyFromHex(c19PrivKeyHex)
	if err != nil {
		t.Fatalf("privkey: %v", err)
	}
	sig, err := privKey.Sign(digest) // signs the 32 bytes as-is (RFC6979, low-S)
	if err != nil {
		t.Fatalf("external sign: %v", err)
	}
	sigHex := hex.EncodeToString(append(sig.Serialize(), 0x41)) // ALL|FORKID
	// --- end external wallet ---

	if _, _, err := c.FinalizeCall(prepared, map[int]string{prepared.SigIndices[0]: sigHex}, provider); err != nil {
		t.Fatalf("FinalizeCall: %v", err)
	}

	if execErr := c19ExecuteSpend(t, provider); execErr != nil {
		t.Fatalf("multi-signer spend REJECTED by the go-sdk script interpreter — "+
			"PreparedCall.Sighash is not the BIP-143 hash256(preimage) digest: %v", execErr)
	}
}

// TestCall_DefaultPath_StillValidates_C19 guards the trace risk: the default
// Call() path must keep producing a spendable transaction after the C19 change.
func TestCall_DefaultPath_StillValidates_C19(t *testing.T) {
	c, provider, signer := c19Deploy(t)

	if _, _, err := c.Call("inc", []interface{}{nil}, provider, signer, nil); err != nil {
		t.Fatalf("default Call: %v", err)
	}
	if got := anfToBigInt(c.state["count"]).Int64(); got != 6 {
		t.Fatalf("state count = %d after inc, want 6", got)
	}
	if execErr := c19ExecuteSpend(t, provider); execErr != nil {
		t.Fatalf("default Call() spend REJECTED by the go-sdk script interpreter: %v", execErr)
	}
}
