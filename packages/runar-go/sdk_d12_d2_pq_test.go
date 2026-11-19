package runar

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func d12Compile(t *testing.T, name, src string) *RunarArtifact {
	t.Helper()
	tmp := t.TempDir() + "/" + name + ".runar.ts"
	if err := os.WriteFile(tmp, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("go", "run", "../../compilers/go", "--source", tmp).Output()
	if err != nil {
		t.Fatalf("compile %s: %v", name, err)
	}
	var art RunarArtifact
	if err := json.Unmarshal(out, &art); err != nil {
		t.Fatalf("unmarshal artifact: %v", err)
	}
	return &art
}

// D12 D2: extractLocktime / extractSequence / extractOutpoint read the REAL
// fields of the call transaction. The SDK used to derive the post-state from
// nil dummies, so a method storing them built a continuation the covenant
// refuses. The validating MockProvider replays the spend through the go-sdk
// interpreter, so a successful Call proves the SDK's state equals the script's.
func TestD12_PreimageExtractorsUseRealTxFields(t *testing.T) {
	art := d12Compile(t, "Rec", `import { StatefulSmartContract, ByteString, extractLocktime, extractSequence, extractOutpoint } from 'runar-lang';
class Rec extends StatefulSmartContract {
  lt: bigint;
  sq: bigint;
  op: ByteString;
  constructor(lt: bigint, sq: bigint, op: ByteString) { super(lt, sq, op); this.lt = lt; this.sq = sq; this.op = op; }
  public rec() {
    this.lt = extractLocktime(this.txPreimage);
    this.sq = extractSequence(this.txPreimage);
    this.op = extractOutpoint(this.txPreimage);
  }
}`)
	provider := NewMockProvider("testnet")
	signer, err := NewLocalSigner(strings.Repeat("11", 32))
	if err != nil {
		t.Fatal(err)
	}
	addr, _ := signer.GetAddress()
	provider.AddUtxo(addr, UTXO{Txid: strings.Repeat("aa", 32), OutputIndex: 0, Satoshis: 5_000_000, Script: BuildP2PKHScript(addr)})
	c := NewRunarContract(art, []interface{}{int64(0), int64(0), ""})
	if _, _, err := c.Deploy(provider, signer, DeployOptions{Satoshis: 50_000}); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	spent := c.GetCurrentUtxo()
	lt := uint32(100)
	if _, _, err := c.Call("rec", nil, provider, signer, &CallOptions{Locktime: &lt}); err != nil {
		t.Fatalf("rec(): %v", err)
	}
	txidLE, _ := hex.DecodeString(spent.Txid)
	for i, j := 0, len(txidLE)-1; i < j; i, j = i+1, j-1 {
		txidLE[i], txidLE[j] = txidLE[j], txidLE[i]
	}
	wantOp := hex.EncodeToString(txidLE) + fmt.Sprintf("%02x000000", spent.OutputIndex)
	st := c.GetState()
	if got := anfToBigInt(st["lt"]).Int64(); got != 100 {
		t.Errorf("lt = %d, want 100", got)
	}
	if got := anfToBigInt(st["sq"]).Int64(); got != 0xfffffffe {
		t.Errorf("sq = %x, want fffffffe", got)
	}
	if got := anfToString(st["op"]); got != wantOp {
		t.Errorf("op = %s, want %s", got, wantOp)
	}
}

func d12MustPanic(t *testing.T, label string, fn func()) {
	t.Helper()
	defer func() {
		t.Helper()
		if recover() == nil {
			t.Fatalf("%s: accepted, want a refusal", label)
		}
	}()
	fn()
}

// D12 PQ-F1: a constructor arg flowing straight into verifyWOTS /
// verifySLHDSA_* as the public key must have the parameter set's length
// (WOTS 64, SLH-DSA 2n). Any other length deploys an output whose owner's
// valid signature is refused forever. The check reads the artifact's ANF,
// which the Go compiler emits for stateful contracts only, so a stateful
// contract is used here (a stateless artifact without ANF is not checked).
func TestD12_PQPubKeyLengthCheckedAtConstruction(t *testing.T) {
	wots := d12Compile(t, "W", `import { StatefulSmartContract, ByteString, assert, verifyWOTS } from 'runar-lang';
class W extends StatefulSmartContract {
  readonly pubkey: ByteString;
  n: bigint;
  constructor(pubkey: ByteString, n: bigint) { super(pubkey, n); this.pubkey = pubkey; this.n = n; }
  public spend(msg: ByteString, sig: ByteString) { assert(verifyWOTS(msg, sig, this.pubkey)); this.n = this.n + 1n; }
}`)
	for _, n := range []int{0, 32, 63, 65, 128} {
		n := n
		d12MustPanic(t, fmt.Sprintf("WOTS pk %d B", n), func() {
			NewRunarContract(wots, []interface{}{strings.Repeat("01", n), int64(0)})
		})
	}
	NewRunarContract(wots, []interface{}{strings.Repeat("01", 64), int64(0)})

	slh := d12Compile(t, "S", `import { StatefulSmartContract, ByteString, assert, verifySLHDSA_SHA2_128s } from 'runar-lang';
class S extends StatefulSmartContract {
  readonly pubkey: ByteString;
  n: bigint;
  constructor(pubkey: ByteString, n: bigint) { super(pubkey, n); this.pubkey = pubkey; this.n = n; }
  public spend(msg: ByteString, sig: ByteString) { assert(verifySLHDSA_SHA2_128s(msg, sig, this.pubkey)); this.n = this.n + 1n; }
}`)
	for _, n := range []int{0, 16, 31, 33, 64} {
		n := n
		d12MustPanic(t, fmt.Sprintf("SLH-DSA-128s pk %d B", n), func() {
			NewRunarContract(slh, []interface{}{strings.Repeat("01", n), int64(0)})
		})
	}
	NewRunarContract(slh, []interface{}{strings.Repeat("01", 32), int64(0)})
}
