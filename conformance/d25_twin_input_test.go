package conformance

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"
	gocompiler "github.com/icellan/runar/compilers/go/compiler"
	runar "github.com/icellan/runar/packages/runar-go"
)

// ---------------------------------------------------------------------------
// D25 (D12 PRE-F1) — twin-input theft, executed on the go-sdk interpreter
// against the GO compiler's own output.
//
// Two UTXOs of one stateful contract spent in ONE transaction that reach the
// same post-state used to be satisfied by ONE continuation output: every
// covenant input rebuilt the identical whole output list
// `hash256(continuation || change) == hashOutputs` (the BIP-143 preimage has
// no input position), so the second input's value left as the attacker's
// "change". Nobody had to sign anything.
//
// The fix binds the continuation to the input that made it, per contract:
//
//	class 1  every continuation method mutate-only (Counter) -> SIGHASH_SINGLE
//	         by default; BIP-143 SINGLE commits hashOutputs to
//	         output[inputIndex] only.
//	class 2  mixes auto-continuation with addOutput (MixedPot) -> every
//	         continuation carries sha256(spent outpoint) as a hidden last state
//	         field `_spentOutpointHash`.
//
// Everything the spend needs (sighash type, unlock layout, codePart prefix,
// the binding field) is read from the compiled artifact, so this one file runs
// unedited against the compiler before and after the fix. Each attack asserts
// that AT MOST ONE input verifies and that input 0 (whose continuation is the
// genuine one) still does, so a harness that rejects everything cannot pass.
// ---------------------------------------------------------------------------

const d25BindingField = "_spentOutpointHash"

var d25Attacker = []byte{
	0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
	0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
}

const d25MixedPotSrc = `import { StatefulSmartContract, assert, extractAmount } from 'runar-lang';

class MixedPot extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }

  public increment() {
    this.count++;
  }

  public bump() {
    this.addOutput(extractAmount(this.txPreimage), this.count + 1n);
  }
}
`

// d25CompileGo compiles with the Go compiler package built from the current
// source tree (never a prebuilt binary, which could be stale) and returns the
// artifact in the Go SDK's shape.
func d25CompileGo(t *testing.T, source, fileName string) *runar.RunarArtifact {
	t.Helper()
	res := gocompiler.CompileFromSourceStrWithResult(source, fileName)
	if !res.Success || res.Artifact == nil {
		var msgs []string
		for _, d := range res.Diagnostics {
			msgs = append(msgs, d.Message)
		}
		t.Fatalf("Go compiler failed on %s: %s", fileName, strings.Join(msgs, "; "))
	}
	raw, err := gocompiler.ArtifactToJSON(res.Artifact)
	if err != nil {
		t.Fatalf("artifact to JSON: %v", err)
	}
	var art runar.RunarArtifact
	if err := json.Unmarshal(raw, &art); err != nil {
		t.Fatalf("artifact JSON to SDK shape: %v", err)
	}
	return &art
}

func d25CounterArtifact(t *testing.T) *runar.RunarArtifact {
	t.Helper()
	path := filepath.Join("..", "examples", "go", "stateful-counter", "Counter.runar.go")
	src := mustReadFile(t, path)
	return d25CompileGo(t, src, "Counter.runar.go")
}

func d25MixedPotArtifact(t *testing.T) *runar.RunarArtifact {
	t.Helper()
	return d25CompileGo(t, d25MixedPotSrc, "MixedPot.runar.ts")
}

// d25Utxo is one contract UTXO: a distinct outpoint, its state, its value.
type d25Utxo struct {
	txid    *chainhash.Hash
	vout    uint32
	count   int64
	sats    uint64
	binding string // _spentOutpointHash in the UTXO's state (zero at deploy)
}

func d25MakeUtxo(k int, count int64, sats uint64) d25Utxo {
	h, _ := chainhash.NewHashFromHex(strings.Repeat(fmt.Sprintf("%02x", 0xc0+k), 32))
	return d25Utxo{txid: h, vout: uint32(k), count: count, sats: sats, binding: strings.Repeat("00", 32)}
}

// wireOutpoint is the 36-byte BIP-143 outpoint: txid (internal byte order) || vout LE.
func (u d25Utxo) wireOutpoint() []byte {
	out := make([]byte, 36)
	copy(out, u.txid.CloneBytes())
	binary.LittleEndian.PutUint32(out[32:], u.vout)
	return out
}

func d25HasBinding(art *runar.RunarArtifact) bool {
	n := len(art.StateFields)
	return n > 0 && art.StateFields[n-1].Name == d25BindingField
}

// d25LockingScript builds the full locking script (codePart + OP_RETURN +
// state) for `count`, with the binding field set to `binding` when the
// artifact carries one.
func d25LockingScript(t *testing.T, art *runar.RunarArtifact, count int64, binding string) string {
	t.Helper()
	c := runar.NewRunarContract(art, []interface{}{big.NewInt(count)})
	state := map[string]interface{}{"count": big.NewInt(count)}
	if d25HasBinding(art) {
		state[d25BindingField] = binding
	}
	c.SetState(state)
	return c.GetLockingScript()
}

// d25NextScript is the honest continuation of `spent` reaching `count`.
func d25NextScript(t *testing.T, art *runar.RunarArtifact, count int64, spent d25Utxo) string {
	t.Helper()
	binding := ""
	if d25HasBinding(art) {
		h := sha256.Sum256(spent.wireOutpoint())
		binding = hex.EncodeToString(h[:])
	}
	return d25LockingScript(t, art, count, binding)
}

func d25P2PKH(pkh []byte) string { return "76a914" + hex.EncodeToString(pkh) + "88ac" }

// d25Input is one contract input of an assembled transaction.
type d25Input struct {
	method       string
	utxo         d25Utxo
	changeAmount int64 // pushed as _changeAmount when the method takes one
	newAmount    int64 // pushed as _newAmount when the method takes one
}

type d25Output struct {
	sats   uint64
	script string
}

func d25Method(t *testing.T, art *runar.RunarArtifact, name string) (int, *runar.ABIMethod) {
	t.Helper()
	idx := 0
	for i := range art.ABI.Methods {
		m := &art.ABI.Methods[i]
		if !m.IsPublic {
			continue
		}
		if m.Name == name {
			return idx, m
		}
		idx++
	}
	t.Fatalf("method %q not in ABI", name)
	return -1, nil
}

func d25PublicCount(art *runar.RunarArtifact) int {
	n := 0
	for _, m := range art.ABI.Methods {
		if m.IsPublic {
			n++
		}
	}
	return n
}

// d25SpendAll assembles one transaction from the contract inputs and the
// outputs, builds each input's unlocking script from the artifact's ABI, and
// runs every input through the go-sdk interpreter. Returns one verdict per
// input ("ACCEPT" or the rejection site).
func d25SpendAll(t *testing.T, art *runar.RunarArtifact, inputs []d25Input, outputs []d25Output) []spendRejection {
	t.Helper()
	tx := transaction.NewTransaction()
	lockings := make([]string, len(inputs))
	prevOuts := make([]*transaction.TransactionOutput, len(inputs))
	for k, in := range inputs {
		lockings[k] = d25LockingScript(t, art, in.utxo.count, in.utxo.binding)
		ls, err := script.NewFromHex(lockings[k])
		if err != nil {
			t.Fatalf("parse locking %d: %v", k, err)
		}
		prevOuts[k] = &transaction.TransactionOutput{Satoshis: in.utxo.sats, LockingScript: ls}
		tx.AddInputWithOutput(&transaction.TransactionInput{
			SourceTXID:       in.utxo.txid,
			SourceTxOutIndex: in.utxo.vout,
			SequenceNumber:   transaction.DefaultSequenceNumber,
		}, prevOuts[k])
	}
	for _, o := range outputs {
		s, err := script.NewFromHex(o.script)
		if err != nil {
			t.Fatalf("parse output script: %v", err)
		}
		tx.AddOutput(&transaction.TransactionOutput{Satoshis: o.sats, LockingScript: s})
	}

	unlocks := make([]string, len(inputs))
	for k, in := range inputs {
		methodIdx, m := d25Method(t, art, in.method)
		flag := 0x41
		if m.SigHashType != nil {
			flag = *m.SigHashType
		}
		// The SDK's rule (getCodeSepIndex): the per-method index when the
		// artifact lists one, else the single shared codeSeparatorIndex.
		sep := -1
		if methodIdx < len(art.CodeSeparatorIndices) {
			sep = art.CodeSeparatorIndices[methodIdx]
		} else if art.CodeSeparatorIndex != nil {
			sep = *art.CodeSeparatorIndex
		} else {
			t.Fatalf("artifact has no OP_CODESEPARATOR index for method %d", methodIdx)
		}
		if lockings[k][sep*2:sep*2+2] != "ab" {
			t.Fatalf("codeSeparatorIndices[%d]=%d is not OP_CODESEPARATOR", methodIdx, sep)
		}
		scriptCode, err := script.NewFromHex(lockings[k][(sep+1)*2:])
		if err != nil {
			t.Fatalf("parse scriptCode: %v", err)
		}
		tx.Inputs[k].SetSourceTxOutput(&transaction.TransactionOutput{Satoshis: in.utxo.sats, LockingScript: scriptCode})
		preimage, err := tx.CalcInputPreimage(uint32(k), sighash.Flag(flag))
		if err != nil {
			t.Fatalf("calc preimage %d: %v", k, err)
		}
		tx.Inputs[k].SetSourceTxOutput(prevOuts[k])

		// codePart = the locking script minus "6a" + state.
		stateHex := lockings[k][len(lockings[k])-2*d25StateLen(art):]
		codePart := lockings[k][:len(lockings[k])-len(stateHex)-2]
		usesCodePart := true
		if m.UsesCodePart != nil {
			usesCodePart = *m.UsesCodePart
		}
		var u strings.Builder
		if usesCodePart {
			b, _ := hex.DecodeString(codePart)
			u.WriteString(encodePushBytes(b))
		}
		for _, p := range m.Params {
			switch p.Name {
			case "_changePKH":
				u.WriteString(encodePushBytes(d25Attacker))
			case "_changeAmount":
				u.WriteString(encodePushInt(in.changeAmount))
			case "_newAmount":
				u.WriteString(encodePushInt(in.newAmount))
			case "txPreimage":
				u.WriteString(encodePushBytes(preimage))
			default:
				t.Fatalf("method %s: unexpected ABI param %q", in.method, p.Name)
			}
		}
		if d25PublicCount(art) > 1 {
			u.WriteString(encodePushInt(int64(methodIdx)))
		}
		unlocks[k] = u.String()
		us, err := script.NewFromHex(unlocks[k])
		if err != nil {
			t.Fatalf("parse unlock: %v", err)
		}
		tx.Inputs[k].UnlockingScript = us
	}

	verdicts := make([]spendRejection, len(inputs))
	for k := range inputs {
		verdicts[k] = executeScriptWithTxLocated(lockings[k], unlocks[k], tx, k, prevOuts[k])
	}
	return verdicts
}

// d25StateLen: every state field here is fixed width (bigint 8, Sha256 32).
func d25StateLen(art *runar.RunarArtifact) int {
	n := 0
	for _, f := range art.StateFields {
		switch f.Type {
		case "bigint":
			n += 8
		case "Sha256":
			n += 32
		default:
			panic("d25StateLen: unexpected state type " + f.Type)
		}
	}
	return n
}

func d25Log(t *testing.T, label string, v []spendRejection) []bool {
	t.Helper()
	ok := make([]bool, len(v))
	parts := make([]string, len(v))
	for k, r := range v {
		ok[k] = r.err == nil
		parts[k] = fmt.Sprintf("input %d: %s", k, r)
	}
	t.Logf("%s: %s", label, strings.Join(parts, " | "))
	return ok
}

// d25ExpectTwinRefused: at most one input verifies, and input 0 (the one whose
// continuation is genuinely in the tx) still does.
func d25ExpectTwinRefused(t *testing.T, label string, v []spendRejection) {
	t.Helper()
	ok := d25Log(t, label, v)
	n := 0
	for _, x := range ok {
		if x {
			n++
		}
	}
	if n > 1 {
		t.Errorf("TWIN-INPUT THEFT ACCEPTED (%s): %d of %d contract inputs verified against ONE continuation output", label, n, len(ok))
	}
	if !ok[0] {
		t.Errorf("%s: input 0 (genuine continuation) must verify; got %s", label, v[0])
	}
	// Every other input must be refused by the continuation's hashOutputs
	// compare (the method's last expression), not by an unrelated guard.
	for k := 1; k < len(v); k++ {
		if v[k].err != nil && !v[k].finalStackFalse {
			t.Errorf("%s: input %d rejected for the wrong reason: want the hashOutputs compare false, got %s", label, k, v[k])
		}
	}
}

func d25ExpectAllAccept(t *testing.T, label string, v []spendRejection) {
	t.Helper()
	ok := d25Log(t, label, v)
	for k, x := range ok {
		if !x {
			t.Errorf("%s: honest input %d must verify, got %s", label, k, v[k])
		}
	}
}

// ---- class 1: Counter -------------------------------------------------------

func TestD25_Counter_IncrementTwin(t *testing.T) {
	art := d25CounterArtifact(t)
	u0, u1 := d25MakeUtxo(0, 0, 10_000), d25MakeUtxo(1, 0, 10_000)
	v := d25SpendAll(t, art,
		[]d25Input{{"increment", u0, 9_000, 10_000}, {"increment", u1, 9_000, 10_000}},
		[]d25Output{{10_000, d25NextScript(t, art, 1, u0)}, {9_000, d25P2PKH(d25Attacker)}})
	d25ExpectTwinRefused(t, "Counter 2x increment twin", v)
}

func TestD25_Counter_ConvergingTwin(t *testing.T) {
	art := d25CounterArtifact(t)
	u0, u1 := d25MakeUtxo(0, 0, 10_000), d25MakeUtxo(1, 2, 10_000)
	v := d25SpendAll(t, art,
		[]d25Input{{"increment", u0, 9_000, 10_000}, {"decrement", u1, 9_000, 10_000}},
		[]d25Output{{10_000, d25NextScript(t, art, 1, u0)}, {9_000, d25P2PKH(d25Attacker)}})
	d25ExpectTwinRefused(t, "Counter converging twin (0.increment + 2.decrement)", v)
}

func TestD25_Counter_HonestSingle(t *testing.T) {
	art := d25CounterArtifact(t)
	u0 := d25MakeUtxo(0, 0, 10_000)
	v := d25SpendAll(t, art,
		[]d25Input{{"increment", u0, 0, 10_000}},
		[]d25Output{{10_000, d25NextScript(t, art, 1, u0)}})
	d25ExpectAllAccept(t, "Counter honest single increment", v)
}

// Two independent Counters in one tx, each continuation at its own input
// index. Under the pre-D25 ALL covenant this cannot verify (each input hashes
// [its own continuation] but the tx carries two); under SINGLE it must.
func TestD25_Counter_HonestBatch(t *testing.T) {
	art := d25CounterArtifact(t)
	u0, u1 := d25MakeUtxo(0, 0, 10_000), d25MakeUtxo(1, 5, 7_000)
	v := d25SpendAll(t, art,
		[]d25Input{{"increment", u0, 0, 10_000}, {"increment", u1, 0, 7_000}},
		[]d25Output{{10_000, d25NextScript(t, art, 1, u0)}, {7_000, d25NextScript(t, art, 6, u1)}})
	d25ExpectAllAccept(t, "Counter honest two-instance batch", v)
}

// ---- class 2: MixedPot ------------------------------------------------------

func TestD25_MixedPot_IncrementTwin(t *testing.T) {
	art := d25MixedPotArtifact(t)
	u0, u1 := d25MakeUtxo(0, 0, 10_000), d25MakeUtxo(1, 0, 10_000)
	v := d25SpendAll(t, art,
		[]d25Input{{"increment", u0, 9_000, 10_000}, {"increment", u1, 9_000, 10_000}},
		[]d25Output{{10_000, d25NextScript(t, art, 1, u0)}, {9_000, d25P2PKH(d25Attacker)}})
	d25ExpectTwinRefused(t, "MixedPot increment twin", v)
}

func TestD25_MixedPot_BumpTwin(t *testing.T) {
	art := d25MixedPotArtifact(t)
	u0, u1 := d25MakeUtxo(0, 0, 10_000), d25MakeUtxo(1, 0, 10_000)
	v := d25SpendAll(t, art,
		[]d25Input{{"bump", u0, 9_000, 0}, {"bump", u1, 9_000, 0}},
		[]d25Output{{10_000, d25NextScript(t, art, 1, u0)}, {9_000, d25P2PKH(d25Attacker)}})
	d25ExpectTwinRefused(t, "MixedPot bump twin (unsigned addOutput(extractAmount))", v)
}

func TestD25_MixedPot_CrossMethodTwin(t *testing.T) {
	art := d25MixedPotArtifact(t)
	u0, u1 := d25MakeUtxo(0, 0, 10_000), d25MakeUtxo(1, 0, 10_000)
	v := d25SpendAll(t, art,
		[]d25Input{{"increment", u0, 9_000, 10_000}, {"bump", u1, 9_000, 0}},
		[]d25Output{{10_000, d25NextScript(t, art, 1, u0)}, {9_000, d25P2PKH(d25Attacker)}})
	d25ExpectTwinRefused(t, "MixedPot cross-method twin (increment@0 + bump@1)", v)
}

func TestD25_MixedPot_HonestSingle(t *testing.T) {
	art := d25MixedPotArtifact(t)
	for _, method := range []string{"increment", "bump"} {
		u0 := d25MakeUtxo(0, 0, 10_000)
		newAmount := int64(10_000)
		v := d25SpendAll(t, art,
			[]d25Input{{method, u0, 0, newAmount}},
			[]d25Output{{10_000, d25NextScript(t, art, 1, u0)}})
		d25ExpectAllAccept(t, "MixedPot honest single "+method, v)
	}
}

func mustReadFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}
