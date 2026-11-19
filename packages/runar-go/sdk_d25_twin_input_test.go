package runar

import (
	"encoding/hex"
	"strings"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// D25 (D12 PRE-F1) — the Go SDK side of the twin-input binding. Port of the
// SDK-relevant cases of packages/runar-sdk/src/__tests__/d25-twin-input.test.ts.
// Every call goes through the validating MockProvider, which replays each
// known input on the go-sdk interpreter, so a successful Call proves the SDK
// built the transaction the covenant accepts. The executed twin attacks
// against the Go compiler's own output live in conformance/d25_twin_input_test.go.
//
//	class 1 (Counter, every continuation method mutate-only): methods carry
//	        ABI sigHashType 0x43 and params `_newAmount, txPreimage`; the
//	        preimage is built under SINGLE|FORKID and the continuation sits at
//	        output index == the contract's input index.
//	class 2 (MixedPot): the state carries a trailing `_spentOutpointHash`
//	        that the SDK must derive as sha256(real spent outpoint).

const d25CounterSrc = `import { StatefulSmartContract, assert } from 'runar-lang';
class Counter extends StatefulSmartContract {
  count: bigint;
  constructor(count: bigint) { super(count); this.count = count; }
  public increment() { this.count++; }
  public decrement() { assert(this.count > 0n); this.count--; }
}`

const d25MixedSrc = `import { StatefulSmartContract, assert, extractAmount } from 'runar-lang';
class MixedPot extends StatefulSmartContract {
  count: bigint;
  constructor(count: bigint) { super(count); this.count = count; }
  public increment() { this.count++; }
  public bump() { this.addOutput(extractAmount(this.txPreimage), this.count + 1n); }
}`

// A signed mutate-only method: class 1, with a user Sig (PrepareCall digest).
const d25SignedSrc = `import { StatefulSmartContract, assert, checkSig } from 'runar-lang';
import type { PubKey, Sig } from 'runar-lang';
class Owned extends StatefulSmartContract {
  count: bigint;
  readonly owner: PubKey;
  constructor(count: bigint, owner: PubKey) { super(count, owner); this.count = count; this.owner = owner; }
  public increment(sig: Sig) { assert(checkSig(sig, this.owner)); this.count++; }
}`

func d25Funded(t *testing.T) (*MockProvider, *LocalSigner) {
	t.Helper()
	provider := NewMockProvider("testnet")
	signer, err := NewLocalSigner(strings.Repeat("11", 32))
	if err != nil {
		t.Fatal(err)
	}
	addr, _ := signer.GetAddress()
	provider.AddUtxo(addr, UTXO{Txid: strings.Repeat("ab", 32), OutputIndex: 0, Satoshis: 5_000_000, Script: BuildP2PKHScript(addr)})
	return provider, signer
}

func d25MethodABI(t *testing.T, art *RunarArtifact, name string) *ABIMethod {
	t.Helper()
	for i := range art.ABI.Methods {
		if art.ABI.Methods[i].Name == name {
			return &art.ABI.Methods[i]
		}
	}
	t.Fatalf("no ABI method %s", name)
	return nil
}

func d25ParamNames(m *ABIMethod) string {
	var n []string
	for _, p := range m.Params {
		n = append(n, p.Name)
	}
	return strings.Join(n, ",")
}

func d25HonestChain(t *testing.T, art *RunarArtifact, methods []string) *RunarContract {
	t.Helper()
	provider, signer := d25Funded(t)
	c := NewRunarContract(art, []interface{}{int64(0)})
	if _, _, err := c.Deploy(provider, signer, DeployOptions{Satoshis: 10_000}); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	for i, m := range methods {
		if _, _, err := c.Call(m, nil, provider, signer, nil); err != nil {
			t.Fatalf("call %d (%s): %v", i, m, err)
		}
		if provider.LastValidatedInputCount() == 0 {
			t.Fatalf("call %d (%s): the validating provider executed no input", i, m)
		}
	}
	return c
}

func TestD25SDK_Class1_CounterABIIsSingle(t *testing.T) {
	art := d12Compile(t, "Counter", d25CounterSrc)
	for _, name := range []string{"increment", "decrement"} {
		m := d25MethodABI(t, art, name)
		if m.SigHashType == nil || *m.SigHashType != 0x43 {
			t.Fatalf("%s sigHashType = %v, want 0x43", name, m.SigHashType)
		}
		if got := d25ParamNames(m); got != "_newAmount,txPreimage" {
			t.Fatalf("%s params = %s", name, got)
		}
	}
}

func TestD25SDK_Class1_HonestChainedCalls(t *testing.T) {
	art := d12Compile(t, "Counter", d25CounterSrc)
	c := d25HonestChain(t, art, []string{"increment", "increment", "decrement"})
	if got := anfToBigInt(c.GetState()["count"]).Int64(); got != 1 {
		t.Fatalf("count = %d, want 1", got)
	}
}

func TestD25SDK_Class2_HonestChainedCalls(t *testing.T) {
	art := d12Compile(t, "MixedPot", d25MixedSrc)
	last := art.StateFields[len(art.StateFields)-1]
	if last.Name != "_spentOutpointHash" || last.Type != "Sha256" {
		t.Fatalf("last state field = %+v, want _spentOutpointHash Sha256", last)
	}
	if len(art.ABI.Constructor.Params) != 1 || art.ABI.Constructor.Params[0].Name != "count" {
		t.Fatalf("constructor params = %+v, want [count]", art.ABI.Constructor.Params)
	}
	c := d25HonestChain(t, art, []string{"increment", "bump", "increment"})
	if got := anfToBigInt(c.GetState()["count"]).Int64(); got != 3 {
		t.Fatalf("count = %d, want 3", got)
	}
}

// TS userSigDigest: a user Sig is ALL|FORKID (the byte every signer appends),
// so under a SINGLE covenant PrepareCall.Sighash must be the ALL|FORKID digest
// over the same tx, not hash256 of the covenant's SINGLE preimage.
func TestD25SDK_PrepareCallUserSigDigestIsAllForkID(t *testing.T) {
	art := d12Compile(t, "Owned", d25SignedSrc)
	m := d25MethodABI(t, art, "increment")
	if m.SigHashType == nil || *m.SigHashType != 0x43 {
		t.Fatalf("increment sigHashType = %v, want 0x43", m.SigHashType)
	}
	provider, signer := d25Funded(t)
	pub, _ := signer.GetPublicKey()
	c := NewRunarContract(art, []interface{}{int64(0), pub})
	if _, _, err := c.Deploy(provider, signer, DeployOptions{Satoshis: 10_000}); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	prepared, err := c.PrepareCall("increment", []interface{}{nil}, provider, signer, nil)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if prepared.Sighash == computeBip143Sighash(prepared.Preimage) {
		t.Fatal("PrepareCall.Sighash is the SINGLE covenant preimage's digest; a user ALL|FORKID Sig over it never verifies")
	}
	// The external wallet: ECDSA over the 32-byte digest as-is, ALL|FORKID byte.
	digest, err := hex.DecodeString(prepared.Sighash)
	if err != nil || len(digest) != 32 {
		t.Fatalf("PrepareCall.Sighash is not a 32-byte digest: %q", prepared.Sighash)
	}
	priv, err := ec.PrivateKeyFromHex(strings.Repeat("11", 32))
	if err != nil {
		t.Fatal(err)
	}
	sig, err := priv.Sign(digest)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	sigs := map[int]string{}
	for _, idx := range prepared.SigIndices {
		sigs[idx] = hex.EncodeToString(append(sig.Serialize(), 0x41))
	}
	if _, _, err := c.FinalizeCall(prepared, sigs, provider); err != nil {
		t.Fatalf("finalize with an external signature over PrepareCall.Sighash: %v", err)
	}
}

// TS: additionalContractInputs into one SINGLE continuation is the twin shape;
// refuse it up front with the shared text.
func TestD25SDK_AdditionalContractInputsRefusedForSingle(t *testing.T) {
	art := d12Compile(t, "Counter", d25CounterSrc)
	provider, signer := d25Funded(t)
	a := NewRunarContract(art, []interface{}{int64(0)})
	if _, _, err := a.Deploy(provider, signer, DeployOptions{Satoshis: 10_000}); err != nil {
		t.Fatalf("deploy a: %v", err)
	}
	b := NewRunarContract(art, []interface{}{int64(0)})
	if _, _, err := b.Deploy(provider, signer, DeployOptions{Satoshis: 10_000}); err != nil {
		t.Fatalf("deploy b: %v", err)
	}
	_, _, err := a.Call("increment", nil, provider, signer, &CallOptions{AdditionalContractInputs: []*UTXO{b.GetCurrentUtxo()}})
	if err == nil || !strings.Contains(err.Error(), "additionalContractInputs cannot be spent into one continuation by a SIGHASH_SINGLE method") {
		t.Fatalf("want the D25 refusal, got %v", err)
	}
}

// A data-output method makes the contract class 2 (bind): its single-output
// continuation writes the spent-outpoint binding next to a data output.
const d25DataSrc = `import { StatefulSmartContract, toByteString } from 'runar-lang';
class Logger extends StatefulSmartContract {
  count: bigint;
  constructor(count: bigint) { super(count); this.count = count; }
  public increment() { this.count++; }
  public log() { this.count++; this.addDataOutput(0n, toByteString('6a0161')); }
}`

func TestD25SDK_Class2_DataOutputHonestChainedCalls(t *testing.T) {
	art := d12Compile(t, "Logger", d25DataSrc)
	if last := art.StateFields[len(art.StateFields)-1]; last.Name != "_spentOutpointHash" {
		t.Fatalf("last state field = %s, want _spentOutpointHash", last.Name)
	}
	c := d25HonestChain(t, art, []string{"log", "increment", "log"})
	if got := anfToBigInt(c.GetState()["count"]).Int64(); got != 3 {
		t.Fatalf("count = %d, want 3", got)
	}
}
