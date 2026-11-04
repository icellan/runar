package runar

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// N-270: the "stateless branch" of PrepareCall (taken whenever isStateful —
// derived from a non-empty StateFields — is false, which includes a
// zero-mutable-field StatefulSmartContract) only computed a REAL methodIndex
// when isStateful was true. For any other method than the first, methodIndex
// stayed 0, so c.getCodeSepIndex(methodIndex) looked up
// CodeSeparatorIndices[0] and the wrong method's SigHashType instead of the
// entries for the method actually being called.
//
// twoMethodReadonlySource has ZERO mutable fields (so isStateful is false)
// but two public methods, each with its own auto-injected checkPreimage and
// therefore its own OP_CODESEPARATOR at a DIFFERENT byte offset (verified
// below via CodeSeparatorIndices). Calling methodB (real index 1) with the
// pre-fix code builds the OP_PUSH_TX preimage's scriptCode from
// CodeSeparatorIndices[0] (methodA's offset), which the real on-chain
// script — dispatched to methodB's branch, past methodB's OWN separator —
// does not match, so OP_CHECKSIG fails against the go-sdk interpreter.
//
// What this test proves: calling methodB (real index 1) of a 2-method
// zero-mutable-field StatefulSmartContract is accepted by MockProvider's
// default broadcast validation (which runs the go-sdk script interpreter on
// every known input), and the resulting tx is byte-identical to the TS SDK's
// (and the never-buggy Python SDK's) vector for the same call.
//
// What this test does not prove: the terminal-call branch (same bug, same
// fix, different call site), a methodIndex-driven merge
// (AdditionalContractInputs) on this fixture, or any tier besides TS/Go.
const twoMethodReadonlySource = `import { StatefulSmartContract, PubKey, Sig, assert, checkSig } from 'runar-lang';
class TwoMethodReadonly extends StatefulSmartContract {
  readonly owner: PubKey;
  constructor(owner: PubKey) { super(owner); this.owner = owner; }
  public methodA(sig: Sig): void { assert(checkSig(sig, this.owner)); }
  public methodB(sig: Sig): void { assert(checkSig(sig, this.owner)); }
}
`

func compileTwoMethodReadonly(t *testing.T) RunarArtifact {
	t.Helper()
	tmp := t.TempDir() + "/TwoMethodReadonly.runar.ts"
	if err := os.WriteFile(tmp, []byte(twoMethodReadonlySource), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("go", "run", "../../compilers/go", "--source", tmp).Output()
	if err != nil {
		t.Fatalf("compile TwoMethodReadonly: %v", err)
	}
	var art RunarArtifact
	if err := json.Unmarshal(out, &art); err != nil {
		t.Fatalf("unmarshal artifact: %v", err)
	}
	return art
}

func TestN270_TwoMethodReadonlyFixture_HasDistinctPerMethodCodeSeparators(t *testing.T) {
	art := compileTwoMethodReadonly(t)
	if art.ParentClass != "StatefulSmartContract" || len(art.StateFields) != 0 {
		t.Fatalf("premise: want a zero-mutable-field StatefulSmartContract, got %q with %d state fields",
			art.ParentClass, len(art.StateFields))
	}
	if len(art.CodeSeparatorIndices) != 2 {
		t.Fatalf("premise: want 2 per-method code separators, got %v", art.CodeSeparatorIndices)
	}
	if art.CodeSeparatorIndices[0] == art.CodeSeparatorIndices[1] {
		t.Fatalf("premise: per-method code separators must be at DISTINCT offsets, got %v", art.CodeSeparatorIndices)
	}
}

func TestN270_StatelessBranch_MethodB_IsSpendValid(t *testing.T) {
	art := compileTwoMethodReadonly(t)

	signer, err := NewLocalSigner("0000000000000000000000000000000000000000000000000000000000000003")
	if err != nil {
		t.Fatal(err)
	}
	addr, _ := signer.GetAddress()
	pubKey, _ := signer.GetPublicKey()
	lockingHex := NewRunarContract(&art, []interface{}{pubKey}).GetLockingScript()

	primary := UTXO{Txid: strings.Repeat("aa", 32), OutputIndex: 0, Satoshis: 5000, Script: lockingHex}

	provider := NewMockProvider("testnet") // broadcast validation default-on
	provider.AddUtxo(addr, UTXO{Txid: strings.Repeat("bb", 32), OutputIndex: 0, Satoshis: 100000, Script: BuildP2PKHScript(addr)})
	provider.AddContractUtxo(lockingHex, &primary)

	contract, err := FromUtxo(&art, primary)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := contract.Call("methodB", []interface{}{nil, nil}, provider, signer, nil); err != nil {
		t.Fatalf("methodB call: %v", err)
	}
	if got := provider.LastValidatedInputCount(); got != 2 {
		t.Fatalf("validated %d of 2 inputs", got)
	}
	txs := provider.GetBroadcastedTxs()
	if got := txs[len(txs)-1]; got != n270MethodBTxHex {
		t.Fatalf("methodB tx differs from the cross-tier N-270 vector\n got: %s\nwant: %s", got, n270MethodBTxHex)
	}
}

// Pinned after the fix lands: byte-identical to packages/runar-sdk's TS
// vector and to the never-buggy Python SDK's (used as an independent oracle
// before this value was pinned here).
const n270MethodBTxHex = "0100000002aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000000fdc202473044022025bdb788c88800da0e122ee07bd7e7cf108c4c6d53ebf09ed2ed7f37e4ab1ec3022012880daf6cb232de74f645e6c69e69b74e7096257735aea1ff394d87d6309fcf414d760201000000ef9b6802354444eada24842d68525e3b2860d0af5b1b6abc6c2438eb193da948752adad0a7b9ceca853768aebb6965eca126a62965f698a0c1bc43d83db632adaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000000fdd70176aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e818b21414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937782927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e21038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218ad698254947f7701007e8101419d2102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9ac688813000000000000ffffffffb80a35939e20ceea1e5b24188c0630fdc61fad29e98ab26a0a7546b96748de06000000004100000051ffffffffbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb000000006a47304402200274b1644d07fe4be16d71199ab51edb6c62666285ae09526a0badb16bbc815c022019c1ea6f05f733859e15312ef965dd2cb0fb9d6f8c4632828763fc7a1fad2238412102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9ffffffff01c9990100000000001976a9147dd65592d0ab2fe0d0257d571abf032cd9db93dc88ac00000000"
