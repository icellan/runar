package runar

// N-433: the stateless / zero-mutable-field PrepareCall branch and the
// stateless terminal branch computed a k=1 OP_PUSH_TX ECDSA signature through
// ComputeOpPushTxWithSigHash and never put it in any output
// (buildStatefulPrefix ignores its argument; the only reader of the value was
// a `finalOpPushTxSig != ""` flag that is true exactly when needsOpPushTx is).
// They now use ComputeOpPushTxPreimageWithSigHash (N-253) with the boolean.
//
// Proves: on each stateless path (zero-mutable merge with an extra contract
// input, single-input call, terminal call) zero OP_PUSH_TX signs happen,
// counted through the opPushTxSign seam (countOpPushTxSigns, N-253), and the
// broadcast bytes equal the pinned pre-change vectors (n258MergeTxHex,
// n270MethodBTxHex and the terminal vector captured at base).
// Does not prove: anything on-chain beyond MockProvider's script validation.

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func n433Setup(t *testing.T, art *RunarArtifact) (Signer, string, string, UTXO, *MockProvider) {
	t.Helper()
	signer, err := NewLocalSigner("0000000000000000000000000000000000000000000000000000000000000003")
	if err != nil {
		t.Fatal(err)
	}
	addr, _ := signer.GetAddress()
	pubKey, _ := signer.GetPublicKey()
	lockingHex := NewRunarContract(art, []interface{}{pubKey}).GetLockingScript()
	primary := UTXO{Txid: strings.Repeat("aa", 32), OutputIndex: 0, Satoshis: 5000, Script: lockingHex}
	provider := NewMockProvider("testnet")
	provider.AddUtxo(addr, UTXO{Txid: strings.Repeat("bb", 32), OutputIndex: 0, Satoshis: 100000, Script: BuildP2PKHScript(addr)})
	provider.AddContractUtxo(lockingHex, &primary)
	return signer, addr, lockingHex, primary, provider
}

func lastTx(p *MockProvider) string {
	txs := p.GetBroadcastedTxs()
	return txs[len(txs)-1]
}

func TestN433_ZeroMutableMerge_NoOpPushTxSignature(t *testing.T) {
	src, err := os.ReadFile("../../examples/ts/all-readonly-cleanstack/AllReadonlyCleanstack.runar.ts")
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir() + "/AllReadonlyCleanstack.runar.ts"
	if err := os.WriteFile(tmp, src, 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("go", "run", "../../compilers/go", "--source", tmp).Output()
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	var art RunarArtifact
	if err := json.Unmarshal(out, &art); err != nil {
		t.Fatal(err)
	}
	signer, _, lockingHex, primary, provider := n433Setup(t, &art)
	extra := UTXO{Txid: strings.Repeat("cc", 32), OutputIndex: 1, Satoshis: 7000, Script: lockingHex}
	provider.AddContractUtxo(lockingHex+":extra", &extra)
	contract, err := FromUtxo(&art, primary)
	if err != nil {
		t.Fatal(err)
	}
	signs := countOpPushTxSigns(t)
	if _, _, err := contract.Call("claim", []interface{}{nil, nil}, provider, signer, &CallOptions{
		AdditionalContractInputs: []*UTXO{&extra},
	}); err != nil {
		t.Fatalf("merge call: %v", err)
	}
	if *signs != 0 {
		t.Fatalf("zero-mutable merge computed %d OP_PUSH_TX signature(s); want 0", *signs)
	}
	if got := lastTx(provider); got != n258MergeTxHex {
		t.Fatalf("merge tx bytes moved\n got: %s\nwant: %s", got, n258MergeTxHex)
	}
}

func TestN433_StatelessSingleInput_NoOpPushTxSignature(t *testing.T) {
	art := compileTwoMethodReadonly(t)
	signer, _, _, primary, provider := n433Setup(t, &art)
	contract, err := FromUtxo(&art, primary)
	if err != nil {
		t.Fatal(err)
	}
	signs := countOpPushTxSigns(t)
	if _, _, err := contract.Call("methodB", []interface{}{nil, nil}, provider, signer, nil); err != nil {
		t.Fatalf("methodB call: %v", err)
	}
	if *signs != 0 {
		t.Fatalf("stateless call computed %d OP_PUSH_TX signature(s); want 0", *signs)
	}
	if got := lastTx(provider); got != n270MethodBTxHex {
		t.Fatalf("methodB tx bytes moved\n got: %s\nwant: %s", got, n270MethodBTxHex)
	}
}

func TestN433_StatelessTerminal_NoOpPushTxSignature(t *testing.T) {
	art := compileTwoMethodReadonly(t)
	signer, addr, _, primary, provider := n433Setup(t, &art)
	contract, err := FromUtxo(&art, primary)
	if err != nil {
		t.Fatal(err)
	}
	signs := countOpPushTxSigns(t)
	if _, _, err := contract.Call("methodB", []interface{}{nil, nil}, provider, signer, &CallOptions{
		TerminalOutputs: []TerminalOutput{{ScriptHex: BuildP2PKHScript(addr), Satoshis: 4000}},
	}); err != nil {
		t.Fatalf("terminal call: %v", err)
	}
	if *signs != 0 {
		t.Fatalf("stateless terminal computed %d OP_PUSH_TX signature(s); want 0", *signs)
	}
	if got := lastTx(provider); got != n433TerminalTxHex {
		t.Fatalf("terminal tx bytes moved\n got: %s\nwant: %s", got, n433TerminalTxHex)
	}
}

const n433TerminalTxHex = "0100000001aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000000fdc8024730440220620e5c2cd05d97ca2d91951469bfc3a61a9bb4b1dc1959e16e510f69fba043e902203900d7ee047c058c57776952d71d634d41fe175107bbf35b5518275d8e38bb53414d7c02010000006324e33631b1cb491f73dac8baa476a642eaeccfc7e00c2708764468c82a4e6c3bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e70665044aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000000fddd0176aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e8100011f80517e9321414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937776927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e2102b405d7f0322a89d0f9f3a98e6f938fdc1c969a8d1382a2bf66a71ae74a1e83b0ad698254947f7701007e8101419d2102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9ac688813000000000000ffffffff5a1ddad12332f96e1d310e510254be705e6fea5b749df0e0192092b1d56a4c14000000004100000051ffffffff01a00f0000000000001976a9147dd65592d0ab2fe0d0257d571abf032cd9db93dc88ac00000000"
