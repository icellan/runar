package runar

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// N-258 (user decision R99): a zero-mutable-field StatefulSmartContract call
// that also spends AdditionalContractInputs builds a REAL per-input unlock for
// every extra contract input (its own OP_PUSH_TX preimage over its own
// outpoint / scriptCode / amount, and its own Sig signed at its own input index
// over the post-OP_CODESEPARATOR subscript), instead of refusing (N-227) or
// shipping the sizing placeholder. Fee/change are re-derived from the real
// unlocks.
//
// The scenario is the cross-tier N-258 vector: same contract, key, outpoints
// and amounts as packages/runar-sdk/src/__tests__/n258-zero-mutable-field-
// merge.test.ts, whose tx is accepted by @bsv/sdk Spend on every input.
//
// What this test proves: the Go SDK's merge tx is accepted by MockProvider's
// default broadcast validation, which runs the go-sdk script interpreter on
// every known input (all three are known: both contract inputs and the
// funding input), and is byte-identical to the TS-produced vector.
//
// What this test does not prove: merges on a zero-mutable-field contract with
// more than one public method (the stateless branch derives OP_PUSH_TX from
// method index 0), allPrevouts auto-resolution on this branch, or the
// terminal-outputs path.
func TestN258_ZeroMutableFieldStatefulContract_MergeIsSpendValid(t *testing.T) {
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
		t.Fatalf("compile AllReadonlyCleanstack: %v", err)
	}
	var art RunarArtifact
	if err := json.Unmarshal(out, &art); err != nil {
		t.Fatalf("unmarshal artifact: %v", err)
	}
	if art.ParentClass != "StatefulSmartContract" || len(art.StateFields) != 0 {
		t.Fatalf("premise: want a zero-mutable-field StatefulSmartContract, got %q with %d state fields",
			art.ParentClass, len(art.StateFields))
	}

	signer, err := NewLocalSigner("0000000000000000000000000000000000000000000000000000000000000003")
	if err != nil {
		t.Fatal(err)
	}
	addr, _ := signer.GetAddress()
	pubKey, _ := signer.GetPublicKey()
	lockingHex := NewRunarContract(&art, []interface{}{pubKey}).GetLockingScript()

	primary := UTXO{Txid: strings.Repeat("aa", 32), OutputIndex: 0, Satoshis: 5000, Script: lockingHex}
	extra := UTXO{Txid: strings.Repeat("cc", 32), OutputIndex: 1, Satoshis: 7000, Script: lockingHex}

	provider := NewMockProvider("testnet") // broadcast validation default-on
	provider.AddUtxo(addr, UTXO{Txid: strings.Repeat("bb", 32), OutputIndex: 0, Satoshis: 100000, Script: BuildP2PKHScript(addr)})
	provider.AddContractUtxo(lockingHex, &primary)
	provider.AddContractUtxo(lockingHex+":extra", &extra)

	contract, err := FromUtxo(&art, primary)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := contract.Call("claim", []interface{}{nil, nil}, provider, signer, &CallOptions{
		AdditionalContractInputs: []*UTXO{&extra},
	}); err != nil {
		t.Fatalf("merge call: %v", err)
	}
	if got := provider.LastValidatedInputCount(); got != 3 {
		t.Fatalf("validated %d of 3 inputs", got)
	}
	txs := provider.GetBroadcastedTxs()
	if got := txs[len(txs)-1]; got != n258MergeTxHex {
		t.Fatalf("merge tx differs from the cross-tier N-258 vector\n got: %s\nwant: %s", got, n258MergeTxHex)
	}
}

const n258MergeTxHex = "0100000003aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000000fdea02473044022033b20ee497b244a5f44ea460cbeb66c867d72ee622cf6e8163651998b66da33d02200b7580e4c31b3bf66410bbd033e935bcf41449fcabfdf90275cc2a7df78f8911414d9f0201000000f81f4842d6ef7032c06b4ab50d5a9c032c4704fa3f20d7267e850a75e8da307f82a7d5bb59fc957ff7f737ca0b8be713c705d6173783ad5edb067819bed70be8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000000fd000276aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e8100011f80517e9321414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937776927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e2102b405d7f0322a89d0f9f3a98e6f938fdc1c969a8d1382a2bf66a71ae74a1e83b0ad698254947f7701007e8101419d2102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f97c2102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9ac778813000000000000ffffffffe0fb8d8fe33024ae55861c19ec7c3056e7ba656aa6623274dc5d6140edcd3d370000000041000000ffffffffcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc01000000fdea0247304402203b86795685f996d25ad0c7db76fb2b1d3ba6e1127332ba7806f9786e6ef03d0602201eca36661b0bb5e080c43fe881cae23d59194a557a76fdbca879995aaabc2314414d9f0201000000f81f4842d6ef7032c06b4ab50d5a9c032c4704fa3f20d7267e850a75e8da307f82a7d5bb59fc957ff7f737ca0b8be713c705d6173783ad5edb067819bed70be8cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc01000000fd000276aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e8100011f80517e9321414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937776927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e2102b405d7f0322a89d0f9f3a98e6f938fdc1c969a8d1382a2bf66a71ae74a1e83b0ad698254947f7701007e8101419d2102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f97c2102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9ac77581b000000000000ffffffffe0fb8d8fe33024ae55861c19ec7c3056e7ba656aa6623274dc5d6140edcd3d370000000041000000ffffffffbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb000000006b483045022100fe183c7919d2e06724b2134fa072fa1d6a698eb1b6cc07dd42341eeff238c11f02200abfed215d06dcaae1226e0497cff4ef3834ea7043cdbb76af44104c630b7c25412102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9ffffffff01ceb40100000000001976a9147dd65592d0ab2fe0d0257d571abf032cd9db93dc88ac00000000"
