package helpers

import (
	"strings"
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

// D25: the integration suite builds its SDK artifacts with this package's own
// pipeline, not the compiler's assembler. That pipeline dropped the ABI
// sigHashType (so every mutate-only contract, now SIGHASH_SINGLE by default,
// was spent with an ALL|FORKID preimage the OP_PUSH_TX checksig rejects) and
// never injected the mixed-contract _spentOutpointHash. 37 regtest tests
// failed on it. MockProvider replays every broadcast on the go-sdk
// interpreter, so a chain of successful calls proves the artifact matches the
// script it describes. No node needed.

const d25HelperCounterSrc = `import { StatefulSmartContract, assert } from 'runar-lang';
class Counter extends StatefulSmartContract {
  count: bigint;
  constructor(count: bigint) { super(count); this.count = count; }
  public increment() { this.count++; }
}`

const d25HelperMixedSrc = `import { StatefulSmartContract, assert, extractAmount } from 'runar-lang';
class MixedPot extends StatefulSmartContract {
  count: bigint;
  constructor(count: bigint) { super(count); this.count = count; }
  public increment() { this.count++; }
  public bump() { this.addOutput(extractAmount(this.txPreimage), this.count + 1n); }
}`

func d25HelperChain(t *testing.T, art *runar.RunarArtifact, methods []string) {
	t.Helper()
	provider := runar.NewMockProvider("testnet")
	w := NewWallet()
	signer, err := SDKSignerFromWallet(w)
	if err != nil {
		t.Fatal(err)
	}
	provider.AddUtxo(w.Address, runar.UTXO{Txid: strings.Repeat("aa", 32), OutputIndex: 0, Satoshis: 1_000_000, Script: w.P2PKHScript()})
	c := runar.NewRunarContract(art, []interface{}{int64(0)})
	if _, _, err := c.Deploy(provider, signer, runar.DeployOptions{Satoshis: 10_000}); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	for i, m := range methods {
		if _, _, err := c.Call(m, nil, provider, signer, nil); err != nil {
			t.Fatalf("call %d (%s): %v", i, m, err)
		}
	}
}

func TestD25Helper_SingleMethodCarriesSigHashType(t *testing.T) {
	art, err := CompileSourceStringToSDKArtifact(d25HelperCounterSrc, "Counter.runar.ts", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range art.ABI.Methods {
		if m.Name == "increment" && (m.SigHashType == nil || *m.SigHashType != 0x43) {
			t.Fatalf("increment sigHashType = %v, want 0x43", m.SigHashType)
		}
	}
	d25HelperChain(t, art, []string{"increment", "increment", "increment"})
}

func TestD25Helper_MixedContractCarriesSpentOutpointHash(t *testing.T) {
	art, err := CompileSourceStringToSDKArtifact(d25HelperMixedSrc, "MixedPot.runar.ts", nil)
	if err != nil {
		t.Fatal(err)
	}
	last := art.StateFields[len(art.StateFields)-1]
	if last.Name != "_spentOutpointHash" {
		t.Fatalf("last state field = %+v, want _spentOutpointHash", last)
	}
	d25HelperChain(t, art, []string{"increment", "bump", "increment"})
}
