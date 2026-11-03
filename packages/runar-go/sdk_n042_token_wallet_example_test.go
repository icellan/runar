package runar

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"testing"
)

// N-042: TokenWallet must drive a SHIPPED example contract, not only the
// fixture inlined in the F-045 test. This compiles
// examples/ts/token-wallet-naive-INSECURE/WalletToken.runar.ts with the Go
// compiler and runs Transfer / Merge against it.
//
// Oracle: MockProvider's broadcast validation plus a go-sdk interpreter replay
// of every input (f045ValidateAll; real ECDSA / BIP-143).
//
// Proves: the shipped example compiles in the Go tier and every input of the
// txs TokenWallet broadcasts executes; Merge spends both token outpoints once
// and the continuation holds the summed supply.
// Does NOT prove: node acceptance, or that the example is a sound token (its
// header documents that transfer keeps the holder and merge is inflatable).

const n042ExamplePath = "../../examples/ts/token-wallet-naive-INSECURE/WalletToken.runar.ts"

func n042Artifact(t *testing.T) *RunarArtifact {
	t.Helper()
	if _, err := os.Stat(n042ExamplePath); err != nil {
		t.Fatalf("shipped TokenWallet example missing: %v", err)
	}
	out, err := exec.Command("go", "run", "../../compilers/go", "--source", n042ExamplePath).Output()
	if err != nil {
		t.Fatalf("compile WalletToken example: %v", err)
	}
	var art RunarArtifact
	if err := json.Unmarshal(out, &art); err != nil {
		t.Fatalf("unmarshal artifact: %v", err)
	}
	return &art
}

func TestN042_TokenWalletDrivesShippedExample(t *testing.T) {
	art := n042Artifact(t)

	t.Run("transfer", func(t *testing.T) {
		provider, wallet, tokens, known := f045Setup(t, art, []int64{100}, 5000, 200000)
		bal, err := wallet.GetBalance()
		if err != nil || bal != 100 {
			t.Fatalf("GetBalance = %d, %v; want 100", bal, err)
		}
		other, _ := NewLocalSigner("0000000000000000000000000000000000000000000000000000000000000144")
		otherAddr, _ := other.GetAddress()
		if _, err := wallet.Transfer(otherAddr, 100); err != nil {
			t.Fatalf("Transfer: %v", err)
		}
		txs := provider.GetBroadcastedTxs()
		tx := f045ValidateAll(t, txs[len(txs)-1], known)
		if got, want := f045Spent(tx)[0], tokens[0].Txid+":0"; got != want {
			t.Fatalf("input 0 spends %s, want token %s", got, want)
		}
	})

	t.Run("merge", func(t *testing.T) {
		provider, wallet, tokens, known := f045Setup(t, art, []int64{100, 250}, 5000, 200000)
		if _, err := wallet.Merge(); err != nil {
			t.Fatalf("Merge: %v", err)
		}
		txs := provider.GetBroadcastedTxs()
		tx := f045ValidateAll(t, txs[len(txs)-1], known)
		spent := f045Spent(tx)
		seen := map[string]int{}
		for _, s := range spent {
			seen[s]++
		}
		for _, u := range tokens {
			if seen[u.Txid+":0"] != 1 {
				t.Fatalf("token %s spent %d times, want 1 (inputs %v)", u.Txid, seen[u.Txid+":0"], spent)
			}
		}
		merged, err := FromUtxo(art, UTXO{Txid: "00", OutputIndex: 0, Satoshis: int64(tx.Outputs[0].Satoshis), Script: hex.EncodeToString(*tx.Outputs[0].LockingScript)})
		if err != nil {
			t.Fatal(err)
		}
		if got := anfToBigInt(merged.GetState()["supply"]).Int64(); got != 350 {
			t.Fatalf("merged supply = %d, want 350", got)
		}
	})
}
