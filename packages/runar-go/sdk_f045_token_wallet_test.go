package runar

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/script/interpreter"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// F-045: TokenWallet.Transfer / .Merge must sign the transaction that is
// actually broadcast. Pre-fix both BIP-143-signed a locally built throwaway
// tx and passed that concrete Sig into Call, which skips auto-signing and
// builds a different tx; Merge also left the second token UTXO unspent.
//
// Oracle: the go-sdk script engine (real ECDSA / BIP-143) replayed on every
// input of the broadcast tx; MockProvider's own broadcast validation (same
// engine) refuses the pre-fix tx before it is recorded.
//
// Proves: every input of the tx TokenWallet broadcasts executes, and Merge
// spends BOTH token outpoints exactly once into one continuation.
// Does NOT prove: node acceptance, the other SDKs, or token semantics beyond
// this fixture (its transfer does not reassign the holder).

const f045WalletTokenSrc = `
import { StatefulSmartContract, assert, checkSig, len } from 'runar-lang';
import type { PubKey, Sig, Addr } from 'runar-lang';

class WalletToken extends StatefulSmartContract {
  supply: bigint;
  holder: PubKey;

  constructor(supply: bigint, holder: PubKey) {
    super(supply, holder);
    this.supply = supply;
    this.holder = holder;
  }

  public transfer(sig: Sig, to: Addr) {
    assert(checkSig(sig, this.holder));
    assert(len(to) === 20n);
  }

  public merge(sig: Sig, otherSupply: bigint, otherHolder: PubKey) {
    assert(checkSig(sig, this.holder));
    assert(otherHolder === this.holder);
    assert(otherSupply >= 0n);
    this.supply = this.supply + otherSupply;
  }
}
`

func f045Artifact(t *testing.T) *RunarArtifact {
	t.Helper()
	tmp := t.TempDir() + "/WalletToken.runar.ts"
	if err := os.WriteFile(tmp, []byte(f045WalletTokenSrc), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("go", "run", "../../compilers/go", "--source", tmp).Output()
	if err != nil {
		t.Fatalf("compile WalletToken: %v", err)
	}
	var art RunarArtifact
	if err := json.Unmarshal(out, &art); err != nil {
		t.Fatalf("unmarshal artifact: %v", err)
	}
	return &art
}

type f045Known map[string]TxOutput

// f045Setup seeds token UTXOs (holding `supplies`, owned by the holder key)
// plus one P2PKH funding coin at the holder's address.
func f045Setup(t *testing.T, art *RunarArtifact, supplies []int64, tokenSats, fundingSats int64) (*MockProvider, *TokenWallet, []UTXO, f045Known) {
	t.Helper()
	signer, err := NewLocalSigner("0000000000000000000000000000000000000000000000000000000000000045")
	if err != nil {
		t.Fatal(err)
	}
	addr, _ := signer.GetAddress()
	pub, _ := signer.GetPublicKey()
	provider := NewMockProvider("testnet")
	known := f045Known{}
	var tokens []UTXO
	for i, s := range supplies {
		c := NewRunarContract(art, []interface{}{s, pub})
		txid := strings.Repeat(fmt.Sprintf("%02x", i+1), 32)
		lock := c.GetLockingScript()
		provider.AddTransaction(&TransactionData{Txid: txid, Version: 1, Outputs: []TxOutput{{Satoshis: tokenSats, Script: lock}}})
		u := UTXO{Txid: txid, OutputIndex: 0, Satoshis: tokenSats, Script: lock}
		provider.AddUtxo(addr, u)
		known[txid+":0"] = TxOutput{Satoshis: tokenSats, Script: lock}
		tokens = append(tokens, u)
	}
	funding := UTXO{Txid: strings.Repeat("fe", 32), OutputIndex: 0, Satoshis: fundingSats, Script: BuildP2PKHScript(addr)}
	provider.AddUtxo(addr, funding)
	known[funding.Txid+":0"] = TxOutput{Satoshis: fundingSats, Script: funding.Script}
	return provider, NewTokenWallet(art, provider, signer), tokens, known
}

// f045ValidateAll replays every input of txHex through the go-sdk engine.
func f045ValidateAll(t *testing.T, txHex string, known f045Known) *transaction.Transaction {
	t.Helper()
	tx, err := transaction.NewTransactionFromHex(txHex)
	if err != nil {
		t.Fatal(err)
	}
	for i, in := range tx.Inputs {
		key := fmt.Sprintf("%s:%d", in.SourceTXID.String(), in.SourceTxOutIndex)
		prev, ok := known[key]
		if !ok {
			t.Fatalf("input %d spends unknown outpoint %s", i, key)
		}
		ls, err := script.NewFromHex(prev.Script)
		if err != nil {
			t.Fatal(err)
		}
		if err := interpreter.NewEngine().Execute(
			interpreter.WithTx(tx, i, &transaction.TransactionOutput{Satoshis: uint64(prev.Satoshis), LockingScript: ls}),
			interpreter.WithAfterGenesis(), interpreter.WithAfterChronicle(), interpreter.WithForkID(),
		); err != nil {
			t.Fatalf("input %d rejected: %v", i, err)
		}
	}
	return tx
}

func f045Spent(tx *transaction.Transaction) []string {
	var s []string
	for _, in := range tx.Inputs {
		s = append(s, fmt.Sprintf("%s:%d", in.SourceTXID.String(), in.SourceTxOutIndex))
	}
	return s
}

func TestF045_TokenWalletTransfer_SignsTheBroadcastTx(t *testing.T) {
	art := f045Artifact(t)
	other, _ := NewLocalSigner("0000000000000000000000000000000000000000000000000000000000000047")
	otherAddr, _ := other.GetAddress()
	// An Addr is a hash160. The raw hash isolates signing; the Base58 address
	// is the documented form.
	for _, recipient := range []string{BuildP2PKHScript(otherAddr)[6:46], otherAddr} {
		provider, wallet, tokens, known := f045Setup(t, art, []int64{100}, 5000, 200000)
		if _, err := wallet.Transfer(recipient, 100); err != nil {
			t.Fatalf("Transfer(%s): %v", recipient, err)
		}
		txs := provider.GetBroadcastedTxs()
		tx := f045ValidateAll(t, txs[len(txs)-1], known)
		if got, want := f045Spent(tx)[0], tokens[0].Txid+":0"; got != want {
			t.Fatalf("input 0 spends %s, want token %s", got, want)
		}
	}
}

// D25: this token's continuation methods are all mutate-only, so they commit
// under SIGHASH_SINGLE, one output per input. Merge spends two token UTXOs
// into ONE continuation, which is exactly the twin-input shape SINGLE closes:
// the second input would need its own continuation at its own index. The SDK
// refuses before building or broadcasting the tx (a merge needs an addOutput
// method; see FungibleToken.merge). Both funding layouts the old test drove
// are kept, so the refusal precedes funding selection in each.
func TestF045_TokenWalletMerge_RefusedUnderSingle(t *testing.T) {
	art := f045Artifact(t)
	for _, sats := range [][2]int64{{5000, 200000}, {300000, 50000}} {
		provider, wallet, _, _ := f045Setup(t, art, []int64{100, 250}, sats[0], sats[1])
		before := len(provider.GetBroadcastedTxs())
		_, err := wallet.Merge()
		if err == nil || !strings.Contains(err.Error(), "additionalContractInputs cannot be spent into one continuation by a SIGHASH_SINGLE method") {
			t.Fatalf("Merge (token %d sats, funding %d sats): want the D25 refusal, got %v", sats[0], sats[1], err)
		}
		if after := len(provider.GetBroadcastedTxs()); after != before {
			t.Fatalf("Merge broadcast %d tx(s) before refusing", after-before)
		}
	}
}
