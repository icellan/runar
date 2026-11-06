package helpers

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// p2pkhTx builds an unsigned tx spending `in` (txid:vout) to the given
// (script, sats) outputs. Signatures are irrelevant to the ledger: it only
// tracks outpoints, so an empty unlocking script is fine here.
func p2pkhTx(t *testing.T, inTxid string, inVout uint32, outs ...struct {
	script string
	sats   uint64
}) *transaction.Transaction {
	t.Helper()
	tx := transaction.NewTransaction()
	if err := tx.AddInputFrom(inTxid, inVout, "51", 1, nil); err != nil {
		t.Fatalf("add input: %v", err)
	}
	for _, o := range outs {
		s, err := script.NewFromHex(o.script)
		if err != nil {
			t.Fatalf("script: %v", err)
		}
		tx.AddOutput(&transaction.TransactionOutput{Satoshis: o.sats, LockingScript: s})
	}
	return tx
}

type out = struct {
	script string
	sats   uint64
}

func TestUtxoLedger_TracksOutputsAndConsumesInputs(t *testing.T) {
	alice, bob := NewWallet(), NewWallet()
	l := newUtxoLedger()

	// Funding tx: 2 outputs to alice, 1 to bob.
	fund := p2pkhTx(t, "11"+strings.Repeat("00", 31), 0,
		out{alice.P2PKHScript(), 1000},
		out{alice.P2PKHScript(), 2000},
		out{bob.P2PKHScript(), 3000},
	)
	if err := l.recordHex(fund.Hex()); err != nil {
		t.Fatalf("record fund: %v", err)
	}
	fundID := fund.TxID().String()

	got, err := l.utxosForAddress(alice.Address)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("alice: want 2 utxos, got %d: %+v", len(got), got)
	}

	// Spend alice's output 0 into a new output for alice (e.g. a deploy's change).
	spend := p2pkhTx(t, fundID, 0, out{alice.P2PKHScript(), 900})
	if err := l.recordHex(spend.Hex()); err != nil {
		t.Fatalf("record spend: %v", err)
	}
	spendID := spend.TxID().String()

	got, _ = l.utxosForAddress(alice.Address)
	seen := map[string]int64{}
	for _, u := range got {
		seen[fmt.Sprintf("%s:%d", u.Txid, u.OutputIndex)] = u.Satoshis
		if u.Script != alice.P2PKHScript() {
			t.Errorf("wrong script on %s:%d: %s", u.Txid, u.OutputIndex, u.Script)
		}
	}
	if len(got) != 2 {
		t.Fatalf("alice after spend: want 2 utxos, got %d: %+v", len(got), got)
	}
	if _, ok := seen[fundID+":0"]; ok {
		t.Errorf("spent outpoint %s:0 still returned", fundID)
	}
	if seen[fundID+":1"] != 2000 {
		t.Errorf("want %s:1 = 2000 sats, got %v", fundID, seen)
	}
	if seen[spendID+":0"] != 900 {
		t.Errorf("want %s:0 = 900 sats, got %v", spendID, seen)
	}

	// Bob is untouched.
	got, _ = l.utxosForAddress(bob.Address)
	if len(got) != 1 || got[0].Satoshis != 3000 || got[0].OutputIndex != 2 {
		t.Errorf("bob: want single 3000-sat utxo at vout 2, got %+v", got)
	}

	// Unknown address → empty, not an error.
	got, err = l.utxosForAddress(NewWallet().Address)
	if err != nil || len(got) != 0 {
		t.Errorf("stranger: want empty, got %+v err=%v", got, err)
	}
}

// Satoshi values come from the serialized tx, so they are exact — no
// float BTC conversion (the rounding problem behind commit c92ea6349).
func TestUtxoLedger_ExactSatoshis(t *testing.T) {
	w := NewWallet()
	l := newUtxoLedger()
	tx := p2pkhTx(t, "22"+strings.Repeat("00", 31), 0, out{w.P2PKHScript(), 1000540})
	if err := l.recordHex(tx.Hex()); err != nil {
		t.Fatal(err)
	}
	got, _ := l.utxosForAddress(w.Address)
	if len(got) != 1 || got[0].Satoshis != 1000540 {
		t.Fatalf("want 1000540 sats, got %+v", got)
	}
}

func TestUtxoLedger_RejectsGarbage(t *testing.T) {
	l := newUtxoLedger()
	if err := l.recordHex("zz"); err == nil {
		t.Fatal("want error for non-hex tx")
	}
	if _, err := l.utxosForAddress("not-an-address"); err == nil {
		t.Fatal("want error for invalid address")
	}
}

func TestUtxoLedger_ConcurrentRecord(t *testing.T) {
	w := NewWallet()
	l := newUtxoLedger()
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tx := p2pkhTx(t, "33"+strings.Repeat("00", 30)+fmt.Sprintf("%02x", i), 0, out{w.P2PKHScript(), uint64(1000 + i)})
			if err := l.recordHex(tx.Hex()); err != nil {
				t.Error(err)
			}
			_, _ = l.utxosForAddress(w.Address)
		}(i)
	}
	wg.Wait()
	got, _ := l.utxosForAddress(w.Address)
	if len(got) != 32 {
		t.Fatalf("want 32 utxos, got %d", len(got))
	}
}
