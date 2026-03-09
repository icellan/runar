package contract

import (
	runar "github.com/icellan/runar/packages/runar-go"
	"testing"
)

func newPriceBet() *PriceBet {
	return &PriceBet{
		AlicePubKey:  runar.MockPubKey(),
		BobPubKey:    runar.MockPubKey(),
		OraclePubKey: runar.RabinPubKey("oracle_rabin_pk"),
		StrikePrice:  50000,
	}
}

func TestPriceBet_Settle_AliceWins(t *testing.T) {
	newPriceBet().Settle(60000, runar.RabinSig("sig"), runar.ByteString("pad"), runar.MockSig(), runar.MockSig())
}

func TestPriceBet_Settle_BobWins(t *testing.T) {
	newPriceBet().Settle(30000, runar.RabinSig("sig"), runar.ByteString("pad"), runar.MockSig(), runar.MockSig())
}

func TestPriceBet_Settle_BobWinsAtStrike(t *testing.T) {
	newPriceBet().Settle(50000, runar.RabinSig("sig"), runar.ByteString("pad"), runar.MockSig(), runar.MockSig())
}

func TestPriceBet_Settle_ZeroPriceRejected(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure for zero price")
		}
	}()
	newPriceBet().Settle(0, runar.RabinSig("sig"), runar.ByteString("pad"), runar.MockSig(), runar.MockSig())
}

func TestPriceBet_Cancel(t *testing.T) {
	newPriceBet().Cancel(runar.MockSig(), runar.MockSig())
}

func TestPriceBet_Compile(t *testing.T) {
	if err := runar.CompileCheck("PriceBet.runar.go"); err != nil {
		t.Fatalf("compile check failed: %v", err)
	}
}
