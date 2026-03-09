package contract

import (
	"testing"
	runar "github.com/icellan/runar/packages/runar-go"
)

func newOracleFeed() *OraclePriceFeed {
	return &OraclePriceFeed{
		OraclePubKey: runar.RabinPubKey("oracle_rabin_pk"),
		Receiver:     runar.MockPubKey(),
	}
}

func TestOraclePriceFeed_Settle(t *testing.T) {
	newOracleFeed().Settle(60000, runar.RabinSig("sig"), runar.ByteString("pad"), runar.MockSig())
}

func TestOraclePriceFeed_Settle_PriceTooLow_Fails(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure")
		}
	}()
	newOracleFeed().Settle(50000, runar.RabinSig("sig"), runar.ByteString("pad"), runar.MockSig())
}

func TestOraclePriceFeed_Compile(t *testing.T) {
	if err := runar.CompileCheck("OraclePriceFeed.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}
