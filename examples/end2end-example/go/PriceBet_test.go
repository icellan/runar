package contract

import (
	runar "github.com/icellan/runar/packages/runar-go"
	"testing"
)

func newPriceBet() *PriceBet {
	return &PriceBet{
		AlicePubKey:  runar.Alice.PubKey,
		BobPubKey:    runar.Bob.PubKey,
		OraclePubKey: runar.RabinTestKeyN,
		StrikePrice:  50000,
	}
}

func signPrice(price int64) (runar.RabinSig, runar.ByteString) {
	msg := runar.Num2Bin(price, 8)
	return runar.RabinSignToBytes([]byte(msg), runar.RabinTestP(), runar.RabinTestQ())
}

func TestPriceBet_Settle_AliceWins(t *testing.T) {
	rabinSig, pad := signPrice(60000)
	aliceSig := runar.SignTestMessage(runar.Alice.PrivKey)
	bobSig := runar.SignTestMessage(runar.Bob.PrivKey)
	newPriceBet().Settle(60000, rabinSig, pad, aliceSig, bobSig)
}

func TestPriceBet_Settle_BobWins(t *testing.T) {
	rabinSig, pad := signPrice(30000)
	aliceSig := runar.SignTestMessage(runar.Alice.PrivKey)
	bobSig := runar.SignTestMessage(runar.Bob.PrivKey)
	newPriceBet().Settle(30000, rabinSig, pad, aliceSig, bobSig)
}

func TestPriceBet_Settle_BobWinsAtStrike(t *testing.T) {
	rabinSig, pad := signPrice(50000)
	aliceSig := runar.SignTestMessage(runar.Alice.PrivKey)
	bobSig := runar.SignTestMessage(runar.Bob.PrivKey)
	newPriceBet().Settle(50000, rabinSig, pad, aliceSig, bobSig)
}

func TestPriceBet_Settle_ZeroPriceRejected(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure for zero price")
		}
	}()
	rabinSig, pad := signPrice(0)
	aliceSig := runar.SignTestMessage(runar.Alice.PrivKey)
	bobSig := runar.SignTestMessage(runar.Bob.PrivKey)
	newPriceBet().Settle(0, rabinSig, pad, aliceSig, bobSig)
}

func TestPriceBet_Cancel(t *testing.T) {
	aliceSig := runar.SignTestMessage(runar.Alice.PrivKey)
	bobSig := runar.SignTestMessage(runar.Bob.PrivKey)
	newPriceBet().Cancel(aliceSig, bobSig)
}

func TestPriceBet_Compile(t *testing.T) {
	if err := runar.CompileCheck("PriceBet.runar.go"); err != nil {
		t.Fatalf("compile check failed: %v", err)
	}
}
