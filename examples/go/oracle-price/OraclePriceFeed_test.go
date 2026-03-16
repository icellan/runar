package contract

import (
	"testing"
	runar "github.com/icellan/runar/packages/runar-go"
)

func newOracleFeed() *OraclePriceFeed {
	return &OraclePriceFeed{
		OraclePubKey: runar.RabinTestKeyN,
		Receiver:     runar.Alice.PubKey,
	}
}

func TestOraclePriceFeed_Settle(t *testing.T) {
	price := int64(60000)
	msg := runar.Num2Bin(price, 8)
	rabinSig, padding := runar.RabinSignToBytes([]byte(msg), runar.RabinTestP(), runar.RabinTestQ())
	receiverSig := runar.SignTestMessage(runar.Alice.PrivKey)
	newOracleFeed().Settle(price, rabinSig, padding, receiverSig)
}

func TestOraclePriceFeed_Settle_PriceTooLow_Fails(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure")
		}
	}()
	price := int64(50000)
	msg := runar.Num2Bin(price, 8)
	rabinSig, padding := runar.RabinSignToBytes([]byte(msg), runar.RabinTestP(), runar.RabinTestQ())
	receiverSig := runar.SignTestMessage(runar.Alice.PrivKey)
	newOracleFeed().Settle(price, rabinSig, padding, receiverSig)
}

func TestOraclePriceFeed_Compile(t *testing.T) {
	if err := runar.CompileCheck("OraclePriceFeed.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}
