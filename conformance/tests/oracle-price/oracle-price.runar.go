package contract

import "runar"

type OraclePriceFeed struct {
	runar.SmartContract
	OraclePubKey runar.RabinPubKey `runar:"readonly"`
	Receiver     runar.PubKey      `runar:"readonly"`
}

func (c *OraclePriceFeed) Settle(price runar.Bigint, rabinSig runar.RabinSig, padding runar.ByteString, sig runar.Sig) {
	// Verify oracle signed this price
	msg := runar.Num2Bin(price, 8)
	runar.Assert(runar.VerifyRabinSig(msg, rabinSig, padding, c.OraclePubKey))

	// Price must be above threshold for payout
	runar.Assert(price > 50000)

	// Receiver must sign
	runar.Assert(runar.CheckSig(sig, c.Receiver))
}
