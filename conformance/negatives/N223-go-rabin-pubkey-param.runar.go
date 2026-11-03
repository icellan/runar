// F-286: verifyRabinSig's modulus (4th argument) is a spending-method parameter,
// so the spender picks n and forges any message (n = 1, sig = 0 passes real
// Spend). Every tier must refuse:
//   verifyRabinSig public key (4th argument) must be a contract property or a literal; a spender-supplied Rabin modulus lets anyone forge a signature
// Shape: Go surface, exported-method parameter.
package contracts

import runar "github.com/icellan/runar/packages/runar-go"

type RabinParam struct {
	runar.SmartContract
	Pk runar.RabinPubKey `runar:"readonly"`
}

func (c *RabinParam) Settle(msg runar.ByteString, sig runar.RabinSig, padding runar.ByteString, n runar.RabinPubKey) {
	runar.Assert(runar.VerifyRabinSig(msg, sig, padding, n))
}
