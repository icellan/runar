package x

import runar "github.com/icellan/runar/packages/runar-go"

// IntentOutputP2PKH exercises the runar.RequireOutputP2PKH intrinsic.
// The contract asserts that output 0 of the spending transaction is a
// standard P2PKH output paying exactly `BondAmount` satoshis to
// `BondPKH` (the 20-byte HASH160 of the bond-return pubkey).
//
// The auto-injected method parameter `_serialisedOutputs` carries the
// full serialised output set; the intrinsic asserts hash256 of those
// bytes matches the preimage's hashOutputs field, then substrings at
// offset 0 (= outputIndex * 34) to compare against the expected P2PKH
// bytes.
type IntentOutputP2PKH struct {
	runar.StatefulSmartContract

	BondPKH    runar.ByteString `runar:"readonly"`
	BondAmount runar.Bigint     `runar:"readonly"`
	Count      runar.Bigint
}

func (c *IntentOutputP2PKH) PayBond() {
	runar.RequireOutputP2PKH(0, c.BondPKH, c.BondAmount)
	c.Count = c.Count + 1
}
