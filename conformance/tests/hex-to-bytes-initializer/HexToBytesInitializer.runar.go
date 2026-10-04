package contract

import runar "github.com/icellan/runar/packages/runar-go"

type HexToBytesInitializer struct {
	runar.SmartContract
	P2pkhPrefix runar.ByteString `runar:"readonly"`
	P2pkhSuffix runar.ByteString `runar:"readonly"`
	PubKeyHash  runar.Addr       `runar:"readonly"`
}

func (c *HexToBytesInitializer) init() {
	c.P2pkhPrefix = "1976a914"
	c.P2pkhSuffix = "88ac"
}

func (c *HexToBytesInitializer) Unlock(sig runar.Sig, pubKey runar.PubKey, script runar.ByteString) {
	runar.Assert(runar.Hash160(pubKey) == c.PubKeyHash)
	runar.Assert(runar.Cat(runar.Cat(c.P2pkhPrefix, c.PubKeyHash), c.P2pkhSuffix) == script)
	runar.Assert(runar.CheckSig(sig, pubKey))
}
