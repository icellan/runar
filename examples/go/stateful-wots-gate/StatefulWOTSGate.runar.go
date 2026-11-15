package contract

import runar "github.com/icellan/runar/packages/runar-go"

// StatefulWOTSGate — stateful + post-quantum interaction fixture (GAP-407).
// TEST FIXTURE, NOT AN AUTHORIZATION GATE: wotsPubKey is a spender-supplied witness,
// so anyone can advance the counter; it exists to exercise stateful covenant +
// WOTS+ verify composition (GAP-407).
type StatefulWOTSGate struct {
	runar.StatefulSmartContract
	Count runar.Int
}

func (c *StatefulWOTSGate) Advance(msg runar.ByteString, sig runar.ByteString, wotsPubKey runar.ByteString) {
	runar.Assert(runar.VerifyWOTS(msg, sig, wotsPubKey))
	c.Count = c.Count + 1
}
