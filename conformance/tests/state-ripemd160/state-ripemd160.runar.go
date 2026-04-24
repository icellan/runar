//go:build ignore

package contract

import "runar"

type HashRegistry struct {
	runar.StatefulSmartContract
	CurrentHash runar.Ripemd160
}

func (c *HashRegistry) Update(newHash runar.Ripemd160) {
	c.CurrentHash = newHash
	runar.Assert(true)
}
