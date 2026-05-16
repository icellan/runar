// Package contract — minimal `asm` raw-script contract (Go DSL surface).
package contract

import runar "github.com/icellan/runar/packages/runar-go"

type Anyone struct {
	runar.UnsafeSmartContract
}

func (c *Anyone) Unlock() {
	runar.Asm("51", 0, 1)
}
