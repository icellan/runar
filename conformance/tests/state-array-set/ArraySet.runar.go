package contract

import runar "github.com/icellan/runar/packages/runar-go"

// ArraySet is the Go port of ArraySet.runar.ts. The array literal lives in the
// private init() method, which is how the Go DSL spells a property initializer.
type ArraySet struct {
	runar.StatefulSmartContract
	Slots [4]runar.Int
}

func (c *ArraySet) init() {
	c.Slots = [4]runar.Int{0, 0, 0, 0}
}

func (c *ArraySet) Put(i runar.Int, v runar.Int) {
	c.Slots[i] = v
	runar.Assert(true)
}
