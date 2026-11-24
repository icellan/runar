package x

import runar "github.com/icellan/runar/packages/runar-go"

// StatefulTerminalLoop -- a TERMINAL stateful method (no state write, so no
// injected continuation assert) whose bounded loop of asserts is followed by a
// final assert, which is the script result. Without it the method is refused
// in every tier (conformance/negatives N547).
type StatefulTerminalLoop struct {
	runar.StatefulSmartContract

	Floor runar.Bigint
	Count runar.Bigint
}

func (c *StatefulTerminalLoop) Close(x runar.Bigint) {
	for i := runar.Bigint(0); i < 2; i++ {
		runar.Assert(x >= c.Floor+i)
	}
	runar.Assert(x > c.Count)
}
