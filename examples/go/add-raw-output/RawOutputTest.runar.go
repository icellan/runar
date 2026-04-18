package contract

import runar "github.com/icellan/runar/packages/runar-go"

// RawOutputTest exercises AddRawOutput alongside AddOutput for stateful
// contracts.
type RawOutputTest struct {
	runar.StatefulSmartContract
	Count runar.Bigint
}

// SendToScript emits a raw output with arbitrary script bytes, then increments
// the counter and emits the state continuation.
func (c *RawOutputTest) SendToScript(scriptBytes runar.ByteString) {
	c.AddRawOutput(1000, scriptBytes)
	c.Count = c.Count + 1
	c.AddOutput(0, c.Count)
}
