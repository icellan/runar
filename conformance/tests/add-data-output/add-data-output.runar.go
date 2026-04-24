package contract

import runar "github.com/icellan/runar/packages/runar-go"

// DataOutputTest exercises AddDataOutput alongside state continuation.
type DataOutputTest struct {
	runar.StatefulSmartContract
	Count runar.Bigint
}

// Publish increments the counter and attaches an arbitrary data output whose
// bytes are committed to by the state continuation hash.
func (c *DataOutputTest) Publish(payload runar.ByteString) {
	c.Count = c.Count + 1
	c.AddDataOutput(0, payload)
}
