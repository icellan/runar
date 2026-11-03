//go:build ignore

// F-011: an unterminated .runar.go string literal. Go interpreted strings
// cannot span lines, so a literal that reaches a line break is unterminated.
// Tokenizers that scanned to the next quote swallowed the guard on the next
// line. Every hand-written Go surface must refuse with:
//   unterminated string literal
// and the Go tier (go/parser) reports its own unterminated-literal error.
package contract

import runar "github.com/icellan/runar/packages/runar-go"

type Guarded struct {
	runar.SmartContract
}

func (c *Guarded) Unlock(y runar.Bigint) {
	var tag runar.ByteString = "cafe
	runar.Assert(y < 5)
	// ";
	runar.Assert(runar.Len(tag) == 2)
	runar.Assert(y >= 0)
}
