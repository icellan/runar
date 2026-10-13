// N-010 (CL-BUG-167): the Rust tier's `.runar.go` parser recovers from an
// unparseable statement by calling `self.advance()` with NO diagnostic
// (parser_gocontract.rs, parse_block). A stray `%` cannot start a statement
// in any tier's Go surface (it is a binary-only operator), so every other
// tier's parser refuses the program outright. The Rust tier instead drops
// the `%` token silently and keeps going, compiling clean (exit 0) to a
// script that is missing the `runar.Assert` statement entirely.
// Every tier must refuse with a parse error naming the unexpected token.
package contract

import runar "github.com/icellan/runar/packages/runar-go"

type Drop struct {
	runar.SmartContract
	Secret runar.Int `runar:"readonly"`
}

func (c *Drop) Verify(claim runar.Int) {
	%
	runar.Assert(claim == c.Secret)
}
