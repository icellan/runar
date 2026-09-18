//go:build ignore

// R-065 — a three-part Go `for` header whose POST clause is empty.
//
// `for i := runar.Int(0); i < 5; {` is legal Go: the update lives in the body.
// This is the same rule N35 states, reached through a different hole, and it
// needs its own fixture because the two holes are in different passes.
//
// Here the bound IS parsed (5) and only the update is missing, so Zig's
// `validate.zig` R-065 rule is the one that should fire — and does not,
// because the check sits inside `if (f.update) |u|`. A `null` update is
// legitimate for `for i in 0..N` (Rust) and `range(N)` (Python), which is why
// the guard was written that way; a C-style three-part header with an empty
// post clause is a different thing entirely and the AST could not tell them
// apart.
//
// Measured before the fix (exit codes captured without a pipe):
//
//   ts / python / ruby   exit 1   parse error
//   go                   exit 1   R-065 "For loop update must advance…"
//   rust                 exit 1   parse error
//   java                 exit 65  parse error
//   zig                  exit 0   114 hexchars — unrolled five times, skipping
//                                 R-065 entirely
//
// Zig emitted a five-iteration script for a loop no other tier will compile.

package contract

import "runar"

type GoLoopEmptyPost struct {
	runar.SmartContract
	ExpectedSum runar.Int `runar:"readonly"`
}

func (c *GoLoopEmptyPost) Verify(start runar.Int) {
	sum := runar.Int(0)
	for i := runar.Int(0); i < 5; {
		sum = sum + start + i
		i++
	}
	runar.Assert(sum == c.ExpectedSum)
}
