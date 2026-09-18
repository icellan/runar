//go:build ignore

// R-065 — a Go-format `for` header with a condition and nothing else.
//
// The unrolled loop model carries `{count, iterVar, start, step, body}` and
// synthesises iteration k as `start + k*step`. A condition-only header puts
// the update (if any) in the BODY, where the compiler cannot prove that it
// runs unconditionally, that it runs once per iteration, or that it advances
// by one — so no iteration count is derivable. spec/grammar.md:420 already
// says so: "The loop variable MUST use simple increment (`++`) or decrement
// (`--`)". A header with no update clause has no such variable.
//
// Measured before the fix (exit codes captured without a pipe):
//
//   ts       exit 1   parse error
//   go       exit 1   R-065 "For loop update must advance the loop variable…"
//   python   exit 1   R-065, same sentence
//   ruby     exit 1   parse error
//   java     exit 65  R-065, same sentence
//   rust     exit 0   184 hexchars — GUESSED count=5 from the condition
//   zig      exit 0   16 hexchars, `0000007b7c9c7777` — the LOOP BODY IS GONE
//
// Zig's `parse_go.zig` tried the three-part header, failed on the missing
// `;`, restored the tokenizer and then DISCARDED the whole header with a
// `while (kind != .lbrace) { _ = bump(); }`. `bound` kept its `0` default, so
// `anf_lower` computed `count = bound - start = 0` and unrolled zero times:
// `sum` never accumulates and the guard degrades to `0 == expectedSum`.
// Anyone-can-spend when that constant is 0, permanently unspendable when it
// is not. Fund loss either way, from source a developer would plausibly write.
//
// Rust's answer is not merely different, it is unsound: it derives the count
// from the condition alone, so a body whose increment is CONDITIONAL — a Go
// program that either spins forever or advances irregularly — also unrolls to
// a fixed five iterations. Measured: a body of `if start > 3 { i++ }; sum =
// sum + i` compiled clean to 234 hexchars. A script that computes something
// the source does not say is worse than no script.
//
// So all seven refuse. A parser that cannot derive a bound must say so, not
// pick one.

package contract

import "runar"

type GoLoopConditionOnly struct {
	runar.SmartContract
	ExpectedSum runar.Int `runar:"readonly"`
}

func (c *GoLoopConditionOnly) Verify(start runar.Int) {
	sum := runar.Int(0)
	i := runar.Int(0)
	for i < 5 {
		sum = sum + start + i
		i++
	}
	runar.Assert(sum == c.ExpectedSum)
}
