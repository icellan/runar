package frontend

import "testing"

// R-147 / CL-BUG-056 — `stampSP1FriAck` wrapped six of the eight non-default
// dispatch branches, but not Solidity and not Rust.
//
// The stamp records whether the raw source carried
// `@acknowledgeUnsoundSP1FriVerifier`, and it is applied to the parse RESULT
// precisely so it is independent of which surface parser ran. Two branches
// returned without it, so on `.runar.sol` and `.runar.rs` the directive could
// never be honoured: the SP1-FRI refusal was unbypassable there, and on the
// other seven surfaces it was not.
//
// That is SAFE — the strict direction — but it is a per-surface behaviour
// difference in a security gate, undocumented and unexercised, and the kind of
// thing a reader discovers by writing a contract that will not compile for a
// reason the docs say it should.
//
// Frontend parity is this project's first invariant, and a directive honoured
// on seven of nine surfaces is a violation of it whichever direction the odd
// ones lean.
//
// F-007 removed the directive (and stampSP1FriAck) outright: the SP1 FRI
// verifier is not implemented for v1 and is refused on every surface. The
// tests below keep the per-surface sources and now pin that the old directive
// is inert on each of them.

const ackDirective = "// @acknowledgeUnsoundSP1FriVerifier\n"

func ackSources() map[string]struct{ file, src string } {
	return map[string]struct{ file, src string }{
		".runar.sol": {"P.runar.sol", ackDirective + `pragma runar ^1.0;

contract P {
    bigint immutable a;

    constructor(bigint a_) {
        a = a_;
    }

    function go(bigint x) public {
        require(x > a);
    }
}
`},
		".runar.rs": {"P.runar.rs", ackDirective + `use runar::prelude::*;

#[runar::contract]
struct P {
    #[readonly]
    a: Int,
}

impl P {
    pub fn go(&self, x: Int) {
        assert!(x > self.a);
    }
}
`},
		".runar.ts": {"P.runar.ts", ackDirective + `import { SmartContract, assert } from 'runar-lang';

export class P extends SmartContract {
  readonly a: bigint;

  constructor(a: bigint) {
    super(a);
    this.a = a;
  }

  public go(x: bigint) {
    assert(x > this.a);
  }
}
`},
	}
}

// withSP1FriCall appends `assert(verifySP1FRI(a, a, a))` to the contract's
// first method, so the refusal can be checked on the AST each surface produced.
func withSP1FriCall(c *ContractNode) *ContractNode {
	call := ExpressionStmt{Expr: CallExpr{
		Callee: Identifier{Name: "assert"},
		Args: []Expression{CallExpr{
			Callee: Identifier{Name: "verifySP1FRI"},
			Args:   []Expression{Identifier{Name: "a"}, Identifier{Name: "a"}, Identifier{Name: "a"}},
		}},
	}}
	c.Methods[0].Body = append(c.Methods[0].Body, call)
	return c
}

func sp1Refused(c *ContractNode) bool {
	for _, d := range Validate(c).Errors {
		if containsSubstr(d.Message, "not implemented for v1") {
			return true
		}
	}
	return false
}

// Was TestR147_AckDirectiveIsHonouredOnEverySurface.
// F-007: rewritten to expect refusal — the directive was removed for v1, so on every surface it must open nothing.
func TestR147_AckDirectiveIsInertOnEverySurface(t *testing.T) {
	for ext, c := range ackSources() {
		res := ParseSource([]byte(c.src), c.file)
		if res == nil || res.Contract == nil || len(res.Errors) > 0 {
			t.Fatalf("%s: a source carrying the old directive must still parse: %+v", ext, res)
		}
		if !sp1Refused(withSP1FriCall(res.Contract)) {
			t.Errorf("%s: @acknowledgeUnsoundSP1FriVerifier stood the verifySP1FRI refusal down; "+
				"F-007 removed that override on every surface", ext)
		}
	}
}

// Was TestR147_NoDirectiveMeansNoAck — the control. F-007: rewritten to expect refusal without the directive too,
// so the test above cannot pass against a refusal that only fires when the directive is present.
func TestR147_NoDirectiveStillRefused(t *testing.T) {
	for ext, c := range ackSources() {
		clean := c.src[len(ackDirective):]
		res := ParseSource([]byte(clean), c.file)
		if res == nil || res.Contract == nil {
			t.Fatalf("%s: parse produced no contract", ext)
		}
		// Checked first: withSP1FriCall mutates the contract.
		if sp1Refused(res.Contract) {
			t.Errorf("%s: refusal fired for a contract that does not call verifySP1FRI", ext)
		}
		if !sp1Refused(withSP1FriCall(res.Contract)) {
			t.Errorf("%s: verifySP1FRI was not refused", ext)
		}
	}
}
