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

func TestR147_AckDirectiveIsHonouredOnEverySurface(t *testing.T) {
	for ext, c := range ackSources() {
		res := ParseSource([]byte(c.src), c.file)
		if res == nil || res.Contract == nil {
			t.Fatalf("%s: parse produced no contract: %+v", ext, res)
		}
		if !res.Contract.AckUnsoundSP1Fri {
			t.Errorf("%s: @acknowledgeUnsoundSP1FriVerifier was not recorded. "+
				"The stamp is applied to the parse RESULT so it is independent of "+
				"which surface parser ran — a branch that returns without it makes "+
				"the directive unhonourable on that surface alone.", ext)
		}
	}
}

// The control: no directive, no stamp. Without this the test above would pass
// against a stamp that is always true.
func TestR147_NoDirectiveMeansNoAck(t *testing.T) {
	for ext, c := range ackSources() {
		clean := c.src[len(ackDirective):]
		res := ParseSource([]byte(clean), c.file)
		if res == nil || res.Contract == nil {
			t.Fatalf("%s: parse produced no contract", ext)
		}
		if res.Contract.AckUnsoundSP1Fri {
			t.Errorf("%s: ack recorded for a source that carries no directive", ext)
		}
	}
}
