package frontend

import (
	"strings"
	"testing"
)

// F-017 — two distinct source identifiers that a surface's name conversion
// maps to ONE Rúnar name are refused with one shared diagnostic.
//
// Before the rule, `tmp = n + 1; tmp_ = n + 2; assert_(tmp == tmp_)` in a
// .runar.py contract (always false under Python semantics) bound both
// spellings to one variable and compiled to `OP_DUP OP_DUP OP_NUMEQUAL`: an
// always-TRUE guard.
//
// What this proves: the Go tier's frontend refuses a collision on each of the
// five renaming surfaces (.py/.rs/.rb/.move/.go) with exactly the text the TS
// reference emits, picks the same pair regardless of declaration order, and
// does not refuse `sum_` on its own or a local that reuses a property's exact
// spelling.
// What it does NOT prove: anything about the other tiers (their own suites and
// conformance/negatives/N46-N50 cover that), or the semantics of a local that
// shadows a property under the same spelling (N-016, a separate item).

func f017Msg(a, b, name string) string {
	return "identifier collision: '" + a + "' and '" + b + "' both convert to '" + name + "'; rename one of them"
}

func f017Py(body string) string {
	return `from runar import SmartContract, Bigint, public, assert_


class Trail(SmartContract):
    k: Bigint

    def __init__(self, k: Bigint):
        super().__init__(k)
        self.k = k

    @public
    def unlock(self, n: Bigint):
` + body + "\n"
}

const f017Rs = `use runar::prelude::*;

#[runar::contract]
struct Trail {
    #[readonly]
    k: Int,
}

impl Trail {
    pub fn unlock(&self, n: Int) {
        let n_ = n + 1;
        assert!(n_ == n);
    }
}
`

const f017Rb = `require 'runar'

class Trail < Runar::SmartContract
  prop :k, Bigint

  def initialize(k)
    super(k)
    @k = k
  end

  runar_public n: Bigint
  def unlock(n)
    k_ = n + 1
    assert k_ == @k
  end
end
`

const f017Move = `module Trail {
    use runar::types::{Int};

    struct Trail {
        k: Int,
    }

    public fun unlock(contract: &Trail, n: Int) {
        let tmp = n + 1;
        let tmp_ = n + 2;
        assert!(tmp == tmp_, 0);
    }
}
`

const f017Go = "package contract\n\nimport runar \"github.com/icellan/runar/packages/runar-go\"\n\n" +
	"type Trail struct {\n\trunar.SmartContract\n\tK runar.Int `runar:\"readonly\"`\n}\n\n" +
	"func (c *Trail) Unlock(n runar.Int) {\n\tk := n + 1\n\trunar.Assert(k == c.K)\n}\n"

func f017CollisionErrors(src, file string) []string {
	var out []string
	for _, e := range ParseSource([]byte(src), file).Errors {
		if strings.HasPrefix(e.Message, "identifier collision") {
			out = append(out, e.Message)
		}
	}
	return out
}

func TestF017_IdentifierCollisionRefused(t *testing.T) {
	cases := []struct {
		name, src, file, want string
	}{
		{"py tmp/tmp_", f017Py("        tmp = n + 1\n        tmp_ = n + 2\n        assert_(tmp == tmp_)"), "Trail.runar.py", f017Msg("tmp", "tmp_", "tmp")},
		{"py _tmp/tmp", f017Py("        _tmp = n + 1\n        tmp = n + 2\n        assert_(_tmp == tmp)"), "Trail.runar.py", f017Msg("_tmp", "tmp", "tmp")},
		{"py a__b/a_b", f017Py("        a__b = n + 1\n        a_b = n + 2\n        assert_(a__b == a_b)"), "Trail.runar.py", f017Msg("a__b", "a_b", "aB")},
		{"py loop var", f017Py("        acc = n\n        for i_ in range(3):\n            acc = acc + 1\n        i = acc\n        assert_(i == n + 3)"), "Trail.runar.py", f017Msg("i", "i_", "i")},
		{"rs param/local", f017Rs, "Trail.runar.rs", f017Msg("n", "n_", "n")},
		{"rb property/local", f017Rb, "Trail.runar.rb", f017Msg("k", "k_", "k")},
		{"move tmp/tmp_", f017Move, "Trail.runar.move", f017Msg("tmp", "tmp_", "tmp")},
		{"go field/local", f017Go, "Trail.runar.go", f017Msg("K", "k", "k")},
		// Two collisions: the smallest Rúnar name wins, then its two
		// smallest spellings in byte order — independent of declaration order.
		{"py pair choice", f017Py("        z_ = n + 1\n        z = n + 2\n        b__c = n + 3\n        b_c = n + 4\n        bC = n + 5\n        assert_(z + z_ + b__c + b_c + bC > 0)"), "Trail.runar.py", f017Msg("bC", "b__c", "bC")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := f017CollisionErrors(tc.src, tc.file)
			if len(got) != 1 || got[0] != tc.want {
				t.Fatalf("want exactly [%q], got %q", tc.want, got)
			}
		})
	}
}

func TestF017_NoCollisionAccepted(t *testing.T) {
	for name, body := range map[string]string{
		"distinct":      "        x = n + 1\n        y = n + 2\n        assert_(x != y)",
		"sum_ alone":    "        sum_ = n + 1\n        sum_ = sum_ + 1\n        assert_(sum_ == n + 2)",
		"same spelling": "        k = n + 1\n        assert_(k == self.k)",
	} {
		t.Run(name, func(t *testing.T) {
			if got := f017CollisionErrors(f017Py(body), "Trail.runar.py"); len(got) != 0 {
				t.Fatalf("unexpected collision diagnostic: %q", got)
			}
		})
	}
}
