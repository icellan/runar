"""F-017 — two distinct source identifiers that a surface's name conversion
maps to ONE Rúnar name are refused with one shared diagnostic.

Before the rule, ``tmp = n + 1; tmp_ = n + 2; assert_(tmp == tmp_)`` in a
.runar.py contract (always false under Python semantics) bound both spellings
to one variable and compiled to ``OP_DUP OP_DUP OP_NUMEQUAL``: an always-TRUE
guard.

What this proves: the Python tier's frontend refuses a collision on each of
the five renaming surfaces (.py/.rs/.rb/.move/.go) with exactly the text the
TS reference emits, picks the same pair regardless of declaration order, and
does not refuse ``sum_`` on its own or a local that reuses a property's exact
spelling.
What it does NOT prove: anything about the other tiers (their own suites and
conformance/negatives/N46-N50 cover that), or the semantics of a local that
shadows a property under the same spelling (N-016, a separate item).
"""
from __future__ import annotations

import pytest

from runar_compiler.frontend.parser_dispatch import parse_source


def _msg(a: str, b: str, name: str) -> str:
    return f"identifier collision: '{a}' and '{b}' both convert to '{name}'; rename one of them"


def _py(body: str) -> str:
    return (
        "from runar import SmartContract, Bigint, public, assert_\n\n\n"
        "class Trail(SmartContract):\n"
        "    k: Bigint\n\n"
        "    def __init__(self, k: Bigint):\n"
        "        super().__init__(k)\n"
        "        self.k = k\n\n"
        "    @public\n"
        "    def unlock(self, n: Bigint):\n"
        f"{body}\n"
    )


_RS = """use runar::prelude::*;

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
"""

_RB = """require 'runar'

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
"""

_MOVE = """module Trail {
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
"""

_GO = (
    "package contract\n\nimport runar \"github.com/icellan/runar/packages/runar-go\"\n\n"
    "type Trail struct {\n\trunar.SmartContract\n\tK runar.Int `runar:\"readonly\"`\n}\n\n"
    "func (c *Trail) Unlock(n runar.Int) {\n\tk := n + 1\n\trunar.Assert(k == c.K)\n}\n"
)


def _collisions(src: str, file_name: str) -> list[str]:
    result = parse_source(src, file_name)
    msgs = [getattr(e, "message", str(e)) for e in result.errors]
    return [m for m in msgs if m.startswith("identifier collision")]


@pytest.mark.parametrize(
    "src,file_name,expected",
    [
        (_py("        tmp = n + 1\n        tmp_ = n + 2\n        assert_(tmp == tmp_)"), "Trail.runar.py", _msg("tmp", "tmp_", "tmp")),
        (_py("        _tmp = n + 1\n        tmp = n + 2\n        assert_(_tmp == tmp)"), "Trail.runar.py", _msg("_tmp", "tmp", "tmp")),
        (_py("        a__b = n + 1\n        a_b = n + 2\n        assert_(a__b == a_b)"), "Trail.runar.py", _msg("a__b", "a_b", "aB")),
        (_py("        acc = n\n        for i_ in range(3):\n            acc = acc + 1\n        i = acc\n        assert_(i == n + 3)"), "Trail.runar.py", _msg("i", "i_", "i")),
        (_RS, "Trail.runar.rs", _msg("n", "n_", "n")),
        (_RB, "Trail.runar.rb", _msg("k", "k_", "k")),
        (_MOVE, "Trail.runar.move", _msg("tmp", "tmp_", "tmp")),
        (_GO, "Trail.runar.go", _msg("K", "k", "k")),
        # Two collisions: the smallest Rúnar name wins, then its two smallest
        # spellings in ordinal order — independent of declaration order.
        (_py("        z_ = n + 1\n        z = n + 2\n        b__c = n + 3\n        b_c = n + 4\n        bC = n + 5\n        assert_(z + z_ + b__c + b_c + bC > 0)"), "Trail.runar.py", _msg("bC", "b__c", "bC")),
    ],
    ids=["py-tmp", "py-_tmp", "py-a__b", "py-loop", "rs-param", "rb-prop", "move-tmp", "go-field", "py-pair-choice"],
)
def test_f017_collision_refused(src: str, file_name: str, expected: str) -> None:
    assert _collisions(src, file_name) == [expected]


@pytest.mark.parametrize(
    "body",
    [
        "        x = n + 1\n        y = n + 2\n        assert_(x != y)",
        "        sum_ = n + 1\n        sum_ = sum_ + 1\n        assert_(sum_ == n + 2)",
        "        k = n + 1\n        assert_(k == self.k)",
    ],
    ids=["distinct", "sum_-alone", "same-spelling"],
)
def test_f017_no_collision_accepted(body: str) -> None:
    assert _collisions(_py(body), "Trail.runar.py") == []
