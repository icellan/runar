//! F-017 — two distinct source identifiers that a surface's name conversion
//! maps to ONE Rúnar name are refused with one shared diagnostic.
//!
//! Before the rule, `tmp = n + 1; tmp_ = n + 2; assert_(tmp == tmp_)` in a
//! .runar.py contract (always false under Python semantics) bound both
//! spellings to one variable and compiled to `OP_DUP OP_DUP OP_NUMEQUAL`: an
//! always-TRUE guard.
//!
//! What this proves: the Rust tier's frontend refuses a collision on each of
//! the five renaming surfaces (.py/.rs/.rb/.move/.go) with exactly the text the
//! TS reference emits, picks the same pair regardless of declaration order,
//! and does not refuse `sum_` on its own or a local that reuses a property's
//! exact spelling.
//! What it does NOT prove: anything about the other tiers (their own suites
//! and conformance/negatives/N46-N50 cover that), or the semantics of a local
//! that shadows a property under the same spelling (N-016, a separate item).

use runar_compiler_rust::frontend::parser::parse_source;

fn msg(a: &str, b: &str, name: &str) -> String {
    format!("identifier collision: '{}' and '{}' both convert to '{}'; rename one of them", a, b, name)
}

fn py(body: &str) -> String {
    format!(
        "from runar import SmartContract, Bigint, public, assert_\n\n\nclass Trail(SmartContract):\n    k: Bigint\n\n    def __init__(self, k: Bigint):\n        super().__init__(k)\n        self.k = k\n\n    @public\n    def unlock(self, n: Bigint):\n{}\n",
        body
    )
}

const RS: &str = "use runar::prelude::*;\n\n#[runar::contract]\nstruct Trail {\n    #[readonly]\n    k: Int,\n}\n\nimpl Trail {\n    pub fn unlock(&self, n: Int) {\n        let n_ = n + 1;\n        assert!(n_ == n);\n    }\n}\n";

const RB: &str = "require 'runar'\n\nclass Trail < Runar::SmartContract\n  prop :k, Bigint\n\n  def initialize(k)\n    super(k)\n    @k = k\n  end\n\n  runar_public n: Bigint\n  def unlock(n)\n    k_ = n + 1\n    assert k_ == @k\n  end\nend\n";

const MOVE: &str = "module Trail {\n    use runar::types::{Int};\n\n    struct Trail {\n        k: Int,\n    }\n\n    public fun unlock(contract: &Trail, n: Int) {\n        let tmp = n + 1;\n        let tmp_ = n + 2;\n        assert!(tmp == tmp_, 0);\n    }\n}\n";

const GO: &str = "package contract\n\nimport runar \"github.com/icellan/runar/packages/runar-go\"\n\ntype Trail struct {\n\trunar.SmartContract\n\tK runar.Int `runar:\"readonly\"`\n}\n\nfunc (c *Trail) Unlock(n runar.Int) {\n\tk := n + 1\n\trunar.Assert(k == c.K)\n}\n";

fn collisions(src: &str, file: &str) -> Vec<String> {
    parse_source(src, Some(file))
        .errors
        .into_iter()
        .map(|d| d.message)
        .filter(|m| m.starts_with("identifier collision"))
        .collect()
}

#[test]
fn f017_collision_is_refused_on_every_renaming_surface() {
    let cases: Vec<(String, &str, String)> = vec![
        (py("        tmp = n + 1\n        tmp_ = n + 2\n        assert_(tmp == tmp_)"), "Trail.runar.py", msg("tmp", "tmp_", "tmp")),
        (py("        _tmp = n + 1\n        tmp = n + 2\n        assert_(_tmp == tmp)"), "Trail.runar.py", msg("_tmp", "tmp", "tmp")),
        (py("        a__b = n + 1\n        a_b = n + 2\n        assert_(a__b == a_b)"), "Trail.runar.py", msg("a__b", "a_b", "aB")),
        (py("        acc = n\n        for i_ in range(3):\n            acc = acc + 1\n        i = acc\n        assert_(i == n + 3)"), "Trail.runar.py", msg("i", "i_", "i")),
        (RS.to_string(), "Trail.runar.rs", msg("n", "n_", "n")),
        (RB.to_string(), "Trail.runar.rb", msg("k", "k_", "k")),
        (MOVE.to_string(), "Trail.runar.move", msg("tmp", "tmp_", "tmp")),
        (GO.to_string(), "Trail.runar.go", msg("K", "k", "k")),
        // Two collisions: the smallest Rúnar name wins, then its two smallest
        // spellings in byte order — independent of declaration order.
        (py("        z_ = n + 1\n        z = n + 2\n        b__c = n + 3\n        b_c = n + 4\n        bC = n + 5\n        assert_(z + z_ + b__c + b_c + bC > 0)"), "Trail.runar.py", msg("bC", "b__c", "bC")),
    ];
    for (src, file, want) in cases {
        assert_eq!(collisions(&src, file), vec![want.clone()], "{} should be refused with {}", file, want);
    }
}

#[test]
fn f017_non_colliding_names_are_accepted() {
    for body in [
        "        x = n + 1\n        y = n + 2\n        assert_(x != y)",
        "        sum_ = n + 1\n        sum_ = sum_ + 1\n        assert_(sum_ == n + 2)",
        "        k = n + 1\n        assert_(k == self.k)",
    ] {
        assert!(collisions(&py(body), "Trail.runar.py").is_empty(), "unexpected collision for {:?}", body);
    }
}
