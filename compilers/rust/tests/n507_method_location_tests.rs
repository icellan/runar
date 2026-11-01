//! N-507 -- every Rust surface parser records a method's (and an explicit
//! constructor's) `source_location` where the method STARTS, as the TS
//! reference does, not at the token after its body.
//!
//! The source for each surface is the `multi-method` conformance example
//! (a constructor, a private helper and two public methods, each followed by
//! another member), and the expected positions are what the TS parser reports
//! for the same file (`parse()` in 01-parse.ts). The AST stores a 1-based
//! column while TS stores a 0-based one, so the comparison is on `column - 1`.
//!
//! Proves: per surface, the line:col of the constructor and every method equals
//! the TS reference's. Does not prove: expression/statement positions, any
//! diagnostic wording, or surfaces beyond the seven below (`.runar.ts` and
//! `.runar.zig` are covered elsewhere; N-500 covers Zig). Constructors that a
//! surface synthesizes (Go, Rust, Java) are compared as well, so a change to
//! where they are anchored would show here.

use runar_compiler_rust::frontend::parser::parse_source;

fn locations(source: &str, file: &str) -> Vec<(String, usize, usize)> {
    let result = parse_source(source, Some(file));
    assert!(result.errors.is_empty(), "{file}: unexpected errors: {:?}", result.error_strings());
    let contract = result.contract.expect("contract");
    std::iter::once(&contract.constructor)
        .chain(contract.methods.iter())
        .map(|m| {
            (
                m.name.clone(),
                m.source_location.line as usize,
                (m.source_location.column as usize).saturating_sub(1),
            )
        })
        .collect()
}

fn check(source: &str, file: &str, want: &[(&str, usize, usize)]) {
    let want: Vec<(String, usize, usize)> =
        want.iter().map(|(n, l, c)| (n.to_string(), *l, *c)).collect();
    assert_eq!(locations(source, file), want, "{file}");
}

const SOL: &str = r#"pragma runar ^0.1.0;

contract MultiMethod is SmartContract {
    PubKey immutable owner;
    PubKey immutable backup;

    constructor(PubKey _owner, PubKey _backup) {
        owner = _owner;
        backup = _backup;
    }

    function computeThreshold(int a, int b) private returns (int) {
        return a * b + 1;
    }

    function spendWithOwner(Sig sig, int amount) public {
        int threshold = this.computeThreshold(amount, 2);
        require(threshold > 10);
        require(checkSig(sig, owner));
    }

    function spendWithBackup(Sig sig) public {
        require(checkSig(sig, backup));
    }
}
"#;

#[test]
fn sol_method_locations_are_method_start() {
    check(SOL, "MultiMethod.runar.sol", &[("constructor", 7, 4), ("computeThreshold", 12, 4), ("spendWithOwner", 16, 4), ("spendWithBackup", 22, 4)]);
}

const MOVE: &str = r#"module MultiMethod {
    use runar::types::{PubKey, Sig, Int};
    use runar::crypto::{check_sig};

    struct MultiMethod {
        owner: PubKey,
        backup: PubKey,
    }

    fun compute_threshold(a: Int, b: Int): Int {
        a * b + 1
    }

    public fun spend_with_owner(contract: &MultiMethod, sig: Sig, amount: Int) {
        let threshold = compute_threshold(amount, 2);
        assert!(threshold > 10, 0);
        assert!(check_sig(sig, contract.owner), 0);
    }

    public fun spend_with_backup(contract: &MultiMethod, sig: Sig) {
        assert!(check_sig(sig, contract.backup), 0);
    }
}
"#;

#[test]
fn move_method_locations_are_method_start() {
    check(MOVE, "MultiMethod.runar.move", &[("constructor", 5, 4), ("computeThreshold", 10, 4), ("spendWithOwner", 14, 4), ("spendWithBackup", 20, 4)]);
}

const PY: &str = r#"from runar import SmartContract, PubKey, Sig, Bigint, public, assert_, check_sig

class MultiMethod(SmartContract):
    owner: PubKey
    backup: PubKey

    def __init__(self, owner: PubKey, backup: PubKey):
        super().__init__(owner, backup)
        self.owner = owner
        self.backup = backup

    def _compute_threshold(self, a: Bigint, b: Bigint) -> Bigint:
        return a * b + 1

    @public
    def spend_with_owner(self, sig: Sig, amount: Bigint):
        threshold: Bigint = self._compute_threshold(amount, 2)
        assert_(threshold > 10)
        assert_(check_sig(sig, self.owner))

    @public
    def spend_with_backup(self, sig: Sig):
        assert_(check_sig(sig, self.backup))
"#;

#[test]
fn py_method_locations_are_method_start() {
    check(PY, "MultiMethod.runar.py", &[("constructor", 7, 4), ("computeThreshold", 12, 4), ("spendWithOwner", 16, 4), ("spendWithBackup", 22, 4)]);
}

const RB: &str = r#"require 'runar'

class MultiMethod < Runar::SmartContract
  prop :owner, PubKey
  prop :backup, PubKey

  def initialize(owner, backup)
    super(owner, backup)
    @owner = owner
    @backup = backup
  end

  params a: Bigint, b: Bigint
  def compute_threshold(a, b)
    return a * b + 1
  end

  runar_public sig: Sig, amount: Bigint
  def spend_with_owner(sig, amount)
    threshold = compute_threshold(amount, 2)
    assert threshold > 10
    assert check_sig(sig, @owner)
  end

  runar_public sig: Sig
  def spend_with_backup(sig)
    assert check_sig(sig, @backup)
  end
end
"#;

#[test]
fn rb_method_locations_are_method_start() {
    check(RB, "MultiMethod.runar.rb", &[("constructor", 7, 2), ("computeThreshold", 14, 2), ("spendWithOwner", 19, 2), ("spendWithBackup", 26, 2)]);
}

const RS: &str = r#"use runar::prelude::*;

#[runar::contract]
pub struct MultiMethod {
    #[readonly]
    pub owner: PubKey,
    #[readonly]
    pub backup: PubKey,
}

impl MultiMethod {
    fn compute_threshold(&self, a: Int, b: Int) -> Int {
        a * b + 1
    }

    pub fn spend_with_owner(&self, sig: Sig, amount: Int) {
        let threshold = self.compute_threshold(amount, 2);
        assert!(threshold > 10);
        assert!(check_sig(&sig, &self.owner));
    }

    pub fn spend_with_backup(&self, sig: Sig) {
        assert!(check_sig(&sig, &self.backup));
    }
}
"#;

#[test]
fn rs_method_locations_are_method_start() {
    check(RS, "MultiMethod.runar.rs", &[("constructor", 4, 4), ("computeThreshold", 12, 4), ("spendWithOwner", 16, 8), ("spendWithBackup", 22, 8)]);
}

const GO: &str = r#"package contract

import runar "github.com/icellan/runar/packages/runar-go"

type MultiMethod struct {
	runar.SmartContract
	Owner  runar.PubKey `runar:"readonly"`
	Backup runar.PubKey `runar:"readonly"`
}

func (c *MultiMethod) computeThreshold(a runar.Int, b runar.Int) runar.Int {
	return a*b + 1
}

func (c *MultiMethod) SpendWithOwner(sig runar.Sig, amount runar.Int) {
	threshold := c.computeThreshold(amount, 2)
	runar.Assert(threshold > 10)
	runar.Assert(runar.CheckSig(sig, c.Owner))
}

func (c *MultiMethod) SpendWithBackup(sig runar.Sig) {
	runar.Assert(runar.CheckSig(sig, c.Backup))
}
"#;

#[test]
fn go_method_locations_are_method_start() {
    check(GO, "MultiMethod.runar.go", &[("constructor", 5, 17), ("computeThreshold", 11, 0), ("spendWithOwner", 15, 0), ("spendWithBackup", 21, 0)]);
}

const JAVA: &str = r#"package runar.examples.multimethod;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.Bigint;
import runar.lang.types.PubKey;
import runar.lang.types.Sig;

import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.checkSig;

/**
 * MultiMethod -- exercises multiple public methods plus a {@code private}
 * helper that gets inlined by the compiler. Demonstrates owner/backup
 * dual spending paths, each gated by a different signature.
 */
class MultiMethod extends SmartContract {

    @Readonly PubKey owner;
    @Readonly PubKey backup;

    MultiMethod(PubKey owner, PubKey backup) {
        super(owner, backup);
        this.owner = owner;
        this.backup = backup;
    }

    private Bigint computeThreshold(Bigint a, Bigint b) {
        return a.times(b).plus(Bigint.ONE);
    }

    @Public
    void spendWithOwner(Sig sig, Bigint amount) {
        Bigint threshold = this.computeThreshold(amount, Bigint.TWO);
        assertThat(threshold.gt(Bigint.of(10)));
        assertThat(checkSig(sig, this.owner));
    }

    @Public
    void spendWithBackup(Sig sig) {
        assertThat(checkSig(sig, this.backup));
    }
}
"#;

#[test]
fn java_method_locations_are_method_start() {
    check(JAVA, "MultiMethod.runar.java", &[("constructor", 23, 4), ("computeThreshold", 29, 4), ("spendWithOwner", 33, 4), ("spendWithBackup", 40, 4)]);
}
