"""F-016 — which class in a ``.runar.ts`` file is the contract.

The TS reference (``packages/runar-compiler/src/passes/01-parse.ts``) walks
EVERY class in the file and keeps only one whose ``extends`` names a valid base
(``SmartContract`` / ``StatefulSmartContract`` / ``UnsafeSmartContract``):

* classes with no ``extends`` or another base are ignored, wherever they sit;
* several valid classes -> one ``Only one SmartContract subclass is allowed per
  file`` error at each valid class after the first (the LAST one is kept);
* no valid class -> ``No class extending SmartContract, StatefulSmartContract,
  or UnsafeSmartContract found`` at 1:0 and no contract.

Python's ``parser_ts.py`` returned on the FIRST ``class`` token and defaulted a
missing ``extends`` to ``SmartContract``. A leading helper class was therefore
compiled as the contract with zero diagnostics: in ``DECOY_FIRST`` below the
helper's ``unlock`` accepts every preimage EXCEPT the real one, while the real
``HashLock`` accepts only the hash preimage. The real-engine proof that the pre-fix Python artifact
accepts such a spend is
``packages/runar-testing/src/__tests__/f016-python-ts-class-selection-vm.test.ts``.

Every expected value here was captured by running the TS reference compiler
on the same shape (see remediation-logs/F-016/ts-reference-shapes.txt), not by
reading its code.

What this proves: Python's .runar.ts parser picks the same class, the same
parent class and the same error diagnostics (message + location) as the TS
reference for helper-first, foreign-base-first, contract-first, two-valid,
three-valid, no-extends-only and foreign-base-only files; and DECOY_FIRST
compiles to the TS reference's bytes. What it does NOT prove: anything about
the other .runar.* surfaces or the other six tiers' parsers.
"""

from __future__ import annotations

from runar_compiler.compiler import compile_from_source
from runar_compiler.frontend.parser_dispatch import parse_source

NO_CLASS = (
    "No class extending SmartContract, StatefulSmartContract, "
    "or UnsafeSmartContract found"
)
ONLY_ONE = "Only one SmartContract subclass is allowed per file"

HASHLOCK = """\
export class HashLock extends SmartContract {
  readonly hashValue: Sha256;

  constructor(hashValue: Sha256) {
    super(hashValue);
    this.hashValue = hashValue;
  }

  public unlock(preimage: ByteString) {
    assert(sha256(preimage) === this.hashValue);
  }
}
"""

# Same ABI as HashLock, but ``unlock`` accepts any preimage except the real one.
DECOY = """\
class Helper {
  readonly hashValue: Sha256;

  constructor(hashValue: Sha256) {
    super(hashValue);
    this.hashValue = hashValue;
  }

  public unlock(preimage: ByteString) {
    assert(sha256(preimage) !== this.hashValue);
  }
}
"""

IMPORTS = "import { SmartContract, assert, ByteString, Sha256, sha256 } from 'runar-lang';\n\n"

DECOY_FIRST = IMPORTS + DECOY + "\n" + HASHLOCK
FOREIGN_BASE_FIRST = IMPORTS + DECOY.replace("class Helper {", "class Helper extends Base {") + "\n" + HASHLOCK
CONTRACT_FIRST = IMPORTS + HASHLOCK + "\n" + DECOY
NO_EXTENDS_ONLY = IMPORTS + DECOY
FOREIGN_BASE_ONLY = IMPORTS + DECOY.replace("class Helper {", "class Helper extends Base {")

TWO_VALID = IMPORTS + """\
export class First extends SmartContract {
  constructor() {
    super();
  }

  public unlock(preimage: ByteString) {
    assert(true);
  }
}

""" + HASHLOCK

THREE_VALID = """\
import { SmartContract, assert } from 'runar-lang';

export class A extends SmartContract {
  constructor() { super(); }
  public unlock(x: bigint) { assert(x === 1n); }
}
export class B extends SmartContract {
  constructor() { super(); }
  public unlock(x: bigint) { assert(x === 2n); }
}
export class C extends SmartContract {
  constructor() { super(); }
  public unlock(x: bigint) { assert(x === 3n); }
}
"""


def _parse(src: str):
    return parse_source(src, "Probe.runar.ts")


def _errors(result) -> list[tuple[str, int, int]]:
    return [
        (e.message, e.loc.line if e.loc else None, e.loc.column if e.loc else None)
        for e in result.errors
    ]


class TestTsContractClassSelection:
    def test_helper_first_selects_the_extending_class(self):
        r = _parse(DECOY_FIRST)
        assert r.errors == [], r.error_strings()
        assert r.contract is not None
        assert r.contract.name == "HashLock"
        assert r.contract.parent_class == "SmartContract"

    def test_foreign_base_first_selects_the_extending_class(self):
        r = _parse(FOREIGN_BASE_FIRST)
        assert r.errors == [], r.error_strings()
        assert r.contract is not None
        assert r.contract.name == "HashLock"

    def test_contract_first_then_helper(self):
        r = _parse(CONTRACT_FIRST)
        assert r.errors == [], r.error_strings()
        assert r.contract is not None
        assert r.contract.name == "HashLock"

    def test_two_valid_classes_is_an_error_and_keeps_the_last(self):
        r = _parse(TWO_VALID)
        assert r.contract is not None
        assert r.contract.name == "HashLock"
        assert _errors(r) == [(ONLY_ONE, 13, 0)]

    def test_three_valid_classes_errors_on_each_extra(self):
        r = _parse(THREE_VALID)
        assert r.contract is not None
        assert r.contract.name == "C"
        assert _errors(r) == [(ONLY_ONE, 7, 0), (ONLY_ONE, 11, 0)]

    def test_class_without_extends_alone_is_refused(self):
        r = _parse(NO_EXTENDS_ONLY)
        assert r.contract is None
        assert _errors(r) == [(NO_CLASS, 1, 0)]

    def test_class_with_foreign_base_alone_is_refused(self):
        r = _parse(FOREIGN_BASE_ONLY)
        assert r.contract is None
        assert _errors(r) == [(NO_CLASS, 1, 0)]

    def test_decoy_first_compiles_to_the_reference_bytes(self, tmp_path):
        # TS reference: `OP_SHA256 <hashValue placeholder> OP_EQUAL`
        # (constructor arg unbaked -> OP_0 placeholder). The decoy compiles to
        # `OP_SHA256 <placeholder> OP_EQUAL OP_NOT` (the inverted lock).
        path = tmp_path / "Probe.runar.ts"
        path.write_text(DECOY_FIRST, encoding="utf-8")
        artifact = compile_from_source(str(path))
        assert artifact.contract_name == "HashLock"
        assert artifact.script == "a80087"
