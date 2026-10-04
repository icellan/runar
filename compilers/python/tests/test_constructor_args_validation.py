"""constructorArgs shape validation.

Mirrors packages/runar-compiler/src/__tests__/constructor-args-validation.test.ts.

``compile_from_source(constructor_args=...)`` must reject inputs that would
silently bake nothing and emit placeholder scripts that fail opaquely at
runtime:

 (a) positional arrays (natural guess, but keys match no property names);
 (b) keys that don't match any contract property (typos);
 (c) referenced readonly properties left unbaked after applying the args.

Python is dynamically typed, so unlike Go/Rust the positional-array reject (a)
is a real, reachable case and must be checked. snake_case source identifiers
map to camelCase property names in the ANF, so keys are camelCase.
"""

from __future__ import annotations

import textwrap

import pytest

from runar_compiler.compiler import CompilationError, compile_from_source


HASH_LOCK_SOURCE = textwrap.dedent("""\
    from runar import SmartContract, ByteString, Sha256, public, assert_, sha256

    class HashLock(SmartContract):
        hash_value: Sha256

        def __init__(self, hash_value: Sha256):
            super().__init__(hash_value)
            self.hash_value = hash_value

        @public
        def unlock(self, preimage: ByteString):
            assert_(sha256(preimage) == self.hash_value)
""")

TWO_PROP_SOURCE = textwrap.dedent("""\
    from runar import SmartContract, Bigint, public, assert_

    class TwoProp(SmartContract):
        target: Bigint
        unused: Bigint

        def __init__(self, target: Bigint, unused: Bigint):
            super().__init__(target, unused)
            self.target = target
            self.unused = unused

        @public
        def check(self, x: Bigint):
            assert_(x == self.target)
""")

HASH = "aa" * 32


def _compile(tmp_path, source: str, name: str, constructor_args=None):
    path = tmp_path / name
    path.write_text(source, encoding="utf-8")
    return compile_from_source(str(path), constructor_args=constructor_args)


class TestConstructorArgsValidation:
    def test_rejects_positional_array(self, tmp_path):
        # Positional array -- the shape RunarContract/TestContract take, but NOT
        # what the compiler takes. Previously baked nothing silently.
        with pytest.raises(CompilationError, match="positional array"):
            _compile(tmp_path, HASH_LOCK_SOURCE, "HashLock.runar.py",
                     constructor_args=[HASH])

    def test_rejects_keys_matching_no_property(self, tmp_path):
        with pytest.raises(CompilationError) as exc:
            _compile(tmp_path, HASH_LOCK_SOURCE, "HashLock.runar.py",
                     constructor_args={"hashVal": HASH})  # typo: hashValue
        msg = str(exc.value)
        assert "'hashVal'" in msg
        assert "hashValue" in msg

    def test_rejects_referenced_readonly_left_unbaked(self, tmp_path):
        # 'target' is referenced by check() but not provided.
        with pytest.raises(CompilationError, match=r"'target'.*placeholder"):
            _compile(tmp_path, TWO_PROP_SOURCE, "TwoProp.runar.py",
                     constructor_args={"unused": 1})

    def test_accepts_unreferenced_readonly_left_unbaked(self, tmp_path):
        # 'unused' is never referenced by a method -- DCE eliminates it, so
        # leaving it unbaked is fine.
        artifact = _compile(tmp_path, TWO_PROP_SOURCE, "TwoProp.runar.py",
                            constructor_args={"target": 42})
        assert len(artifact.script) > 0

    def test_accepts_complete_named_record(self, tmp_path):
        artifact = _compile(tmp_path, HASH_LOCK_SOURCE, "HashLock.runar.py",
                            constructor_args={"hashValue": HASH})
        assert HASH in artifact.script
        # Fully baked -- no placeholder constructor slots.
        assert len(artifact.constructor_slots) == 0

    def test_still_compiles_placeholder_when_no_args(self, tmp_path):
        artifact = _compile(tmp_path, HASH_LOCK_SOURCE, "HashLock.runar.py")
        assert len(artifact.constructor_slots) >= 1


# F-101 -- (d) value kind / byte-width check.
#
# Before the fix ``_apply_constructor_args`` baked any value into the property:
# ``True`` against a 20-byte hash pushed OP_1, ``42`` a 1-byte number, a 6-byte
# hex string a 6-byte push -- every one compiled and is unspendable. Proves:
# each mismatch is refused with the TypeScript reference's diagnostic, naming
# the property, its declared type and the expected shape. Does NOT prove
# anything about the SDK's deploy-time constructorSlots path.

def _p2pkh(t: str) -> str:
    return (
        "class P2PKH extends SmartContract {\n"
        f"  readonly pubKeyHash: {t};\n"
        f"  constructor(pubKeyHash: {t}) {{ super(pubKeyHash); this.pubKeyHash = pubKeyHash; }}\n"
        "  public unlock(sig: Sig, pubKey: PubKey) {\n"
        "    assert(hash160(pubKey) === this.pubKeyHash);\n"
        "    assert(checkSig(sig, pubKey));\n"
        "  }\n"
        "}\n"
    )


FLAGGED_TS = (
    "class Flagged extends SmartContract {\n"
    "  readonly target: bigint;\n"
    "  readonly on: boolean;\n"
    "  constructor(target: bigint, on: boolean) { super(target, on); this.target = target; this.on = on; }\n"
    "  public check(x: bigint) { assert(this.on); assert(x === this.target); }\n"
    "}\n"
)


class TestConstructorArgValueTypeF101:
    @pytest.mark.parametrize("typ,value,want", [
        ("ByteString", True, "must be a hex string, got a boolean"),
        ("Addr", True, "must be exactly 20 bytes of hex, got a boolean"),
        ("Addr", 42, "must be exactly 20 bytes of hex, got an integer"),
        ("Addr", "aabbccddeeff", "must be exactly 20 bytes of hex, got 6 bytes of hex"),
        ("Addr", "zzzz-not-hex", "must be exactly 20 bytes of hex, got a non-hex string"),
        ("ByteString", "abc", "must be a hex string, got a non-hex string"),
        ("ByteString", 1.5, "must be a hex string, got an unsupported value"),
    ])
    def test_rejects_value_not_matching_property_type(self, tmp_path, typ, value, want):
        with pytest.raises(CompilationError) as exc:
            _compile(tmp_path, _p2pkh(typ), "P2PKH.runar.ts",
                     constructor_args={"pubKeyHash": value})
        msg = str(exc.value)
        assert f"property 'pubKeyHash' ({typ})" in msg
        assert want in msg

    def test_rejects_bigint_and_boolean_mismatches(self, tmp_path):
        with pytest.raises(CompilationError) as exc:
            _compile(tmp_path, FLAGGED_TS, "Flagged.runar.ts",
                     constructor_args={"target": "2a", "on": 1})
        msg = str(exc.value)
        assert "property 'target' (bigint) must be an integer, got 1 bytes of hex" in msg
        assert "property 'on' (boolean) must be a boolean, got an integer" in msg

    def test_bool_is_not_an_integer(self, tmp_path):
        # Python's bool subclasses int; True must not pass as a bigint.
        with pytest.raises(CompilationError, match=r"must be an integer, got a boolean"):
            _compile(tmp_path, FLAGGED_TS, "Flagged.runar.ts",
                     constructor_args={"target": True, "on": True})

    def test_accepts_correctly_typed_values(self, tmp_path):
        art = _compile(tmp_path, _p2pkh("Addr"), "P2PKH.runar.ts",
                       constructor_args={"pubKeyHash": "AB" * 20})
        assert ("ab" * 20) in art.script.lower()
        _compile(tmp_path, _p2pkh("ByteString"), "P2PKH.runar.ts",
                 constructor_args={"pubKeyHash": ""})
        _compile(tmp_path, FLAGGED_TS, "Flagged.runar.ts",
                 constructor_args={"target": 42, "on": True})
