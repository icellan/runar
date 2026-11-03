"""N-205 (a) — a stateful method must not write a spender-supplied value into a
MUTABLE property that verifyRabinSig uses as its public key.

A mutable key property is state the previous spend chose: ``this.key =
newKey`` (or ``newKey`` in the key's ``addOutput`` slot) lets a spender set the
next UTXO's modulus to 1 and forge any message one spend later. Rule (user
decision R80, TS reference: the N-205 block of ``checkRabinPubKeyProvenance``
in 02-validate.ts): KEY properties are those reaching a verifyRabinSig 4th
argument, closed under "written into a key property"; outside the constructor
a mutable key property may only be written (assignment, compound assignment,
++/--, addOutput slot) with a value F-286 trusts.

What this proves: the Python tier's validator refuses the write shapes below
and accepts literal / property writes, non-key writes and the key in its own
addOutput slot, on the TS, .runar.py and bare-name .runar.sol surfaces.
What it does NOT prove: the other tiers, the ``--ir`` path
(test_n205_ir_rabin_key_provenance.py and
conformance/negatives/ir-rabin-key-provenance.test.ts), or a spender-supplied
``addRawOutput`` script (which forges any state, not just the key).
"""
from __future__ import annotations

import pytest

from runar_compiler.frontend.parser_dispatch import parse_source
from runar_compiler.frontend.validator import validate


def msg(prop: str) -> str:
    return (
        f"verifyRabinSig public key property '{prop}' may only be assigned a contract property or a literal "
        "outside the constructor; a spender-supplied Rabin modulus lets anyone forge a signature"
    )


_SETTER = """
  private setKey(v: RabinPubKey): void {
    this.key = v;
  }"""

_CHECK = """
  private check(m: ByteString, s: RabinSig, p: ByteString, k: RabinPubKey): boolean {
    return verifyRabinSig(m, s, p, k);
  }"""


def _ts(rotate_body: str, extra_methods: str = "",
        settle_check: str = "verifyRabinSig(msg, sig, padding, this.key)") -> str:
    return (
        "import { StatefulSmartContract, assert, ByteString, RabinSig, RabinPubKey, verifyRabinSig } from 'runar-lang';\n"
        "class C extends StatefulSmartContract {\n"
        "  key: RabinPubKey;\n"
        "  other: RabinPubKey;\n"
        "  count: bigint;\n"
        "  readonly backup: RabinPubKey;\n"
        "  constructor(key: RabinPubKey, other: RabinPubKey, count: bigint, backup: RabinPubKey) {\n"
        "    super(key, other, count, backup);\n"
        "    this.key = key;\n"
        "    this.other = other;\n"
        "    this.count = count;\n"
        "    this.backup = backup;\n"
        "  }\n"
        "  public settle(msg: ByteString, sig: RabinSig, padding: ByteString) {\n"
        f"    assert({settle_check});\n"
        "  }\n"
        "  public rotate(newKey: RabinPubKey, n: bigint) {\n"
        f"{rotate_body}\n"
        "    assert(true);\n"
        "  }\n"
        f"{extra_methods}\n"
        "}\n"
    )


def _errors(source: str, file_name: str = "C.runar.ts") -> list[str]:
    result = parse_source(source, file_name)
    assert result.contract is not None, [e.message for e in result.errors]
    return [d.message for d in validate(result.contract).errors]


REFUSED = {
    "assigned a public parameter": (_ts("    this.key = newKey;"), "key"),
    "assigned a const alias of a parameter": (_ts("    const k = newKey;\n    this.key = k;"), "key"),
    "compound assignment from a parameter": (_ts("    this.key += n;"), "key"),
    "incremented": (_ts("    this.key++;"), "key"),
    "assigned inside an if": (_ts("    if (n > 0n) {\n      this.key = newKey;\n    }"), "key"),
    "passed a parameter in its addOutput slot": (
        _ts("    this.addOutput(1000n, newKey, this.other, this.count);"), "key"),
    "written by a private setter fed a parameter": (_ts("    this.setKey(newKey);", _SETTER), "key"),
    "key reached through a private helper, then written from a parameter": (
        _ts("    this.key = newKey;", _CHECK, "this.check(msg, sig, padding, this.key)"), "key"),
    "a property that feeds the key is itself written from a parameter": (
        _ts("    this.key = this.other;\n    this.other = newKey;"), "other"),
}

ACCEPTED = {
    "assigned a bigint literal": _ts("    this.key = 1000003n;"),
    "assigned a readonly property": _ts("    this.key = this.backup;"),
    "assigned another property only written from literals": _ts("    this.key = this.other;\n    this.other = 7n;"),
    "non-key state written from a parameter": _ts("    this.count = this.count + n;"),
    "non-Rabin mutable property written from a parameter": _ts("    this.other = newKey;"),
    "the key in its own addOutput slot": _ts("    this.addOutput(1000n, this.key, this.other, n);"),
    "written by a private setter fed a property at every call site": _ts("    this.setKey(this.backup);", _SETTER),
}


@pytest.mark.parametrize("label", sorted(REFUSED))
def test_refused(label: str) -> None:
    src, prop = REFUSED[label]
    assert msg(prop) in _errors(src)


@pytest.mark.parametrize("label", sorted(ACCEPTED))
def test_accepted(label: str) -> None:
    assert _errors(ACCEPTED[label]) == []


def _py(value: str) -> str:
    return (
        "from runar import StatefulSmartContract, ByteString, RabinSig, RabinPubKey, public, assert_, verify_rabin_sig\n"
        "\n"
        "class C(StatefulSmartContract):\n"
        "    key: RabinPubKey\n"
        "\n"
        "    def __init__(self, key: RabinPubKey):\n"
        "        super().__init__(key)\n"
        "        self.key = key\n"
        "\n"
        "    @public\n"
        "    def settle(self, msg: ByteString, sig: RabinSig, padding: ByteString):\n"
        "        assert_(verify_rabin_sig(msg, sig, padding, self.key))\n"
        "\n"
        "    @public\n"
        "    def rotate(self, new_key: RabinPubKey):\n"
        f"        self.key = {value}\n"
        "        assert_(True)\n"
    )


def _sol_bare(value: str) -> str:
    return (
        "pragma runar ^0.1.0;\n"
        "contract C is StatefulSmartContract {\n"
        "    RabinPubKey key;\n"
        "    constructor(RabinPubKey _key) { key = _key; }\n"
        "    function settle(bytes msg, RabinSig sig, bytes padding) public {\n"
        "        require(verifyRabinSig(msg, sig, padding, this.key));\n"
        "    }\n"
        "    function rotate(RabinPubKey newKey) public {\n"
        f"        key = {value};\n"
        "        require(true);\n"
        "    }\n"
        "}\n"
    )


def test_python_surface_literal_write_accepted() -> None:
    assert _errors(_py("1000003"), "C.runar.py") == []


def test_python_surface_parameter_write_refused() -> None:
    assert msg("key") in _errors(_py("new_key"), "C.runar.py")


def test_sol_bare_name_literal_write_accepted() -> None:
    assert _errors(_sol_bare("1000003"), "C.runar.sol") == []


def test_sol_bare_name_parameter_write_refused() -> None:
    assert msg("key") in _errors(_sol_bare("newKey"), "C.runar.sol")
