"""F-286 — verifyRabinSig's public key must come from the contract, not the spender.

``verifyRabinSig(msg, sig, padding, n)`` checks ``(sig^2 + padding) mod n ==
SHA256(msg) mod n``. A spender who picks ``n`` forges any message (``n = 1``,
``sig = 0`` passes real Spend). Rule (user decision R78, TS reference
``checkRabinPubKeyProvenance`` in 02-validate.ts): the 4th argument must be a
contract property or a literal, followed through local aliases and through
private helpers bound to such a value at EVERY call site; anything else is
refused with one shared diagnostic.

What this proves: the Python tier's validator refuses the spender-chosen
modulus shapes below and still accepts the property / literal / alias /
helper shapes, on the TS surface and on the .runar.py surface.
What it does NOT prove: the other tiers (their own suites and
conformance/negatives N220-N228), hostile ``--ir`` JSON (it skips the
frontend), or anything about the strength of a key the deployer bakes.
"""
from __future__ import annotations

import pytest

from runar_compiler.frontend.parser_dispatch import parse_source
from runar_compiler.frontend.validator import validate

MSG = (
    "verifyRabinSig public key (4th argument) must be a contract property or a literal; "
    "a spender-supplied Rabin modulus lets anyone forge a signature"
)

_HELPER = """
  private check(m: ByteString, s: RabinSig, p: ByteString, k: RabinPubKey): boolean {
    return verifyRabinSig(m, s, p, k);
  }"""

_CHAIN = """
  private outer(m: ByteString, s: RabinSig, p: ByteString, k: RabinPubKey): boolean {
    const kk = k;
    return this.inner(m, s, p, kk);
  }
  private inner(m: ByteString, s: RabinSig, p: ByteString, k: RabinPubKey): boolean {
    return verifyRabinSig(m, s, p, k);
  }"""


def _ts(body: str, extra_params: str = "", extra_methods: str = "") -> str:
    return (
        "import { SmartContract, assert, ByteString, RabinSig, RabinPubKey, verifyRabinSig } from 'runar-lang';\n"
        "class C extends SmartContract {\n"
        "  readonly pk: RabinPubKey;\n"
        "  readonly pk2: RabinPubKey;\n"
        "  constructor(pk: RabinPubKey, pk2: RabinPubKey) {\n"
        "    super(pk, pk2);\n"
        "    this.pk = pk;\n"
        "    this.pk2 = pk2;\n"
        "  }\n"
        f"  public settle(msg: ByteString, sig: RabinSig, padding: ByteString{extra_params}) {{\n"
        f"{body}\n"
        "  }\n"
        f"{extra_methods}\n"
        "}\n"
    )


def _errors(source: str, file_name: str = "C.runar.ts") -> list[str]:
    result = parse_source(source, file_name)
    assert result.contract is not None, [e.message for e in result.errors]
    return [d.message for d in validate(result.contract).errors]


REFUSED = {
    "public method parameter": _ts("    assert(verifyRabinSig(msg, sig, padding, n));", ", n: RabinPubKey"),
    "const alias of a parameter": _ts(
        "    const k = n;\n    assert(verifyRabinSig(msg, sig, padding, k));", ", n: RabinPubKey"
    ),
    "let alias from a property, reassigned from a parameter": _ts(
        "    let k = this.pk;\n    k = n;\n    assert(verifyRabinSig(msg, sig, padding, k));", ", n: RabinPubKey"
    ),
    "private helper bound to a public parameter": _ts(
        "    assert(this.check(msg, sig, padding, n));", ", n: RabinPubKey", _HELPER
    ),
    "private helper bound to a property at one site and a parameter at another": _ts(
        "    assert(this.check(msg, sig, padding, this.pk));\n    assert(this.check(msg, sig, padding, n));",
        ", n: RabinPubKey",
        _HELPER,
    ),
    "ternary between a property and a parameter": _ts(
        "    assert(verifyRabinSig(msg, sig, padding, sig > 0n ? this.pk : n));", ", n: RabinPubKey"
    ),
    "computed from a property": _ts("    assert(verifyRabinSig(msg, sig, padding, this.pk + 1n));"),
    "parameter inside a for loop nested in an if": _ts(
        "    if (sig > 0n) {\n      for (let i = 0n; i < 2n; i++) {\n"
        "        assert(verifyRabinSig(msg, sig, padding, n));\n      }\n    }\n    assert(true);",
        ", n: RabinPubKey",
    ),
}

ACCEPTED = {
    "this.<prop>": _ts("    assert(verifyRabinSig(msg, sig, padding, this.pk));"),
    "bigint literal": _ts("    assert(verifyRabinSig(msg, sig, padding, 1000003n));"),
    "const alias of a property": _ts("    const k = this.pk;\n    assert(verifyRabinSig(msg, sig, padding, k));"),
    "let alias reassigned only from properties": _ts(
        "    let k = this.pk;\n    if (sig > 0n) { k = this.pk2; }\n    assert(verifyRabinSig(msg, sig, padding, k));"
    ),
    "private helper bound to a property at every call site": _ts(
        "    assert(this.check(msg, sig, padding, this.pk));\n    assert(this.check(msg, sig, padding, this.pk2));",
        "",
        _HELPER,
    ),
    "two-level private helper chain rooted in a property": _ts(
        "    assert(this.outer(msg, sig, padding, this.pk));", "", _CHAIN
    ),
}


@pytest.mark.parametrize("label", sorted(REFUSED))
def test_refused(label: str) -> None:
    assert MSG in _errors(REFUSED[label])


@pytest.mark.parametrize("label", sorted(ACCEPTED))
def test_accepted(label: str) -> None:
    assert _errors(ACCEPTED[label]) == []


def _py(extra_param: str, key: str) -> str:
    return (
        "from runar import SmartContract, ByteString, RabinSig, RabinPubKey, public, assert_, verify_rabin_sig\n"
        "\n"
        "class C(SmartContract):\n"
        "    pk: RabinPubKey\n"
        "\n"
        "    def __init__(self, pk: RabinPubKey):\n"
        "        super().__init__(pk)\n"
        "        self.pk = pk\n"
        "\n"
        "    @public\n"
        f"    def settle(self, msg: ByteString, sig: RabinSig, padding: ByteString{extra_param}):\n"
        f"        k = {key}\n"
        "        assert_(verify_rabin_sig(msg, sig, padding, k))\n"
    )


def test_python_surface_property_alias_accepted() -> None:
    assert _errors(_py("", "self.pk"), "C.runar.py") == []


def test_python_surface_parameter_alias_refused() -> None:
    assert MSG in _errors(_py(", n: RabinPubKey", "n"), "C.runar.py")
