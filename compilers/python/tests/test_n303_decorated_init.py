"""N-303 — a decorated ``def __init__`` in .runar.py is the constructor.

The TS reference (``parseMethodDef`` in 01-parse-python.ts) decides "this is
the constructor" from the method NAME alone, whatever decorators precede it:
``@public def __init__`` and ``@foo def __init__`` both yield the ordinary
constructor and add no method. Before the fix this tier sent every decorated
``def`` down the method path, so the constructor became a method named
``constructor`` (a public one, for ``@public``) next to an auto-generated
constructor, and compilation failed on the duplicated assignment.

What this proves: the Python tier's frontend produces the same AST shape as
the undecorated control for a decorated ``__init__`` (one constructor with the
declared params, only ``unlock`` in the method list, no errors).
What it does NOT prove: the other tiers (their own suites / the matrix in the
N-303 log), or the compiled hex.
"""
from __future__ import annotations

import pytest

from runar_compiler.frontend.parser_dispatch import parse_source


def _py(decorator: str) -> str:
    return (
        "from runar import SmartContract, Addr, Sig, PubKey, public, assert_, hash160, check_sig\n\n"
        "class P2PKH(SmartContract):\n"
        "    pub_key_hash: Addr\n\n"
        f"{decorator}"
        "    def __init__(self, pub_key_hash: Addr):\n"
        "        super().__init__(pub_key_hash)\n"
        "        self.pub_key_hash = pub_key_hash\n\n"
        "    @public\n"
        "    def unlock(self, sig: Sig, pub_key: PubKey):\n"
        "        assert_(hash160(pub_key) == self.pub_key_hash)\n"
        "        assert_(check_sig(sig, pub_key))\n"
    )


@pytest.mark.parametrize(
    "label,decorator",
    [("undecorated", ""), ("@public", "    @public\n"), ("@foo", "    @foo\n")],
    ids=["undecorated", "public", "foo"],
)
def test_n303_decorated_init_is_the_constructor(label, decorator):
    r = parse_source(_py(decorator), "P2PKH.runar.py")
    assert [e.message for e in r.errors] == [], label
    assert [m.name for m in r.contract.methods] == ["unlock"], label
    assert r.contract.constructor.name == "constructor", label
    assert [p.name for p in r.contract.constructor.params] == ["pubKeyHash"], label
