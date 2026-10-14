"""N-093 -- the Python-surface spellings of the ``@embedAlways`` and
``@sighash`` compiler directives must also run natively.

What this proves: ``EmbedAlways[T]`` is an importable, subscriptable marker
(alone and composed with ``Readonly`` in either order), and ``public`` works
both bare (``@public``) and with the keyword (``@public(sighash="...")``),
returning the decorated function itself in both forms, so a contract that uses
either spelling imports, constructs and runs as plain Python.

What it does NOT prove: anything about compilation (the compiler tiers read
these spellings from source; see compilers/*/tests for N-093).
"""

import runar
from runar import EmbedAlways, Readonly, SmartContract, public


class TestEmbedAlways:
    def test_exported(self):
        assert 'EmbedAlways' in runar.__all__
        assert runar.EmbedAlways is EmbedAlways

    def test_subscriptable(self):
        assert EmbedAlways[bytes] is not None

    def test_composes_with_readonly_either_order(self):
        assert Readonly[EmbedAlways[bytes]] is not None
        assert EmbedAlways[Readonly[bytes]] is not None


class TestPublicDecorator:
    def test_bare_returns_function_unchanged(self):
        def f(x):
            return x + 1

        assert public(f) is f
        assert f._runar_public is True
        assert f(1) == 2

    def test_keyword_returns_function_unchanged(self):
        def f(x):
            return x + 1

        assert public(sighash="SINGLE|FORKID")(f) is f
        assert f._runar_public is True
        assert f(1) == 2

    def test_contract_with_both_spellings_runs(self):
        class C(SmartContract):
            tag: EmbedAlways[bytes]

            def __init__(self, tag: bytes):
                super().__init__(tag)
                self.tag = tag

            @public
            def a(self) -> bytes:
                return self.tag

            @public(sighash="SINGLE|FORKID")
            def b(self) -> bytes:
                return self.tag

        c = C(b"\x01")
        assert c.a() == b"\x01"
        assert c.b() == b"\x01"
        assert C.a._runar_public is True
        assert C.b._runar_public is True
