"""N-321: typecheck diagnostics must not echo an unbounded type text.

Proves: a 1 MB flat type name yields typecheck diagnostics capped at 1024
characters plus the ``...(N more bytes elided)`` marker, and an ordinary type
is echoed verbatim. Does NOT prove: the other tiers
(conformance/negatives/n321-diagnostic-type-echo-parity.test.ts) nor each echo
site individually (the cap sits at the diagnostic sink).
"""

from __future__ import annotations

import re

from runar_compiler.compiler import compile_from_source_str_with_result

HEAD = "import { SmartContract, assert } from 'runar-lang';\nclass P extends SmartContract {\n readonly t: bigint;\n constructor(t: bigint) { super(t); this.t = t; }\n public verify(a: bigint) {\n let q: {T} = a;\n assert(q == this.t);\n }\n}\n"


def _messages(typ: str) -> list[str]:
    res = compile_from_source_str_with_result(HEAD.replace("{T}", typ), "P.runar.ts")
    return [d.message for d in res.diagnostics]


def test_huge_type_text_is_elided():
    echoing = [m for m in _messages("T" * (1 << 20)) if "TTTT" in m]
    assert echoing, "no diagnostic echoed the type"
    for m in echoing:
        assert len(m) < 1100
        assert re.search(r"\.\.\.\(\d+ more bytes elided\)$", m)


def test_ordinary_type_text_is_unchanged():
    assert "'ByteString'" in "\n".join(_messages("ByteString"))
