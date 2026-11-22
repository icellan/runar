"""D25: ``lower_to_anf`` is a public entry point. A caller that assembles its
own pipeline (parse -> validate -> type_check -> lower_to_anf) and never runs
``inject_continuation_binding`` would otherwise lower a mixed ("bind")
contract with no ``_spentOutpointHash``: its continuations would not be bound
to the spent outpoint, which is the twin-input theft D25 closes.
"""
from __future__ import annotations

from runar_compiler.frontend.anf_lower import lower_to_anf
from runar_compiler.frontend.continuation_binding import (
    TWIN_BINDING_FIELD,
    inject_continuation_binding,
)
from runar_compiler.frontend.parser_dispatch import parse_source
from runar_compiler.frontend.typecheck import type_check
from runar_compiler.frontend.validator import validate

MIXED = """import { StatefulSmartContract, assert, extractAmount } from 'runar-lang';
class MixedPot extends StatefulSmartContract {
  count: bigint;
  constructor(count: bigint) { super(count); this.count = count; }
  public increment() { this.count++; }
  public bump() { this.addOutput(extractAmount(this.txPreimage), this.count + 1n); }
}"""


def _frontend():
    pr = parse_source(MIXED, "MixedPot.runar.ts")
    assert not pr.errors and pr.contract is not None, pr.errors
    v = validate(pr.contract)
    assert not v.errors, v.errors
    tc = type_check(pr.contract)
    assert not tc.errors, tc.errors
    return pr.contract


def test_lower_to_anf_injects_binding_without_caller_injection():
    props = lower_to_anf(_frontend()).properties
    assert props and props[-1].name == TWIN_BINDING_FIELD, "binding not injected"


def test_lower_to_anf_does_not_inject_twice():
    props = lower_to_anf(inject_continuation_binding(_frontend())).properties
    assert sum(1 for p in props if p.name == TWIN_BINDING_FIELD) == 1
