"""R-246 (CL-GAP-084): `_validate_property_type` refuses an unknown CustomType
and accepts an unknown PrimitiveType.

    if isinstance(t, PrimitiveType):
        if t.name not in _VALID_PROP_TYPES:
            if t.name == "void":
                self._add_error(...)          # <- and nothing else
    elif isinstance(t, CustomType):
        self._add_error(f"unsupported type '{t.name}' ...")

So a `PrimitiveType` whose name is not in the valid set falls through in silence
unless it happens to be spelled `void`, while ANY CustomType is an error. The
same property, described two ways, gets two answers.

The finding calls it "currently unreachable but fragile", and that is right about
today: every parser in this tier maps an unrecognised name to `CustomType`, so
nothing produces a `PrimitiveType("bogus")`. Unreachable-from-the-parser is not
the same as unreachable — `validate()` is a public entry point that takes an AST,
and the frontend is not the only thing that builds one. A pass that synthesises a
property (the fixed-array expansion synthesises several) is one refactor away
from constructing the node this branch drops on the floor.

These tests drive `validate()` directly with a hand-built contract, which is the
level the asymmetry lives at. The four cases that already worked are asserted
alongside, so a fix that turns the branch into "refuse everything" fails here.
"""

from runar_compiler.frontend.ast_nodes import (
    ContractNode,
    CustomType,
    FixedArrayType,
    MethodNode,
    PrimitiveType,
    PropertyNode,
    SourceLocation,
)
from runar_compiler.frontend.validator import validate

LOC = SourceLocation(file="Probe.runar.ts", line=1, column=1)


def contract_with_property_type(t) -> ContractNode:
    """A minimal stateless contract whose single readonly property has type `t`."""
    return ContractNode(
        name="Probe",
        parent_class="SmartContract",
        properties=[PropertyNode(name="p", type=t, readonly=True, source_location=LOC)],
        constructor=MethodNode(name="constructor", source_location=LOC),
        methods=[],
        source_file="Probe.runar.ts",
    )


def property_type_errors(t) -> list[str]:
    """Only the diagnostics about the property's TYPE.

    A minimal hand-built contract trips other rules (no super() call, and so on);
    filtering keeps this test about the branch it is named for.
    """
    result = validate(contract_with_property_type(t))
    return [
        d.message
        for d in result.errors
        if "type" in d.message.lower() and "'p'" not in d.message
    ]


def test_a_valid_primitive_is_accepted():
    """Control. Without it, 'refuse everything' would pass every case below."""
    assert property_type_errors(PrimitiveType(name="bigint")) == []


def test_an_unknown_custom_type_is_refused():
    """The half that already worked."""
    errs = property_type_errors(CustomType(name="Foobarium"))
    assert any("Foobarium" in e for e in errs), errs


def test_void_as_a_property_type_is_refused():
    errs = property_type_errors(PrimitiveType(name="void"))
    assert any("void" in e for e in errs), errs


def test_an_unknown_primitive_type_is_refused_like_an_unknown_custom_one():
    """The finding. `Foobarium` is not a Runar type however the node spells it."""
    errs = property_type_errors(PrimitiveType(name="Foobarium"))
    assert any("Foobarium" in e for e in errs), (
        "an unknown PrimitiveType passed validation while the identical name as a "
        "CustomType is refused: " + repr(errs)
    )


def test_the_rule_reaches_a_fixed_array_element_type():
    """FixedArray recurses into its element, so the asymmetry hid there too."""
    errs = property_type_errors(
        FixedArrayType(element=PrimitiveType(name="Foobarium"), length=3)
    )
    assert any("Foobarium" in e for e in errs), errs


def test_a_valid_fixed_array_is_still_accepted():
    assert property_type_errors(
        FixedArrayType(element=PrimitiveType(name="bigint"), length=3)
    ) == []
