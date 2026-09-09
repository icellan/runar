"""``@bindingVariant`` directive parsing.

A public method may carry a ``/** @bindingVariant <VARIANT> */`` comment
directive selecting which Any-S OP_PUSH_TX preimage-binding construction its
auto-injected covenant emits: ``lowS`` (default; low-S fixup, safe under the
LOW_S rule that applies to nVersion = 1) or ``all`` (compact non-low-S, ~45 bytes
smaller, valid only for spends with nVersion != 1).

Reuses the exact two-surface directive shape #109 established for
``@embedAlways`` / ``@sighash`` (JSDoc block + leading trivia); the *detection*
lives in the parser, this module owns the *variant grammar* (name validity).

Port of packages/runar-compiler/src/passes/bindingvariant-directive.ts (and the
Go tier's frontend/bindingvariant_directive.go).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# The construction used when no directive is present.
BINDING_VARIANT_DEFAULT = "lowS"

# The recognised variant names (as written). Case-sensitive.
_BINDING_VARIANT_VALUES = frozenset({"lowS", "all"})


@dataclass
class BindingVariantParseResult:
    """Discriminated result: exactly one of ``value`` / ``error`` is set."""
    value: str | None = None
    error: str | None = None


def parse_binding_variant(variant_text: str) -> BindingVariantParseResult:
    """Parse the value text of a ``@bindingVariant`` directive.

    Case-sensitive: only ``lowS`` and ``all`` are accepted, so a typo is rejected
    rather than silently defaulted (a mis-declared binding is an exploit class).
    """
    raw = variant_text.strip()
    if raw == "":
        return BindingVariantParseResult(
            error="@bindingVariant directive requires a value "
                  "(`@bindingVariant all` or `@bindingVariant lowS`)"
        )
    if raw not in _BINDING_VARIANT_VALUES:
        return BindingVariantParseResult(
            error=f'@bindingVariant: unknown variant "{raw}" (valid: lowS, all)'
        )
    return BindingVariantParseResult(value=raw)


# Extract the value following ``@bindingVariant`` in a block of comment text.
# Mirrors the TS BINDING_VARIANT_RE / the Go bindingVariantRE.
_BINDING_VARIANT_RE = re.compile(r"@bindingVariant\s+([A-Za-z0-9_]*?)(?:\*/|\n|\r|\s|$)")


def extract_binding_variant_directive(comment_text: str) -> BindingVariantParseResult | None:
    """Extract and parse a ``@bindingVariant`` directive from a block of comment
    text.

    Returns ``None`` when no ``@bindingVariant`` token is present, otherwise the
    parse result (value or error). Used by the parser after it has collected a
    method's JSDoc / leading-comment trivia.
    """
    m = _BINDING_VARIANT_RE.search(comment_text)
    if m is None:
        return None
    return parse_binding_variant(m.group(1) or "")
