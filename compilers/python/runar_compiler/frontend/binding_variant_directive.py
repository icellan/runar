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


_BINDING_VARIANT_TOKEN_RE = re.compile(r"@bindingVariant\b")
_LINE_START_ERR = (
    "@bindingVariant must be a JSDoc tag at the start of a comment line "
    "(`@bindingVariant all` or `@bindingVariant lowS`)"
)


def _strip_comment_line(raw: str) -> str:
    s = raw.lstrip(" \t")
    if s.startswith("//"):
        s = s[2:].lstrip(" \t")
    elif s.startswith("/**"):
        s = s[3:].lstrip(" \t")
    elif s.startswith("/*"):
        s = s[2:].lstrip(" \t")
    elif s.startswith("*"):
        s = s[1:].lstrip(" \t")
    s = s.rstrip(" \t")
    if s.endswith("*/"):
        s = s[:-2].rstrip(" \t")
    return s


def extract_binding_variant_directive(comment_text: str) -> BindingVariantParseResult | None:
    """Extract and parse a ``@bindingVariant`` directive from a block of comment
    text.

    Returns ``None`` when no ``@bindingVariant`` token is present, otherwise the
    parse result (value or error). Only a JSDoc/line-comment tag at the start of
    a comment line is a directive; mid-sentence mentions and trailing junk error.
    """
    if not _BINDING_VARIANT_TOKEN_RE.search(comment_text):
        return None
    for raw in comment_text.splitlines():
        line = _strip_comment_line(raw)
        if not line.startswith("@bindingVariant"):
            continue
        rest = line[len("@bindingVariant"):]
        if rest and (rest[0].isalnum() or rest[0] == "_"):
            continue
        if rest and rest[0] not in " \t":
            return BindingVariantParseResult(error=_LINE_START_ERR)
        return parse_binding_variant(rest.strip())
    return BindingVariantParseResult(error=_LINE_START_ERR)
