"""``@bindingVariant`` directive parsing (ports #170; original design:
brendan-elas, #167). Mirrors
packages/runar-compiler/src/passes/bindingvariant-directive.ts; diagnostic text
is identical in all seven tiers.

A public ``.runar.ts`` method may carry ``/** @bindingVariant <lowS|all> */``,
selecting the Any-S OP_PUSH_TX binding construction its checkPreimage emits.
``lowS`` (default) is valid at every tx nVersion; ``all`` is the compact
non-low-S blob, spendable only when the spending tx has nVersion != 1. Same
marker rules as ``@sighash`` (F-039 / N-039): one marker per method, and
anything other than `` lowS`` / `` all`` after it is an error.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

BINDING_VARIANT_MARKER = "@bindingVariant"

BINDING_VARIANT_MALFORMED_ERROR = (
    "@bindingVariant: malformed directive; expected `@bindingVariant lowS` or `@bindingVariant all`"
)
BINDING_VARIANT_MULTIPLE_ERROR = (
    "@bindingVariant: more than one @bindingVariant directive on this method; declare exactly one"
)

_SEGMENT_RE = re.compile(r"[ \t][A-Za-z0-9_ \t]*")


@dataclass
class BindingVariantParseResult:
    value: str | None = None
    error: str | None = None


def _parse_binding_variant(text: str) -> BindingVariantParseResult:
    raw = text.strip(" \t")
    if raw in ("lowS", "all"):
        return BindingVariantParseResult(value=raw)
    if raw == "":
        return BindingVariantParseResult(error=BINDING_VARIANT_MALFORMED_ERROR)
    return BindingVariantParseResult(error=f'@bindingVariant: unknown variant "{raw}" (valid: lowS, all)')


def extract_binding_variant_directive(comment_text: str) -> BindingVariantParseResult | None:
    """Extract and parse a ``@bindingVariant`` directive from a method's
    leading-comment text. ``None`` only when no marker occurs."""
    first = comment_text.find(BINDING_VARIANT_MARKER)
    if first == -1:
        return None
    after = comment_text[first + len(BINDING_VARIANT_MARKER):]
    if BINDING_VARIANT_MARKER in after:
        return BindingVariantParseResult(error=BINDING_VARIANT_MULTIPLE_ERROR)
    end = len(after)
    for i, c in enumerate(after):
        if c in "\n\r" or (c == "*" and after[i + 1:i + 2] == "/"):
            end = i
            break
    seg = after[:end]
    if not _SEGMENT_RE.fullmatch(seg):
        return BindingVariantParseResult(error=BINDING_VARIANT_MALFORMED_ERROR)
    return _parse_binding_variant(seg)


def binding_variant_unsupported_message(surface_name: str) -> str:
    """The non-TS surfaces' refusal, identical in all seven tiers."""
    return (
        f"@bindingVariant directive is not supported by the {surface_name} surface parser; "
        "write the contract in TypeScript (.runar.ts), where @bindingVariant is honoured"
    )
