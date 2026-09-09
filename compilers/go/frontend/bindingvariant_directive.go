package frontend

import (
	"fmt"
	"regexp"
	"strings"
)

// `@bindingVariant` directive parsing.
//
// A public method may carry a `/** @bindingVariant <VARIANT> */` comment
// directive selecting which Any-S OP_PUSH_TX preimage-binding construction its
// auto-injected covenant emits: "lowS" (default; low-S fixup, safe under the
// LOW_S rule that applies to nVersion = 1) or "all" (compact non-low-S, ~50 bytes
// smaller, valid only for spends with nVersion != 1). Faithful Go port of the
// TypeScript reference module
// packages/runar-compiler/src/passes/bindingvariant-directive.ts.

// bindingVariantDefault is the construction used when no directive is present.
const bindingVariantDefault = "lowS"

// bindingVariantValues are the recognised variant names (as written).
var bindingVariantValues = map[string]bool{"lowS": true, "all": true}

type bindingVariantParseResult struct {
	value string
	err   string
}

func (r bindingVariantParseResult) ok() bool { return r.err == "" }

// parseBindingVariant parses the value text of a `@bindingVariant` directive.
// Case-sensitive: only "lowS" and "all" are accepted, so a typo is rejected
// rather than silently defaulted (a mis-declared binding is an exploit class).
func parseBindingVariant(variantText string) bindingVariantParseResult {
	raw := strings.TrimSpace(variantText)
	if raw == "" {
		return bindingVariantParseResult{err: "@bindingVariant directive requires a value (`@bindingVariant all` or `@bindingVariant lowS`)"}
	}
	if !bindingVariantValues[raw] {
		return bindingVariantParseResult{err: fmt.Sprintf("@bindingVariant: unknown variant %q (valid: lowS, all)", raw)}
	}
	return bindingVariantParseResult{value: raw}
}

// bindingVariantRE extracts the value following an `@bindingVariant` token in a
// block of comment text. Mirrors the TS BINDING_VARIANT_RE.
var bindingVariantRE = regexp.MustCompile(`@bindingVariant\s+([A-Za-z0-9_]*?)(?:\*/|\n|\r|\s|$)`)

// extractBindingVariantDirective extracts and parses a `@bindingVariant`
// directive from a block of comment text. Returns (result, true) when the token
// is present, else (_, false).
func extractBindingVariantDirective(commentText string) (bindingVariantParseResult, bool) {
	m := bindingVariantRE.FindStringSubmatch(commentText)
	if m == nil {
		return bindingVariantParseResult{}, false
	}
	return parseBindingVariant(m[1]), true
}
