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

var bindingVariantTokenRE = regexp.MustCompile(`@bindingVariant\b`)

const bindingVariantLineStartErr = "@bindingVariant must be a JSDoc tag at the start of a comment line (`@bindingVariant all` or `@bindingVariant lowS`)"

func isBindingVariantIdentChar(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_'
}

func stripBindingVariantCommentLine(raw string) string {
	s := strings.TrimLeft(raw, " \t")
	switch {
	case strings.HasPrefix(s, "//"):
		s = strings.TrimLeft(s[2:], " \t")
	case strings.HasPrefix(s, "/**"):
		s = strings.TrimLeft(s[3:], " \t")
	case strings.HasPrefix(s, "/*"):
		s = strings.TrimLeft(s[2:], " \t")
	case strings.HasPrefix(s, "*"):
		s = strings.TrimLeft(s[1:], " \t")
	}
	s = strings.TrimRight(s, " \t")
	if strings.HasSuffix(s, "*/") {
		s = strings.TrimRight(s[:len(s)-2], " \t")
	}
	return s
}

// extractBindingVariantDirective extracts and parses a `@bindingVariant`
// directive from a block of comment text. Returns (result, true) when the token
// is present, else (_, false). Only a JSDoc/line-comment tag at the start of a
// comment line is a directive; mid-sentence mentions and trailing junk error.
func extractBindingVariantDirective(commentText string) (bindingVariantParseResult, bool) {
	if !bindingVariantTokenRE.MatchString(commentText) {
		return bindingVariantParseResult{}, false
	}
	for _, raw := range strings.Split(commentText, "\n") {
		line := stripBindingVariantCommentLine(strings.TrimRight(raw, "\r"))
		if !strings.HasPrefix(line, "@bindingVariant") {
			continue
		}
		rest := line[len("@bindingVariant"):]
		if rest != "" && isBindingVariantIdentChar(rest[0]) {
			continue
		}
		if rest != "" && rest[0] != ' ' && rest[0] != '\t' {
			return bindingVariantParseResult{err: bindingVariantLineStartErr}, true
		}
		return parseBindingVariant(strings.TrimSpace(rest)), true
	}
	return bindingVariantParseResult{err: bindingVariantLineStartErr}, true
}
