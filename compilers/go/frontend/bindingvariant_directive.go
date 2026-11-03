package frontend

import (
	"fmt"
	"regexp"
	"strings"
)

// `@bindingVariant` directive parsing (ports #170; original design:
// brendan-elas, #167). Mirrors packages/runar-compiler/src/passes/
// bindingvariant-directive.ts; diagnostic text is identical in all seven
// tiers.
//
// A public `.runar.ts` method may carry `/** @bindingVariant <lowS|all> */`,
// selecting the Any-S OP_PUSH_TX binding construction its checkPreimage
// emits. `lowS` (default) is valid at every tx nVersion; `all` is the compact
// non-low-S blob, spendable only when the spending tx has nVersion != 1.
// Same marker rules as `@sighash` (F-039 / N-039): one marker per method,
// and anything other than ` lowS` / ` all` after it is an error.

// BindingVariantDefault is the construction a method uses without a directive.
const BindingVariantDefault = "lowS"

const bindingVariantMarker = "@bindingVariant"

// BindingVariantMalformedError and BindingVariantMultipleError are shared
// verbatim with the other six tiers.
const (
	BindingVariantMalformedError = "@bindingVariant: malformed directive; expected `@bindingVariant lowS` or `@bindingVariant all`"
	BindingVariantMultipleError  = "@bindingVariant: more than one @bindingVariant directive on this method; declare exactly one"
)

var (
	bindingVariantMarkerRE  = regexp.MustCompile(`@bindingVariant`)
	bindingVariantSegmentRE = regexp.MustCompile(`^[ \t][A-Za-z0-9_ \t]*$`)
)

type bindingVariantParseResult struct {
	value string
	err   string
}

func parseBindingVariant(text string) bindingVariantParseResult {
	raw := strings.Trim(text, " \t")
	if raw == "lowS" || raw == "all" {
		return bindingVariantParseResult{value: raw}
	}
	if raw == "" {
		return bindingVariantParseResult{err: BindingVariantMalformedError}
	}
	return bindingVariantParseResult{err: fmt.Sprintf("@bindingVariant: unknown variant %q (valid: lowS, all)", raw)}
}

// extractBindingVariantDirective extracts and parses a `@bindingVariant`
// directive from a method's leading-comment text. present is false only when
// no marker occurs.
func extractBindingVariantDirective(commentText string) (result bindingVariantParseResult, present bool) {
	first := strings.Index(commentText, bindingVariantMarker)
	if first == -1 {
		return bindingVariantParseResult{}, false
	}
	if strings.Contains(commentText[first+len(bindingVariantMarker):], bindingVariantMarker) {
		return bindingVariantParseResult{err: BindingVariantMultipleError}, true
	}
	after := commentText[first+len(bindingVariantMarker):]
	end := len(after)
	for i := 0; i < len(after); i++ {
		c := after[i]
		if c == '\n' || c == '\r' || (c == '*' && i+1 < len(after) && after[i+1] == '/') {
			end = i
			break
		}
	}
	seg := after[:end]
	if !bindingVariantSegmentRE.MatchString(seg) {
		return bindingVariantParseResult{err: BindingVariantMalformedError}, true
	}
	return parseBindingVariant(seg), true
}

// BindingVariantUnsupportedMsg is the non-TS surfaces' refusal, identical in
// all seven tiers.
func BindingVariantUnsupportedMsg(surfaceName string) string {
	return fmt.Sprintf("@bindingVariant directive is not supported by the %s surface parser; write the contract in TypeScript (.runar.ts), where @bindingVariant is honoured", surfaceName)
}
