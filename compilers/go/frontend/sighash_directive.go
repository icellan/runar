package frontend

import (
	"fmt"
	"strings"
)

// `@sighash` directive parsing (issue #123).
//
// A public method may carry a `/** @sighash <FLAGS> */` comment directive that
// declares which BIP-143 sighash type its auto-injected covenant (and the
// SDK-built preimage) commits to. `<FLAGS>` is a `|`-separated set of SigHash
// names, e.g. `SINGLE|FORKID`, `ALL|ANYONECANPAY|FORKID`, `NONE|FORKID`.
//
// The default (no directive) is `ALL|FORKID` (0x41) — byte-identical to the
// historically-pinned mode, so existing fixtures see ZERO change.
//
// This is a faithful Go port of the TypeScript reference module
// packages/runar-compiler/src/passes/sighash-directive.ts: the flag grammar
// (name -> value, combo validity) plus the FORKID-mandatory guard.

// FLAG_VALUES is the numeric value of each sighash flag name.
var sighashFlagValues = map[string]int{
	"ALL":          0x01,
	"NONE":         0x02,
	"SINGLE":       0x03,
	"FORKID":       0x40,
	"ANYONECANPAY": 0x80,
}

// sighashBaseTypeNames are the base-type names. Exactly one MUST appear.
var sighashBaseTypeNames = map[string]bool{"ALL": true, "NONE": true, "SINGLE": true}

// SighashDefault is SIGHASH_ALL | SIGHASH_FORKID — the default when no
// directive is present.
const SighashDefault = 0x41

// Base-type mask and flag constants shared with the field-usage validator.
const (
	sighashBaseTypeMask = 0x1f
	sighashBaseAll      = 0x01
	sighashBaseNone     = 0x02
	sighashBaseSingle   = 0x03
	sighashFlagForkID   = 0x40
	sighashFlagAnyone   = 0x80
)

// sighashParseResult carries either a parsed value or an error message,
// mirroring the TS discriminated union { value } | { error }.
type sighashParseResult struct {
	value int
	err   string
}

func (r sighashParseResult) ok() bool { return r.err == "" }

// parseSighashFlags parses the flag list of an `@sighash` directive.
//
// flagsText is the raw text following `@sighash` (e.g. "SINGLE|FORKID"), with
// any trailing comment punctuation already stripped by the caller.
//
// Validation (security-relevant — a mis-declared mode is an exploit class):
//   - every name must be a known flag (reject typos like FORKD)
//   - EXACTLY ONE base type (ALL/NONE/SINGLE) — reject zero, and reject
//     nonsensical combos such as ALL|NONE. This is checked on NAMES, not on the
//     OR-ed numeric value, because ALL|NONE (0x01|0x02) collides with the
//     numeric value of SINGLE (0x03) — a silent, dangerous aliasing that a
//     purely numeric check would miss.
//   - reject a duplicated flag name (signals a copy/paste error).
//   - FORKID is mandatory on BSV (the whole OP_PUSH_TX / BIP-143 machinery is
//     FORKID-only, so a FORKID-less mode deploys to brick).
func parseSighashFlags(flagsText string) sighashParseResult {
	raw := strings.TrimSpace(flagsText)
	if len(raw) == 0 {
		return sighashParseResult{err: "@sighash directive requires at least one flag (e.g. `@sighash ALL|FORKID`)"}
	}

	names := strings.Split(raw, "|")
	seen := make(map[string]bool)
	var baseTypes []string
	value := 0

	for _, n := range names {
		name := strings.TrimSpace(n)
		if len(name) == 0 {
			return sighashParseResult{err: fmt.Sprintf("@sighash directive has an empty flag in %q", raw)}
		}
		v, known := sighashFlagValues[name]
		if !known {
			return sighashParseResult{err: fmt.Sprintf("@sighash: unknown flag %q (valid: ALL, NONE, SINGLE, FORKID, ANYONECANPAY)", name)}
		}
		if seen[name] {
			return sighashParseResult{err: fmt.Sprintf("@sighash: duplicate flag %q in %q", name, raw)}
		}
		seen[name] = true
		if sighashBaseTypeNames[name] {
			baseTypes = append(baseTypes, name)
		}
		value |= v
	}

	if len(baseTypes) == 0 {
		return sighashParseResult{err: fmt.Sprintf("@sighash: must specify exactly one base type (ALL, NONE, or SINGLE); got %q", raw)}
	}
	if len(baseTypes) > 1 {
		return sighashParseResult{err: fmt.Sprintf("@sighash: cannot combine base types (%s) — pick exactly one of ALL/NONE/SINGLE", strings.Join(baseTypes, "|"))}
	}

	// FORKID is mandatory on BSV: the entire OP_PUSH_TX / BIP-143 preimage
	// machinery is FORKID-only, so a FORKID-less flag set deploys a covenant
	// whose derived signature can never verify (deploy-to-brick). Reject it up
	// front rather than let a spendable-looking script ship.
	if value&sighashFlagValues["FORKID"] == 0 {
		return sighashParseResult{err: fmt.Sprintf("@sighash: FORKID is mandatory on BSV; write e.g. @sighash %s|FORKID (got %q)", baseTypes[0], raw)}
	}

	return sighashParseResult{value: value}
}

// Shared diagnostics (F-039) — identical text in all seven tiers. A marker
// that is present but not followed by a well-formed flag list, or a second
// marker on the same method, is a compile error, never a silent fall-back to
// the default ALL|FORKID mode.
const (
	sighashMalformedError = "@sighash: malformed directive; expected `@sighash <FLAGS>` where FLAGS is a |-separated list of ALL, NONE, SINGLE, FORKID, ANYONECANPAY (e.g. `@sighash SINGLE|FORKID`)"
	sighashMultipleError  = "@sighash: more than one @sighash directive on this method; declare exactly one"
	sighashMarker         = "@sighash"
)

func sighashIsWordByte(c byte) bool {
	return c == '_' || (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}

// extractSighashDirective extracts and parses an `@sighash` directive from a
// method's leading-comment text (all of its leading comments, concatenated).
// Returns (_, false) only when no `@sighash` marker is present, else
// (result, true). Mirrors the TS reference extractSighashDirective.
//
// A marker is every occurrence of `@sighash`, whatever follows it (N-039, user
// decision R85): `@sighashSINGLE|FORKID` or `@sighashType` is a malformed
// directive, never prose. Once a marker is present (fail-closed, F-039):
//   - more than one marker is an error (sighashMultipleError);
//   - the segment after the marker, up to `*/`, a newline, CR or the end, must
//     be empty, or start with a space/tab and contain only [A-Za-z0-9_|],
//     spaces and tabs — anything else is sighashMalformedError;
//   - the flag list itself is then validated by parseSighashFlags.
func extractSighashDirective(commentText string) (sighashParseResult, bool) {
	var markers []int
	for i := 0; ; {
		j := strings.Index(commentText[i:], sighashMarker)
		if j < 0 {
			break
		}
		pos := i + j
		markers = append(markers, pos)
		i = pos + 1
	}
	if len(markers) == 0 {
		return sighashParseResult{}, false
	}
	if len(markers) > 1 {
		return sighashParseResult{err: sighashMultipleError}, true
	}

	after := commentText[markers[0]+len(sighashMarker):]
	end := len(after)
	for i := 0; i < len(after); i++ {
		if after[i] == '\n' || after[i] == '\r' || (after[i] == '*' && i+1 < len(after) && after[i+1] == '/') {
			end = i
			break
		}
	}
	seg := after[:end]
	if len(seg) > 0 {
		ok := seg[0] == ' ' || seg[0] == '\t'
		for i := 0; ok && i < len(seg); i++ {
			c := seg[i]
			ok = sighashIsWordByte(c) || c == '|' || c == ' ' || c == '\t'
		}
		if !ok {
			return sighashParseResult{err: sighashMalformedError}, true
		}
	}
	return parseSighashFlags(seg), true
}

// describeSighash renders a sighash value as a human-readable flag string (for
// diagnostics). Mirrors the TS describeSighash.
func describeSighash(value int) string {
	var parts []string
	base := value & sighashBaseTypeMask
	switch base {
	case sighashBaseAll:
		parts = append(parts, "ALL")
	case sighashBaseNone:
		parts = append(parts, "NONE")
	case sighashBaseSingle:
		parts = append(parts, "SINGLE")
	default:
		parts = append(parts, fmt.Sprintf("0x%x", base))
	}
	if value&sighashFlagAnyone != 0 {
		parts = append(parts, "ANYONECANPAY")
	}
	if value&sighashFlagForkID != 0 {
		parts = append(parts, "FORKID")
	}
	return strings.Join(parts, "|")
}

// resolveNativeSighash (N-093, R38) resolves a sighash declared with a
// surface's NATIVE spelling (Solidity `sighash(...)`, Move/Rust
// `#[sighash(...)]`, Go `//runar:sighash ...`, Python
// `@public(sighash="...")`, Zig `runar.Sighash("...")`, Ruby
// `runar_sighash '...'`, Java `@Sighash("...")`).
//
// specs holds one entry per spelling found on the method: the flag text, or
// nil when the spelling's argument was not well formed (a non-identifier
// token, a non-string argument, ...). Returns (nil, "") when there is no
// spelling, else the numeric type or the diagnostic — the SAME diagnostics the
// `.runar.ts` comment directive produces, checked in the same order:
// non-public method, then more than one spelling, then malformed, then the
// flag grammar of parseSighashFlags. Mirrors resolveNativeSighash in the TS
// reference (sighash-directive.ts); identical in all seven tiers.
func resolveNativeSighash(methodName string, isPublic bool, specs []*string) (*int, string) {
	if len(specs) == 0 {
		return nil, ""
	}
	if !isPublic {
		return nil, fmt.Sprintf("@sighash directive on non-public method '%s' has no effect — only public methods are spending entry points", methodName)
	}
	if len(specs) > 1 {
		return nil, fmt.Sprintf("Method '%s': %s", methodName, sighashMultipleError)
	}
	if specs[0] == nil {
		return nil, fmt.Sprintf("Method '%s': %s", methodName, sighashMalformedError)
	}
	r := parseSighashFlags(*specs[0])
	if !r.ok() {
		return nil, fmt.Sprintf("Method '%s': %s", methodName, r.err)
	}
	v := r.value
	return &v, ""
}

// unknownGoDirectiveMessage (N-093): the Go DSL directive comment
// `//runar:<name> ...`. Only `sighash` exists; any other name is refused
// rather than ignored, so a typo such as `//runar:sighsh` cannot silently drop
// the declaration.
func unknownGoDirectiveMessage(name string) string {
	return fmt.Sprintf("unknown Go DSL directive '//runar:%s'; the only directive is //runar:sighash <FLAGS>", name)
}

// unknownMoveAttributeMessage (N-093): an attribute on the Move surface other
// than the two directives.
func unknownMoveAttributeMessage(attr string) string {
	return fmt.Sprintf("unsupported Move attribute #[%s]; the supported attributes are #[embed_always] and #[sighash(<FLAGS>)]", attr)
}

// nativeSighashSpec returns a pointer to s (a well-formed native sighash spec).
func nativeSighashSpec(s string) *string { return &s }
