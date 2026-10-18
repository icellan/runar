package frontend

import (
	"bytes"
	"context"
	"fmt"
	"math/big"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/typescript/typescript"

	"github.com/icellan/runar/compilers/go/codegen"
	"github.com/icellan/runar/compilers/go/ir"
)

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

// ParseResult holds the result of parsing a Rúnar source file.
type ParseResult struct {
	Contract *ContractNode
	Errors   []Diagnostic
	// SourceSizeErr is non-nil iff ParseSource rejected the input via the
	// DoS-bound source-size guard. Callers wanting typed detection can
	// check `result.SourceSizeErr != nil` (or `errors.As`) instead of
	// string-matching the diagnostic message. BUG-008 follow-up.
	SourceSizeErr *SourceSizeExceededError
}

// ErrorStrings returns error messages as strings (for backward compatibility).
func (r *ParseResult) ErrorStrings() []string {
	result := make([]string, len(r.Errors))
	for i, d := range r.Errors {
		result[i] = d.FormatMessage()
	}
	return result
}

// ParseSource detects the file extension and routes to the appropriate parser.
//   - .runar.sol -> ParseSolidity
//   - .runar.move -> ParseMove
//   - .runar.go -> ParseGoContract
//   - .runar.py -> ParsePython
//   - .runar.rs -> ParseRustMacro
//   - .runar.rb -> ParseRuby
//   - .runar.zig -> ParseZig
//   - .runar.java -> ParseJava
//   - default -> Parse (existing TypeScript parser)
func ParseSource(source []byte, fileName string) *ParseResult {
	result := parseSourceDispatch(source, fileName)
	// N-115: `10 > i` is `i < 10`; every later pass sees the canonical form.
	if result != nil {
		normalizeLoopConditions(result.Contract)
	}
	return result
}

func parseSourceDispatch(source []byte, fileName string) *ParseResult {
	// DoS-bound size guard. Reject oversized source BEFORE any
	// format-specific parser touches the input. BUG-008 follow-up.
	if err := assertSourceBytesUnderLimit(source); err != nil {
		sse := err.(*SourceSizeExceededError)
		return &ParseResult{
			Errors: []Diagnostic{{
				Message:  sse.Error(),
				Severity: SeverityError,
			}},
			SourceSizeErr: sse,
		}
	}

	lower := strings.ToLower(fileName)

	// The TypeScript surface parser (Parse, the default branch) reads the
	// `@sighash` (#123, per-method sighash type) and `@embedAlways` (#109,
	// readonly-field DCE opt-out) directives from COMMENTS. The eight non-TS
	// surfaces spell both directives natively instead (N-093, user decision
	// R38: a modifier mirroring each surface's readonly idiom — see
	// nonTSSurfaces), and their parsers drop comments, so a COMMENT directive in
	// one of those sources would be silently ignored and change signing / DCE
	// semantics. Fail closed on those formats rather than miscompile, and name
	// the native spelling to use. None of the native spellings contains either
	// marker, so this guard never trips on them. Mirrors the TS reference
	// (01-parse.ts NON_TS_SURFACES).
	for _, s := range nonTSSurfaces {
		if strings.HasSuffix(lower, s.ext) {
			if msg := unsupportedDirectiveError(source, s); msg != "" {
				return directiveGuardResult(msg)
			}
			return s.parse(source, fileName)
		}
	}
	// TypeScript surface: honours @sighash / @embedAlways directly.
	return Parse(source, fileName)
}

// Directive markers for the fail-closed guard. `@embedAlways` is word-boundary
// anchored so an identifier like `sighashType` does not trip the guard;
// `@sighash` is not (N-244): N-039 made every occurrence of the marker a
// directive, so a glued `@sighashSINGLE|FORKID` is refused here too, with the
// message every tier shares.
var (
	sighashDirectiveRE     = regexp.MustCompile(`@sighash`)
	embedAlwaysDirectiveRE = regexp.MustCompile(`@embedAlways\b`)
)

func directiveGuardResult(msg string) *ParseResult {
	return &ParseResult{Errors: []Diagnostic{{Message: msg, Severity: SeverityError}}}
}

// nonTSSurface is one non-TS surface: its extension, the human-readable
// surface name for the diagnostic, its format doc, the native spelling of each
// directive on it (N-093), and its parser. `.runar.ts` is intentionally absent:
// the default branch implements the comment directives.
type nonTSSurface struct {
	ext, name, doc, sighashSpelling, embedSpelling string
	parse                                          func([]byte, string) *ParseResult
}

var nonTSSurfaces = []nonTSSurface{
	{".runar.sol", "Solidity", "solidity", "the function modifier sighash(<FLAGS>)", "the property modifier embedAlways", ParseSolidity},
	{".runar.move", "Move", "move", "the attribute #[sighash(<FLAGS>)]", "the attribute #[embed_always]", ParseMove},
	{".runar.go", "Go DSL", "go", "the directive //runar:sighash <FLAGS>", `the struct tag option runar:"readonly,embedAlways"`, ParseGoContract},
	{".runar.py", "Python", "python", `@public(sighash="<FLAGS>")`, "the wrapper type EmbedAlways[T]", ParsePython},
	{".runar.rs", "Rust", "rust", "the attribute #[sighash(<FLAGS>)]", "the attribute #[embed_always]", ParseRustMacro},
	{".runar.rb", "Ruby", "ruby", "runar_sighash '<FLAGS>'", "the prop option embed_always: true", ParseRuby},
	{".runar.zig", "Zig", "zig", `the return type runar.Sighash("<FLAGS>")`, "the type function runar.EmbedAlways(T)", ParseZig},
	{".runar.java", "Java", "java", `the annotation @Sighash("<FLAGS>")`, "the annotation @EmbedAlways", ParseJava},
}

// unsupportedDirectiveError returns a non-empty diagnostic message when the
// source carries a `@sighash` (#123) or `@embedAlways` (#109) COMMENT directive
// on a non-TS surface whose parser ignores comments (so the directive would be
// silently dropped), or "" when the source is clean. The message names the
// surface's native spelling (N-093).
func unsupportedDirectiveError(source []byte, s nonTSSurface) string {
	if sighashDirectiveRE.Match(source) {
		return fmt.Sprintf("@sighash directive (issue #123) is not supported as a comment by the %s surface parser; write it as %s (see docs/formats/%s.md)", s.name, s.sighashSpelling, s.doc)
	}
	if embedAlwaysDirectiveRE.Match(source) {
		return fmt.Sprintf("@embedAlways directive (issue #109) is not supported as a comment by the %s surface parser; write it as %s (see docs/formats/%s.md)", s.name, s.embedSpelling, s.doc)
	}
	return ""
}

// Parse parses a TypeScript source string and extracts the Rúnar contract AST.
func Parse(source []byte, fileName string) *ParseResult {
	// DoS-bound size guard. Reject oversized source BEFORE the tokenizer
	// touches it, even when Parse is called directly instead of via
	// ParseSource. F-177.
	if res := sourceSizeGuardResult(source); res != nil {
		return res
	}
	return withNestingLimit(func() *ParseResult { return parseTsSurface(source, fileName) })
}

// tsParseTimeLimit bounds the tree-sitter parse of a .runar.ts source (N-308).
//
// It is WALL-CLOCK, not an operation count: the go-tree-sitter binding exposes
// no operation counter (its SetOperationLimit is ts_parser_set_timeout_micros,
// whose clock is process CPU via clock() on macOS but CLOCK_MONOTONIC wall
// time on Linux), so the bound is a context deadline, which tree-sitter polls
// through its cancellation flag every 100 parse actions on every OS.
// Generous on purpose: a valid source filling MAX_SOURCE_BYTES parses in
// about a second; the quadratic recovery shapes run for minutes.
const tsParseTimeLimit = 20 * time.Second

// TsParseTooComplexMessage is the diagnostic for a .runar.ts source whose
// tree-sitter parse exceeded tsParseTimeLimit.
const TsParseTooComplexMessage = "source too complex to parse: tree-sitter parse of the .runar.ts source exceeded its time bound"

// parseTsSurface is the .runar.ts surface: tree-sitter parse, then conversion
// to the Rúnar AST.
func parseTsSurface(source []byte, fileName string) *ParseResult {
	parser := sitter.NewParser()
	parser.SetLanguage(typescript.GetLanguage())

	// N-308: tree-sitter's error recovery is quadratic on some bracket-free
	// shapes (`|| || … a`, `lambda: lambda: … a`, `a and a … a` filling
	// MAX_SOURCE_BYTES ran >137 s CPU inside the C parser). Bound the parse
	// and refuse past the bound.
	ctx, cancel := context.WithTimeout(context.Background(), tsParseTimeLimit)
	defer cancel()
	tree, err := parser.ParseCtx(ctx, nil, source)
	if err != nil && ctx.Err() != nil {
		return &ParseResult{Errors: []Diagnostic{{Message: TsParseTooComplexMessage, Severity: SeverityError}}}
	}
	if err != nil {
		return &ParseResult{Errors: []Diagnostic{{Message: fmt.Sprintf("parse error: %v", err), Severity: SeverityError}}}
	}

	root := tree.RootNode()
	p := &parseContext{
		source:   source,
		fileName: fileName,
	}

	// F-213 measure (A), before anything walks the tree recursively.
	// tree-sitter has no hook inside its parser, so the counter the
	// hand-written surfaces keep is recomputed here, iteratively.
	if bad := tsParseNestingViolation(root); bad != nil {
		loc := p.loc(bad)
		return sourceNestingResult(&loc)
	}

	// F-026: every number, extended over the [0-9A-Za-z_] characters glued to
	// it (tree-sitter ends `0b102` at `0b10`), must be a TypeScript integer
	// literal; `012`, `10_`, `0b102` are refused with the shared diagnostic.
	p.checkNumericLiterals(root)

	// N-121: the walk below ignores the `?.` of `this?.t` / `this?.m()` /
	// `this.m?.()`, so each compiled as a plain access or call. Optional
	// chaining is disallowed; refuse it.
	p.checkOptionalChaining(root)

	// tree-sitter is error-tolerant: malformed source still yields a tree, with
	// the bad region marked ERROR/MISSING. Walking such a tree silently DROPS
	// whatever failed to resolve (a statement parser returning nil is simply
	// not appended), so `this.value = ;` used to compile to a script with the
	// state write missing, and a malformed `assert(...)` to a script with the
	// guard missing. Refuse the file instead — one check for every malformed
	// shape, rather than a nil-guard per statement kind.
	if root.HasError() {
		if bad := firstBadNode(root); bad != nil {
			p.addError(fmt.Sprintf(
				"syntax error at line %d: unparseable %s near %q",
				bad.StartPoint().Row+1, bad.Type(), p.snippet(bad),
			))
		} else {
			p.addError("syntax error: source is not valid Rúnar")
		}
		return &ParseResult{Errors: p.errors}
	}

	contract := p.findContract(root)
	if contract == nil {
		p.errors = append(p.errors, Diagnostic{
			Message:  "No class extending SmartContract, StatefulSmartContract, or UnsafeSmartContract found",
			Severity: SeverityError,
			Loc:      &SourceLocation{File: p.fileName, Line: 1, Column: 0},
		})
		return &ParseResult{Errors: p.errors}
	}

	return &ParseResult{
		Contract: contract,
		Errors:   p.errors,
	}
}

// ---------------------------------------------------------------------------
// Parse context
// ---------------------------------------------------------------------------

type parseContext struct {
	source   []byte
	fileName string
	errors   []Diagnostic
}

// checkNumericLiterals refuses every malformed .runar.ts numeric literal
// (F-026, the TS reference's reportInvalidNumericLiterals).
//
// Iterative, in source order: it runs over the raw tree-sitter tree, and
// measure (A) did not always bound every node kind (a 4 MiB `&&&…&Int` type
// annotation is a valid ~4M-deep intersection_type chain, which (A) counts
// only since N-311), so a recursive walk overflowed the 1 GB goroutine stack
// (F-213 refuter, ref_type_rs).
func (p *parseContext) checkNumericLiterals(root *sitter.Node) {
	coveredTo := -1
	tsWalk(root, func(n *sitter.Node) bool {
		if n.Type() == "number" && int(n.StartByte()) >= coveredTo {
			start, end := int(n.StartByte()), int(n.EndByte())
			for end < len(p.source) && isNumberContinue(p.source[end]) {
				end++
			}
			coveredTo = end
			text := string(p.source[start:end])
			if parseIntLiteral("ts", text) == nil {
				p.errors = append(p.errors, lexDiag(invalidIntegerLiteralMsg("ts", text), p.fileName, int(n.StartPoint().Row)+1, int(n.StartPoint().Column)))
			}
		}
		return true
	})
}

// checkOptionalChaining refuses the first .runar.ts `?.`, located at its `?`
// (N-121, the TS reference's reportOptionalChaining). tree-sitter wraps the
// `?.` of a member or subscript access in an optional_chain node but leaves
// an optional call's `?.` as a bare anonymous token, so both are matched.
// Iterative and in source order, like checkNumericLiterals.
func (p *parseContext) checkOptionalChaining(root *sitter.Node) {
	tsWalk(root, func(n *sitter.Node) bool {
		if n.Type() == "optional_chain" || n.Type() == "?." {
			p.errors = append(p.errors, lexDiag(OptionalChainingMsg, p.fileName, int(n.StartPoint().Row)+1, int(n.StartPoint().Column)))
			return false
		}
		return true
	})
}

// tsWalk visits root and every node below it in pre-order (source order),
// iteratively, with one TreeCursor, until visit returns false. It replaces
// stack walks that pushed n.Child(i) for each i: n.Child(i) is not O(1) —
// tree-sitter iterates from the first child on every call — so those walks
// were quadratic in a node's child count, and error recovery on n unbalanced
// openers leaves a node with ~n children (N-181: a 4 MiB `[[[…` ran for hours
// before the syntax error was reported).
func tsWalk(root *sitter.Node, visit func(*sitter.Node) bool) {
	cur := sitter.NewTreeCursor(root)
	defer cur.Close()
	for {
		if !visit(cur.CurrentNode()) {
			return
		}
		if cur.GoToFirstChild() {
			continue
		}
		for !cur.GoToNextSibling() {
			if !cur.GoToParent() {
				return
			}
		}
	}
}

// firstBadNode returns the first ERROR or MISSING node in the tree (pre-order,
// source order), so the diagnostic can point at the offending line instead of
// the whole file. Iterative for the same reason as checkNumericLiterals:
// tree-sitter error recovery can leave an arbitrarily deep subtree.
func firstBadNode(root *sitter.Node) *sitter.Node {
	var bad *sitter.Node
	tsWalk(root, func(n *sitter.Node) bool {
		if n.IsError() || n.IsMissing() {
			bad = n
			return false
		}
		return true
	})
	return bad
}

// snippet renders a short, single-line excerpt of the node's source span for
// the diagnostic message.
func (p *parseContext) snippet(n *sitter.Node) string {
	start, end := int(n.StartByte()), int(n.EndByte())
	if start < 0 || end > len(p.source) || start >= end {
		return ""
	}
	text := strings.TrimSpace(string(p.source[start:end]))
	if idx := strings.IndexAny(text, "\r\n"); idx >= 0 {
		text = text[:idx]
	}
	if len(text) > 40 {
		text = text[:40] + "..."
	}
	return text
}

func (p *parseContext) addError(msg string) {
	p.errors = append(p.errors, Diagnostic{Message: msg, Severity: SeverityError})
}

func (p *parseContext) nodeText(node *sitter.Node) string {
	return node.Content(p.source)
}

func (p *parseContext) loc(node *sitter.Node) SourceLocation {
	pos := node.StartPoint()
	return SourceLocation{
		File:   p.fileName,
		Line:   int(pos.Row) + 1,
		Column: int(pos.Column),
	}
}

// ---------------------------------------------------------------------------
// Contract discovery
// ---------------------------------------------------------------------------

func (p *parseContext) findContract(root *sitter.Node) *ContractNode {
	var contract *ContractNode

	for i := 0; i < int(root.ChildCount()); i++ {
		child := root.Child(i)
		if child == nil {
			continue
		}

		if child.Type() == "class_declaration" {
			c := p.tryParseContractClass(child)
			if c != nil {
				if contract != nil {
					p.addOnlyOneContractError(child)
				}
				contract = c
			}
		}
		// Also check export_statement wrapping a class
		if child.Type() == "export_statement" {
			for j := 0; j < int(child.ChildCount()); j++ {
				gc := child.Child(j)
				if gc == nil {
					continue
				}

				if gc.Type() == "class_declaration" {
					c := p.tryParseContractClass(gc)
					if c != nil {
						if contract != nil {
							// Located at `export`, the declaration's first
							// token, as in the TS reference.
							p.addOnlyOneContractError(child)
						}
						contract = c
					}
				}
			}
		}
	}

	return contract
}

// addOnlyOneContractError reports an extra valid contract class at the start
// of its declaration, with the TS reference's diagnostic.
func (p *parseContext) addOnlyOneContractError(decl *sitter.Node) {
	loc := p.loc(decl)
	p.errors = append(p.errors, Diagnostic{
		Message:  "Only one SmartContract subclass is allowed per file",
		Severity: SeverityError,
		Loc:      &loc,
	})
}

func (p *parseContext) tryParseContractClass(node *sitter.Node) *ContractNode {
	// Check if class extends SmartContract
	heritage := p.findChildByType(node, "class_heritage")
	if heritage == nil {
		return nil
	}

	// N-011: the `extends` expression must be EXACTLY a valid base, as in
	// the TS reference (`ext.getExpression().getText()`). A substring match
	// used to accept `extends NotSmartContract` as a SmartContract.
	extends := p.findChildByType(heritage, "extends_clause")
	if extends == nil {
		return nil
	}
	value := extends.ChildByFieldName("value")
	if value == nil {
		return nil
	}
	parentClass := p.nodeText(value)
	switch parentClass {
	case "SmartContract", "StatefulSmartContract", "UnsafeSmartContract":
	default:
		return nil
	}

	// Get class name
	nameNode := p.findChildByType(node, "type_identifier")
	if nameNode == nil {
		nameNode = p.findChildByType(node, "identifier")
	}
	className := "UnnamedContract"
	if nameNode != nil {
		className = p.nodeText(nameNode)
	}

	// Get class body
	body := p.findChildByType(node, "class_body")
	if body == nil {
		p.addError("class has no body")
		return nil
	}

	// Parse properties, constructor, and methods
	var properties []PropertyNode
	var constructor *MethodNode
	var methods []MethodNode
	var methodSpans, propSpans [][2]uint32

	for i := 0; i < int(body.ChildCount()); i++ {
		member := body.Child(i)
		switch member.Type() {
		case "public_field_definition":
			propSpans = append(propSpans, memberCommentSpans(member)...)
			prop := p.parseProperty(member)
			if prop != nil {
				properties = append(properties, *prop)
			}
		case "method_definition":
			name := p.getMethodName(member)
			if name == "constructor" {
				ctor := p.parseConstructor(member)
				constructor = &ctor
			} else {
				methodSpans = append(methodSpans, memberCommentSpans(member)...)
				method := p.parseMethod(member)
				methods = append(methods, method)
			}
		}
	}

	// N-199 (R75): a directive in the class body that no member reads.
	p.reportLostDirectives(body, methodSpans, propSpans)

	if constructor == nil {
		p.addError("contract must have a constructor")
		defaultCtor := MethodNode{
			Name:           "constructor",
			Visibility:     "public",
			SourceLocation: p.loc(node),
		}
		constructor = &defaultCtor
	}

	return &ContractNode{
		Name:        className,
		ParentClass: parentClass,
		Properties:  properties,
		Constructor: *constructor,
		Methods:     methods,
		SourceFile:  p.fileName,
	}
}

// ---------------------------------------------------------------------------
// Properties
// ---------------------------------------------------------------------------

func (p *parseContext) parseProperty(node *sitter.Node) *PropertyNode {
	// public_field_definition contains: accessibility_modifier?, readonly?, property_name, type_annotation?, initializer?
	isReadonly := false
	var nameStr string
	var typeNode TypeNode

	var initializer Expression

	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		switch child.Type() {
		case "readonly":
			isReadonly = true
		case "property_identifier":
			nameStr = p.nodeText(child)
		case "type_annotation":
			typeNode = p.parseTypeAnnotation(child)
		default:
			// SWC tree-sitter may expose the initializer as a child expression node
			if nameStr != "" && typeNode != nil && initializer == nil {
				initializer = p.parseExpression(child)
			}
		}
	}

	if nameStr == "" {
		return nil
	}

	if typeNode == nil {
		p.addError(fmt.Sprintf("property '%s' must have an explicit type annotation", nameStr))
		typeNode = CustomType{Name: "unknown"}
	}

	// Issue #109: `/** @embedAlways */` (or `// @embedAlways`) directive in the
	// field's leading comment trivia opts it out of DCE elimination.
	embedAlways := embedAlwaysDirectiveRE.MatchString(p.leadingCommentText(node))

	return &PropertyNode{
		Name:           nameStr,
		Type:           typeNode,
		Readonly:       isReadonly,
		Initializer:    initializer,
		EmbedAlways:    embedAlways,
		SourceLocation: p.loc(node),
	}
}

// leadingCommentText collects the text of consecutive `comment` sibling nodes
// immediately preceding a class-body member (property / method). tree-sitter
// exposes comments as siblings in the class_body, so a `/** @sighash ... */`
// or `// @embedAlways` directive is the immediately-preceding sibling of the
// member it annotates. Stacked comments are concatenated (mirrors the TS
// reference's JSDoc + leading-trivia scan).
//
// F-282: sibling adjacency alone is not enough — ts-morph's leading-comment
// scan never attaches a comment that shares a line with the PRECEDING
// token (verified directly against ts-morph: that comment is the preceding
// token's own trailing trivia, not this node's leading trivia). Find the
// nearest non-comment previous sibling and stop collecting at (and
// including) the first comment that starts on the same row that sibling
// ends on.
func (p *parseContext) leadingCommentText(node *sitter.Node) string {
	var parts []string
	for _, c := range leadingCommentNodes(node) {
		parts = append(parts, p.nodeText(c))
	}
	return strings.Join(parts, "\n")
}

// leadingCommentNodes returns the comment siblings leadingCommentText reads
// (nearest first). N-199 uses their byte spans to find a directive that no
// member reads.
func leadingCommentNodes(node *sitter.Node) []*sitter.Node {
	var prevNonComment *sitter.Node
	for s := node.PrevSibling(); s != nil; s = s.PrevSibling() {
		if s.Type() != "comment" {
			prevNonComment = s
			break
		}
	}
	var boundaryRow uint32
	hasBoundary := prevNonComment != nil
	if hasBoundary {
		boundaryRow = prevNonComment.EndPoint().Row
	}
	var out []*sitter.Node
	for prev := node.PrevSibling(); prev != nil && prev.Type() == "comment"; prev = prev.PrevSibling() {
		if hasBoundary && prev.StartPoint().Row <= boundaryRow {
			break
		}
		out = append(out, prev)
	}
	return out
}

// memberCommentSpans returns the byte spans of node's leading comments.
func memberCommentSpans(node *sitter.Node) [][2]uint32 {
	var spans [][2]uint32
	for _, c := range leadingCommentNodes(node) {
		spans = append(spans, [2]uint32{c.StartByte(), c.EndByte()})
	}
	return spans
}

// LostDirectiveMsg is the N-199 (R75) diagnostic shared verbatim by all seven
// tiers (TS: lostDirectiveMessage in sighash-directive.ts).
func LostDirectiveMsg(directive string) string {
	target := "property"
	if directive == "@sighash" {
		target = "method"
	}
	return fmt.Sprintf("%s directive is not attached to any %s and would be silently ignored; put the comment on its own line directly above the %s it annotates (a comment that shares a line with the preceding code belongs to that code)", directive, target, target)
}

var sighashMarkerRE = regexp.MustCompile(`@sighash`)

// reportLostDirectives (N-199, user decision R75) refuses a `@sighash` /
// `@embedAlways` marker inside the contract class body that is not in the
// leading comments of a member of the kind that reads it (`@sighash` of a
// method, `@embedAlways` of a property). A comment sharing a line with the
// preceding token never attaches (F-282), so such a directive used to be
// dropped silently. Text outside the class braces is prose and not scanned.
// Mirrors reportLostDirectives in the TS reference (01-parse.ts).
func (p *parseContext) reportLostDirectives(body *sitter.Node, methodSpans, propSpans [][2]uint32) {
	start, end := body.StartByte()+1, body.EndByte()-1
	if end <= start {
		return
	}
	type lost struct {
		pos       int
		directive string
	}
	var found []lost
	scan := func(re *regexp.Regexp, directive string, spans [][2]uint32) {
		for _, m := range re.FindAllIndex(p.source[start:end], -1) {
			pos := uint32(m[0]) + start
			attached := false
			for _, s := range spans {
				if s[0] <= pos && pos < s[1] {
					attached = true
					break
				}
			}
			if !attached {
				found = append(found, lost{int(pos), directive})
			}
		}
	}
	scan(sighashMarkerRE, "@sighash", methodSpans)
	scan(embedAlwaysDirectiveRE, "@embedAlways", propSpans)
	sort.Slice(found, func(i, j int) bool { return found[i].pos < found[j].pos })
	for _, f := range found {
		lineStart := bytes.LastIndexByte(p.source[:f.pos], '\n') + 1
		loc := SourceLocation{File: p.fileName, Line: bytes.Count(p.source[:f.pos], []byte{'\n'}) + 1, Column: f.pos - lineStart}
		p.errors = append(p.errors, Diagnostic{Message: LostDirectiveMsg(f.directive), Severity: SeverityError, Loc: &loc})
	}
}

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

func (p *parseContext) parseConstructor(node *sitter.Node) MethodNode {
	params := p.parseMethodParams(node)
	body := p.parseMethodBody(node)

	return MethodNode{
		Name:           "constructor",
		Params:         params,
		Body:           body,
		Visibility:     "public",
		SourceLocation: p.loc(node),
	}
}

// ---------------------------------------------------------------------------
// Methods
// ---------------------------------------------------------------------------

func (p *parseContext) parseMethod(node *sitter.Node) MethodNode {
	name := p.getMethodName(node)
	params := p.parseMethodParams(node)
	// N-331: the AST keeps no return type, so an unknown name is refused here.
	if rt := p.findChildByType(node, "type_annotation"); rt != nil {
		if d := UnknownReturnTypeDiagnostic(p.parseTypeAnnotation(rt), name, p.loc(node)); d != nil {
			p.errors = append(p.errors, *d)
		}
	}
	body := p.parseMethodBody(node)

	visibility := "private"
	// Check for accessibility modifier
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child.Type() == "accessibility_modifier" {
			modText := p.nodeText(child)
			if modText == "public" {
				visibility = "public"
			}
		}
		// N-050: a static method is not a contract method; `public static`
		// used to get a dispatch selector (an unsigned spend path).
		if child.Type() == "static" {
			loc := p.loc(node)
			p.errors = append(p.errors, Diagnostic{Message: StaticMethodMsg(name), Severity: SeverityError, Loc: &loc})
		}
	}

	// Issue #123: `/** @sighash <FLAGS> */` directive → per-method sighash type.
	sighashType := p.parseSighashOnMethod(node, name, visibility)

	return MethodNode{
		Name:           name,
		Params:         params,
		Body:           body,
		Visibility:     visibility,
		SighashType:    sighashType,
		SourceLocation: p.loc(node),
	}
}

// parseSighashOnMethod detects + parses a `/** @sighash <FLAGS> */` (or
// `// @sighash ...`) directive on a method from its leading comment trivia.
// Returns the numeric sighash type, or nil when no directive is present.
// Pushes an error for a malformed flag list or a directive on a non-public
// method (only public methods are spending entry points, so a `@sighash` on a
// private helper is meaningless). Mirrors the TS parseSighashOnMethod.
func (p *parseContext) parseSighashOnMethod(node *sitter.Node, name, visibility string) *int {
	comments := p.leadingCommentText(node)
	result, present := extractSighashDirective(comments)
	if !present {
		return nil
	}

	// N-039 (R88a): located at the method declaration, like the TS reference.
	loc := p.loc(node)
	if visibility != "public" {
		p.errors = append(p.errors, Diagnostic{Message: fmt.Sprintf(
			"@sighash directive on non-public method '%s' has no effect — only public methods are spending entry points",
			name), Severity: SeverityError, Loc: &loc})
		return nil
	}

	if !result.ok() {
		p.errors = append(p.errors, Diagnostic{Message: fmt.Sprintf("Method '%s': %s", name, result.err), Severity: SeverityError, Loc: &loc})
		return nil
	}
	v := result.value
	return &v
}

func (p *parseContext) getMethodName(node *sitter.Node) string {
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child.Type() == "property_identifier" {
			return p.nodeText(child)
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// Parameters
// ---------------------------------------------------------------------------

func (p *parseContext) parseMethodParams(node *sitter.Node) []ParamNode {
	formalParams := p.findChildByType(node, "formal_parameters")
	if formalParams == nil {
		return nil
	}

	var params []ParamNode
	for i := 0; i < int(formalParams.ChildCount()); i++ {
		child := formalParams.Child(i)
		if child.Type() == "required_parameter" || child.Type() == "optional_parameter" {
			param := p.parseParam(child)
			if param != nil {
				params = append(params, *param)
			}
		}
	}

	return params
}

func (p *parseContext) parseParam(node *sitter.Node) *ParamNode {
	var name string
	var typ TypeNode

	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		switch child.Type() {
		case "identifier":
			name = p.nodeText(child)
		case "type_annotation":
			typ = p.parseTypeAnnotation(child)
		}
	}

	if name == "" {
		return nil
	}

	if typ == nil {
		p.addError(fmt.Sprintf("parameter '%s' must have an explicit type annotation", name))
		typ = CustomType{Name: "unknown"}
	}

	return &ParamNode{Name: name, Type: typ}
}

// ---------------------------------------------------------------------------
// Type annotations
// ---------------------------------------------------------------------------

func (p *parseContext) parseTypeAnnotation(node *sitter.Node) TypeNode {
	// type_annotation: ":" type
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child == nil {
			continue
		}

		if child.Type() != ":" {
			return p.parseTypeExpr(child)
		}
	}
	return CustomType{Name: "unknown"}
}

func (p *parseContext) parseTypeExpr(node *sitter.Node) TypeNode {
	text := p.nodeText(node)

	switch node.Type() {
	case "predefined_type":
		// bigint, boolean, void, etc.
		switch text {
		case "bigint":
			return PrimitiveType{Name: "bigint"}
		case "boolean":
			return PrimitiveType{Name: "boolean"}
		case "void":
			return PrimitiveType{Name: "void"}
		case "number":
			p.addError("use 'bigint' instead of 'number' in Rúnar contracts")
			return PrimitiveType{Name: "bigint"}
		}
		return CustomType{Name: text}

	case "generic_type":
		// FixedArray<T, N>
		return p.parseGenericType(node)

	case "type_identifier":
		fallthrough
	default:
		// Try text match for primitive types, after resolving alternative
		// spellings (N-104: `Sha256Digest` is runar-lang's name for `Sha256`,
		// and every other surface parser in this package already maps it).
		if canonical := ResolveTypeAlias(text); IsPrimitiveType(canonical) {
			return PrimitiveType{Name: canonical}
		}
		return CustomType{Name: text}
	}
}

func (p *parseContext) parseGenericType(node *sitter.Node) TypeNode {
	// generic_type: type_identifier type_arguments
	nameNode := p.findChildByType(node, "type_identifier")
	if nameNode == nil {
		return CustomType{Name: p.nodeText(node)}
	}

	typeName := p.nodeText(nameNode)
	if typeName != "FixedArray" {
		return CustomType{Name: typeName}
	}

	// Find type_arguments
	argsNode := p.findChildByType(node, "type_arguments")
	if argsNode == nil {
		p.addError("FixedArray requires exactly 2 type arguments")
		return CustomType{Name: typeName}
	}

	// Collect the type arguments (skip punctuation)
	var typeArgs []*sitter.Node
	for i := 0; i < int(argsNode.ChildCount()); i++ {
		child := argsNode.Child(i)
		if child == nil {
			continue
		}

		t := child.Type()
		if t != "<" && t != ">" && t != "," {
			typeArgs = append(typeArgs, child)
		}
	}

	if len(typeArgs) != 2 {
		p.addError("FixedArray requires exactly 2 type arguments")
		return CustomType{Name: typeName}
	}

	elemType := p.parseTypeExpr(typeArgs[0])
	sizeText := p.nodeText(typeArgs[1])
	size, err := strconv.Atoi(sizeText)
	if err != nil || size < 0 {
		p.addError(fmt.Sprintf("FixedArray size must be a positive integer literal, got '%s'", sizeText))
		return CustomType{Name: typeName}
	}

	return FixedArrayType{Element: elemType, Length: size}
}

// ---------------------------------------------------------------------------
// Method body / statements
// ---------------------------------------------------------------------------

func (p *parseContext) parseMethodBody(node *sitter.Node) []Statement {
	body := p.findChildByType(node, "statement_block")
	if body == nil {
		return nil
	}
	return p.parseStatements(body)
}

func (p *parseContext) parseStatements(block *sitter.Node) []Statement {
	var stmts []Statement
	for i := 0; i < int(block.ChildCount()); i++ {
		child := block.Child(i)
		stmt := p.parseStatement(child)
		if stmt != nil {
			stmts = append(stmts, stmt)
		}
	}
	return stmts
}

func (p *parseContext) parseBlockStatements(node *sitter.Node) []Statement {
	if node.Type() == "statement_block" {
		return p.parseStatements(node)
	}
	// else_clause wraps a statement_block or single statement
	if node.Type() == "else_clause" {
		for i := 0; i < int(node.ChildCount()); i++ {
			child := node.Child(i)
			if child.Type() == "statement_block" {
				return p.parseStatements(child)
			}
			if child.Type() == "if_statement" {
				stmt := p.parseIfStatement(child)
				if stmt != nil {
					return []Statement{stmt}
				}
			}
		}
		// Fallback: try parsing the last non-keyword child as a statement
		for i := int(node.ChildCount()) - 1; i >= 0; i-- {
			child := node.Child(i)
			if child.Type() != "else" {
				stmt := p.parseStatement(child)
				if stmt != nil {
					return []Statement{stmt}
				}
			}
		}
		return nil
	}
	// Single statement (no braces)
	stmt := p.parseStatement(node)
	if stmt != nil {
		return []Statement{stmt}
	}
	return nil
}

func (p *parseContext) parseStatement(node *sitter.Node) Statement {
	errsBefore := len(p.errors)
	var stmt Statement
	switch node.Type() {
	case "lexical_declaration":
		stmt = p.parseVariableDecl(node)

	case "expression_statement":
		stmt = p.parseExpressionStatement(node)

	case "if_statement":
		stmt = p.parseIfStatement(node)

	case "for_statement":
		stmt = p.parseForStatement(node)

	case "return_statement":
		stmt = p.parseReturnStatement(node)

	case "{", "}", "(", ")", ";", ",", "comment":
		return nil

	default:
		// F-064: every other node is a statement Rúnar does not support
		// (while, switch, try, a bare block, `;`, ...). Returning nil here
		// used to drop it silently; refuse it with the TS reference's
		// diagnostic instead.
		loc := p.loc(node)
		p.errors = append(p.errors, MakeDiagnostic(
			fmt.Sprintf("Unsupported statement kind: %s", p.tsStatementKindName(node)),
			SeverityError, &loc))
		return nil
	}
	// F-064 backstop: callers drop a nil statement, so a supported statement
	// kind whose operands did not parse (e.g. `assert(a), assert(b);` — the
	// expression parser returns nil for a sequence_expression) must not vanish
	// without a diagnostic.
	if stmt == nil && len(p.errors) == errsBefore {
		loc := p.loc(node)
		p.errors = append(p.errors, MakeDiagnostic(
			fmt.Sprintf("Unsupported expression in statement: '%s'", p.snippet(node)),
			SeverityError, &loc))
	}
	return stmt
}

// tsStatementKindName maps a tree-sitter statement node type onto the
// ts.SyntaxKind name the TS reference reports for the same statement, so every
// tier emits one shared "Unsupported statement kind: <name>" diagnostic.
func (p *parseContext) tsStatementKindName(node *sitter.Node) string {
	switch node.Type() {
	case "statement_block":
		return "Block"
	case "for_in_statement":
		for i := 0; i < int(node.ChildCount()); i++ {
			if node.Child(i).Type() == "of" {
				return "ForOfStatement"
			}
		}
		return "ForInStatement"
	}
	// snake_case -> PascalCase: while_statement -> WhileStatement,
	// class_declaration -> ClassDeclaration, empty_statement -> EmptyStatement.
	parts := strings.Split(node.Type(), "_")
	for i, part := range parts {
		if part != "" {
			parts[i] = strings.ToUpper(part[:1]) + part[1:]
		}
	}
	return strings.Join(parts, "")
}

// ---------------------------------------------------------------------------
// Variable declarations
// ---------------------------------------------------------------------------

func (p *parseContext) parseVariableDecl(node *sitter.Node) Statement {
	// lexical_declaration: (const|let) variable_declarator
	isConst := false
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child.Type() == "const" {
			isConst = true
		}
	}

	// W5: a declaration list declares exactly one variable.
	//
	// `findChildByType` returns the FIRST `variable_declarator` and ignores
	// every later one. This tier did not even warn about it -- the reference
	// tier at least emitted a warning in statement position, which `compile()`
	// does not stop on, while a for-initializer emitted nothing anywhere.
	//
	// What is lost is not always a value. Measured on the reference tier, a
	// private helper carrying the contract's guard, called from a
	// for-initializer's second declarator, compiled to nothing:
	//
	//	for (let i = 0n, k = this.guard(x); i < 2n; i++)   hex 008b519c77
	//	for (let i = 0n;                    i < 2n; i++)   hex 008b519c77
	//
	// Byte-identical. `guard` asserts `x > 100n` and @bsv/sdk
	// Spend.validate() ACCEPTED verify(5n). `k` is never named again, so no
	// later pass can catch this as an undeclared variable; only the effect is
	// lost. Both this tier's sites route through here, since
	// parseVariableDeclFromForInit calls parseVariableDecl.
	//
	// The subset is one declarator per statement (spec/grammar.md's
	// VariableDeclaration production), and python/zig/ruby/java already refuse
	// the shape at the comma. The diagnostic text is shared verbatim with the
	// other tiers that can see a declaration list.
	if n := p.countChildrenByType(node, "variable_declarator"); n > 1 {
		p.addError(extraDeclaratorError(n))
	}

	// Find variable_declarator
	declarator := p.findChildByType(node, "variable_declarator")
	if declarator == nil {
		return nil
	}

	var name string
	var typeNode TypeNode
	var initExpr Expression
	// The declarator has the form `<name> [type_annotation] [= <init>]`.
	// Once we've walked past the `=` token, remaining children belong to the
	// initializer (including bare identifiers like `const x = b`, which would
	// otherwise get mis-parsed as re-declaring `name`).
	seenEq := false

	for i := 0; i < int(declarator.ChildCount()); i++ {
		child := declarator.Child(i)
		switch child.Type() {
		case "=":
			seenEq = true
		case "identifier":
			if !seenEq {
				name = p.nodeText(child)
			} else {
				if expr := p.parseExpression(child); expr != nil {
					initExpr = expr
				}
			}
		case "type_annotation":
			typeNode = p.parseTypeAnnotation(child)
		default:
			if child.Type() != ";" && child.Type() != ":" {
				// Try to parse as init expression
				expr := p.parseExpression(child)
				if expr != nil {
					initExpr = expr
				}
			}
		}
	}

	if name == "" {
		return nil
	}
	if initExpr == nil {
		initExpr = BigIntLiteral{Value: big.NewInt(0)}
	}

	return VariableDeclStmt{
		Name:           name,
		Type:           typeNode,
		Mutable:        !isConst,
		Init:           initExpr,
		SourceLocation: p.loc(node),
	}
}

// ---------------------------------------------------------------------------
// Expression statements (including assignments)
// ---------------------------------------------------------------------------

func (p *parseContext) parseExpressionStatement(node *sitter.Node) Statement {
	loc := p.loc(node)

	// expression_statement contains a single expression child
	var exprNode *sitter.Node
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child.Type() != ";" {
			exprNode = child
			break
		}
	}

	if exprNode == nil {
		return nil
	}

	// Check for assignment: a = b, this.x = b, compound assignments
	if exprNode.Type() == "assignment_expression" {
		return p.parseAssignment(exprNode, loc)
	}

	// Check for augmented_assignment_expression (+=, -=, etc.)
	if exprNode.Type() == "augmented_assignment_expression" {
		return p.parseAugmentedAssignment(exprNode, loc)
	}

	// Regular expression statement
	expr := p.parseExpression(exprNode)
	if expr == nil {
		return nil
	}
	return ExpressionStmt{Expr: expr, SourceLocation: loc}
}

func (p *parseContext) parseAssignment(node *sitter.Node, loc SourceLocation) Statement {
	// assignment_expression: left "=" right
	leftNode := node.ChildByFieldName("left")
	rightNode := node.ChildByFieldName("right")

	if leftNode == nil || rightNode == nil {
		// fallback: parse children manually
		if node.ChildCount() >= 3 {
			leftNode = node.Child(0)
			rightNode = node.Child(2)
		}
	}

	if leftNode == nil || rightNode == nil {
		return nil
	}

	target := p.parseExpression(leftNode)
	value := p.parseExpression(rightNode)
	if target == nil || value == nil {
		return nil
	}

	return AssignmentStmt{Target: target, Value: value, SourceLocation: loc}
}

func (p *parseContext) parseAugmentedAssignment(node *sitter.Node, loc SourceLocation) Statement {
	// augmented_assignment_expression: left op right
	leftNode := node.ChildByFieldName("left")
	rightNode := node.ChildByFieldName("right")
	opNode := node.ChildByFieldName("operator")

	if leftNode == nil || rightNode == nil {
		// fallback to child indices
		if node.ChildCount() >= 3 {
			leftNode = node.Child(0)
			opNode = node.Child(1)
			rightNode = node.Child(2)
		}
	}

	if leftNode == nil || rightNode == nil {
		return nil
	}

	opText := ""
	if opNode != nil {
		opText = p.nodeText(opNode)
	}

	// Map compound ops to binary ops
	var binOp string
	switch opText {
	case "+=":
		binOp = "+"
	case "-=":
		binOp = "-"
	case "*=":
		binOp = "*"
	case "/=":
		binOp = "/"
	case "%=":
		binOp = "%"
	default:
		// Same set and diagnostic as the TS reference (01-parse.ts
		// parseExpressionStatement): any other compound operator is refused.
		opLoc := loc
		p.errors = append(p.errors, MakeDiagnostic(
			fmt.Sprintf("Unsupported binary operator: '%s'", opText), SeverityError, &opLoc))
		return nil
	}

	target := p.parseExpression(leftNode)
	right := p.parseExpression(rightNode)
	if target == nil || right == nil {
		return nil
	}

	// Desugar: a += b -> a = a + b
	value := BinaryExpr{Op: binOp, Left: target, Right: right}
	targetAgain := p.parseExpression(leftNode)

	return AssignmentStmt{Target: targetAgain, Value: value, SourceLocation: loc}
}

// ---------------------------------------------------------------------------
// If statements
// ---------------------------------------------------------------------------

func (p *parseContext) parseIfStatement(node *sitter.Node) Statement {
	loc := p.loc(node)

	condNode := node.ChildByFieldName("condition")
	consequentNode := node.ChildByFieldName("consequence")
	alternativeNode := node.ChildByFieldName("alternative")

	var condition Expression
	if condNode != nil {
		condition = p.parseParenExpression(condNode)
	}
	if condition == nil {
		condition = BoolLiteral{Value: false}
	}

	var thenStmts []Statement
	if consequentNode != nil {
		thenStmts = p.parseBlockStatements(consequentNode)
	}

	var elseStmts []Statement
	if alternativeNode != nil {
		elseStmts = p.parseBlockStatements(alternativeNode)
	}

	return IfStmt{
		Condition:      condition,
		Then:           thenStmts,
		Else:           elseStmts,
		SourceLocation: loc,
	}
}

// ---------------------------------------------------------------------------
// For statements
// ---------------------------------------------------------------------------

func (p *parseContext) parseForStatement(node *sitter.Node) Statement {
	loc := p.loc(node)

	initNode := node.ChildByFieldName("initializer")
	condNode := node.ChildByFieldName("condition")
	updateNode := node.ChildByFieldName("increment")
	bodyNode := node.ChildByFieldName("body")

	// Parse initializer
	var initStmt VariableDeclStmt
	if initNode != nil {
		stmt := p.parseStatement(initNode)
		if vd, ok := stmt.(VariableDeclStmt); ok {
			initStmt = vd
		} else {
			// Try parsing as a lexical_declaration or variable_declaration
			s := p.parseVariableDeclFromForInit(initNode)
			if s != nil {
				initStmt = *s
			} else {
				// N-306: the TS reference's parseForStatement refuses a
				// non-declaration for-initializer with this diagnostic.
				// This branch used to silently substitute a synthetic
				// `_i = 0` for the real initializer expression, discarding
				// it with no error.
				initErrLoc := loc
				p.errors = append(p.errors, MakeDiagnostic("For loop must have a variable declaration initializer", SeverityError, &initErrLoc))
				initStmt = VariableDeclStmt{
					Name:           "_i",
					Mutable:        true,
					Init:           BigIntLiteral{Value: big.NewInt(0)},
					SourceLocation: loc,
				}
			}
		}
	} else {
		initStmt = VariableDeclStmt{
			Name:           "_i",
			Mutable:        true,
			Init:           BigIntLiteral{Value: big.NewInt(0)},
			SourceLocation: loc,
		}
	}

	// Parse condition
	var condition Expression
	if condNode == nil || condNode.Type() == "empty_statement" {
		// N-135: the TS reference refuses an empty condition slot (which
		// tree-sitter hands over as an `empty_statement` node); the `false`
		// placeholder below only keeps the AST well-formed.
		condLoc := loc
		p.errors = append(p.errors, MakeDiagnostic("For loop must have a condition", SeverityError, &condLoc))
	} else {
		// The condition might be wrapped in an expression_statement node
		if condNode.Type() == "expression_statement" && condNode.ChildCount() > 0 {
			condition = p.parseExpression(condNode.Child(0))
		} else {
			condition = p.parseExpression(condNode)
		}
	}
	if condition == nil {
		condition = BoolLiteral{Value: false}
	}

	// Parse update
	var update Statement
	if updateNode != nil {
		update = p.parseForUpdate(updateNode, loc)
	} else {
		// N-132: the TS reference refuses an empty update slot; the
		// placeholder below only keeps the AST well-formed.
		updLoc := loc
		p.errors = append(p.errors, MakeDiagnostic("For loop must have an update expression", SeverityError, &updLoc))
		update = ExpressionStmt{Expr: BigIntLiteral{Value: big.NewInt(0)}, SourceLocation: loc}
	}

	// Parse body
	var body []Statement
	if bodyNode != nil {
		body = p.parseBlockStatements(bodyNode)
	}

	return ForStmt{
		Init:           initStmt,
		Condition:      condition,
		Update:         update,
		Body:           body,
		SourceLocation: loc,
	}
}

func (p *parseContext) parseVariableDeclFromForInit(node *sitter.Node) *VariableDeclStmt {
	// For-loop initializers might be directly a variable declarator type
	nodeType := node.Type()

	if nodeType == "lexical_declaration" {
		stmt := p.parseVariableDecl(node)
		if vd, ok := stmt.(VariableDeclStmt); ok {
			return &vd
		}
	}

	// Walk children looking for the declaration
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child.Type() == "lexical_declaration" {
			stmt := p.parseVariableDecl(child)
			if vd, ok := stmt.(VariableDeclStmt); ok {
				return &vd
			}
		}
	}

	return nil
}

func (p *parseContext) parseForUpdate(node *sitter.Node, loc SourceLocation) Statement {
	// N-133: the TS reference's parseForUpdate accepts only `++`/`--` here
	// and hands everything else to parseExpression, which refuses an
	// assignment (`i = i + 1n`, `i += 1n`) or a comma sequence with
	// "Unsupported binary operator: '<op>'". parseExpression's
	// assignment / sequence arms emit that same diagnostic, so route every
	// update through it rather than desugaring assignments into statements
	// (which compiled the unit-step spellings on this tier alone).
	expr := p.parseExpression(node)
	if expr == nil {
		return ExpressionStmt{Expr: BigIntLiteral{Value: big.NewInt(0)}, SourceLocation: loc}
	}
	return ExpressionStmt{Expr: expr, SourceLocation: loc}
}

// ---------------------------------------------------------------------------
// Return statements
// ---------------------------------------------------------------------------

func (p *parseContext) parseReturnStatement(node *sitter.Node) Statement {
	loc := p.loc(node)

	var value Expression
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child.Type() != "return" && child.Type() != ";" {
			value = p.parseExpression(child)
			break
		}
	}

	return ReturnStmt{Value: value, SourceLocation: loc}
}

// ---------------------------------------------------------------------------
// Expressions
// ---------------------------------------------------------------------------

func (p *parseContext) parseExpression(node *sitter.Node) Expression {
	if node == nil {
		return nil
	}

	switch node.Type() {
	case "binary_expression":
		return p.parseBinaryExpression(node)

	case "unary_expression":
		return p.parseUnaryExpression(node)

	case "update_expression":
		return p.parseUpdateExpression(node)

	case "call_expression":
		return p.parseCallExpression(node)

	case "member_expression":
		return p.parseMemberExpression(node)

	case "subscript_expression":
		return p.parseSubscriptExpression(node)

	case "array":
		// TypeScript array literal: [a, b, c]. Match the dedicated
		// per-format parsers (sol, move, rust, python, zig, ruby, java)
		// which all emit an ArrayLiteralExpr so checkMultiSig and other
		// builtins that consume Sig[]/PubKey[] type-check across all
		// 7 compilers. Anything that recurses into a child here must
		// itself be a real expression — tree-sitter's "array" node
		// children are punctuation tokens ("[", "]", ",") and inner
		// expressions interleaved; filter to the parseable nodes.
		elements := []Expression{}
		for i := 0; i < int(node.ChildCount()); i++ {
			child := node.Child(i)
			t := child.Type()
			if t == "[" || t == "]" || t == "," {
				continue
			}
			if expr := p.parseExpression(child); expr != nil {
				elements = append(elements, expr)
			}
		}
		return ArrayLiteralExpr{Elements: elements}

	case "identifier":
		name := p.nodeText(node)
		if name == "true" {
			return BoolLiteral{Value: true}
		}
		if name == "false" {
			return BoolLiteral{Value: false}
		}
		return Identifier{Name: name}

	case "number":
		text := p.nodeText(node)
		// BigInt literals end with 'n'
		if strings.HasSuffix(text, "n") {
			text = text[:len(text)-1]
		}
		// Parse with big.Int for arbitrary-precision support.
		bi := new(big.Int)
		if _, ok := bi.SetString(text, 0); !ok {
			// Retry with decimal base for edge cases
			bi2 := new(big.Int)
			if _, ok2 := bi2.SetString(text, 10); !ok2 {
				p.addError(fmt.Sprintf("invalid integer literal: %s", text))
				return BigIntLiteral{Value: big.NewInt(0)}
			}
			return BigIntLiteral{Value: bi2}
		}
		return BigIntLiteral{Value: bi}

	case "true":
		return BoolLiteral{Value: true}

	case "false":
		return BoolLiteral{Value: false}

	case "string":
		return p.parseStringLiteral(node)

	case "template_string":
		// Only a NoSubstitutionTemplateLiteral is a ByteString literal; one
		// with `${...}` is a TemplateExpression the TS reference refuses.
		if p.findChildByType(node, "template_substitution") != nil {
			return p.unsupportedExpr(node, "TemplateExpression")
		}
		text := p.nodeText(node)
		// Remove backticks
		if len(text) >= 2 {
			text = text[1 : len(text)-1]
		}
		return ByteStringLiteral{Value: text}

	case "ternary_expression":
		return p.parseTernaryExpression(node)

	case "parenthesized_expression":
		return p.parseParenExpression(node)

	case "this":
		return Identifier{Name: "this"}

	case "super":
		return Identifier{Name: "super"}

	case "as_expression":
		// Type assertion: ignore type, parse expression
		return p.parseExpression(node.Child(0))

	case "non_null_expression":
		// Non-null assertion: parse inner expression
		return p.parseExpression(node.Child(0))

	case "type_assertion":
		// <Type>expr -- parse the expression
		for i := 0; i < int(node.ChildCount()); i++ {
			child := node.Child(i)
			if child.Type() != "type_arguments" && child.Type() != "<" && child.Type() != ">" {
				expr := p.parseExpression(child)
				if expr != nil {
					return expr
				}
			}
		}
		return nil

	case "undefined":
		// ts-morph parses `undefined` as an Identifier, which the typechecker
		// then refuses ("Undefined variable 'undefined'"). tree-sitter gives it
		// its own node type.
		return Identifier{Name: "undefined"}

	case "sequence_expression":
		// `a, b` is a BinaryExpression with a CommaToken in the TS reference.
		return p.unsupportedBinaryOp(node, ",")

	case "assignment_expression", "augmented_assignment_expression":
		// Assignments are statements only (parseExpressionStatement intercepts
		// them first); in expression position -- including a for-update -- the TS
		// reference sees a BinaryExpression with an assignment operator.
		op := "="
		if opNode := node.ChildByFieldName("operator"); opNode != nil {
			op = p.nodeText(opNode)
		}
		return p.unsupportedBinaryOp(node, op)

	default:
		// N-052: this arm used to return nil, which the binary / unary / update
		// parsers turned into BigIntLiteral(0) — `(x, 0n)`, an arrow function or
		// `null` compiled as 0. Anonymous tokens and comments are not
		// expressions and still yield nil for the callers that skip them;
		// every named node is an expression the TS reference refuses.
		if !node.IsNamed() || node.Type() == "comment" {
			return nil
		}
		return p.unsupportedExpr(node, tsExpressionKindName(node.Type()))
	}
}

// tsExpressionKindName maps a tree-sitter expression node type onto the
// ts.SyntaxKind name the TS reference reports for the same expression, so the
// tiers share one "Unsupported expression kind: <name>" diagnostic.
func tsExpressionKindName(t string) string {
	switch t {
	case "arrow_function":
		return "ArrowFunction"
	case "function_expression", "function", "generator_function":
		return "FunctionExpression"
	case "class":
		return "ClassExpression"
	case "new_expression":
		return "NewExpression"
	case "null":
		return "NullKeyword"
	case "regex":
		return "RegularExpressionLiteral"
	case "satisfies_expression":
		return "SatisfiesExpression"
	case "await_expression":
		return "AwaitExpression"
	case "yield_expression":
		return "YieldExpression"
	case "object":
		return "ObjectLiteralExpression"
	case "spread_element":
		return "SpreadElement"
	case "template_string":
		return "TemplateExpression"
	case "meta_property":
		return "MetaProperty"
	case "instantiation_expression":
		return "ExpressionWithTypeArguments"
	default:
		return t
	}
}

// unsupportedExpr emits the TS reference's
// "Unsupported expression kind: <Kind> ('<text>')" diagnostic and, like the
// reference, returns a 0 placeholder so parsing can continue and report more.
func (p *parseContext) unsupportedExpr(node *sitter.Node, kind string) Expression {
	text := []rune(p.nodeText(node))
	if len(text) > 50 {
		text = text[:50]
	}
	loc := p.loc(node)
	p.errors = append(p.errors, MakeDiagnostic(
		fmt.Sprintf("Unsupported expression kind: %s ('%s')", kind, string(text)),
		SeverityError, &loc))
	return BigIntLiteral{Value: big.NewInt(0)}
}

// unsupportedBinaryOp emits the TS reference's "Unsupported binary operator"
// diagnostic at the operator token.
func (p *parseContext) unsupportedBinaryOp(node *sitter.Node, op string) Expression {
	loc := p.loc(node)
	for i := 0; i < int(node.ChildCount()); i++ {
		if c := node.Child(i); !c.IsNamed() && p.nodeText(c) == op {
			loc = p.loc(c)
			break
		}
	}
	p.errors = append(p.errors, MakeDiagnostic(
		fmt.Sprintf("Unsupported binary operator: '%s'", op), SeverityError, &loc))
	return BigIntLiteral{Value: big.NewInt(0)}
}

// tsBinaryOps is the TS reference's OP_MAP (01-parse.ts parseBinaryExpression)
// after the `==` / `!=` mapping.
var tsBinaryOps = map[string]bool{
	"+": true, "-": true, "*": true, "/": true, "%": true,
	"===": true, "!==": true, "<": true, "<=": true, ">": true, ">=": true,
	"&&": true, "||": true, "&": true, "|": true, "^": true, "<<": true, ">>": true,
}

func (p *parseContext) parseBinaryExpression(node *sitter.Node) Expression {
	leftNode := node.ChildByFieldName("left")
	rightNode := node.ChildByFieldName("right")
	opNode := node.ChildByFieldName("operator")

	if leftNode == nil || rightNode == nil {
		// Fallback: children by index
		if node.ChildCount() >= 3 {
			leftNode = node.Child(0)
			opNode = node.Child(1)
			rightNode = node.Child(2)
		}
	}

	if leftNode == nil || rightNode == nil {
		return BigIntLiteral{Value: big.NewInt(0)}
	}

	left := p.parseExpression(leftNode)
	right := p.parseExpression(rightNode)
	if left == nil {
		left = BigIntLiteral{Value: big.NewInt(0)}
	}
	if right == nil {
		right = BigIntLiteral{Value: big.NewInt(0)}
	}

	op := ""
	if opNode != nil {
		op = p.nodeText(opNode)
	}

	// Map == to ===, != to !==
	if op == "==" {
		op = "==="
	}
	if op == "!=" {
		op = "!=="
	}
	if !tsBinaryOps[op] {
		return p.unsupportedBinaryOp(node, op)
	}

	return BinaryExpr{Op: op, Left: left, Right: right}
}

func (p *parseContext) parseUnaryExpression(node *sitter.Node) Expression {
	opNode := node.ChildByFieldName("operator")
	argNode := node.ChildByFieldName("argument")

	if opNode == nil || argNode == nil {
		// Fallback
		if node.ChildCount() >= 2 {
			opNode = node.Child(0)
			argNode = node.Child(1)
		}
	}

	if argNode == nil {
		return BigIntLiteral{Value: big.NewInt(0)}
	}

	operand := p.parseExpression(argNode)
	if operand == nil {
		operand = BigIntLiteral{Value: big.NewInt(0)}
	}

	op := ""
	if opNode != nil {
		op = p.nodeText(opNode)
	}

	// The TS reference's UNARY_MAP is `!`, `-`, `~`; ts-morph parses `typeof`,
	// `void` and `delete` as their own expression kinds.
	switch op {
	case "!", "-", "~":
	case "typeof":
		return p.unsupportedExpr(node, "TypeOfExpression")
	case "void":
		return p.unsupportedExpr(node, "VoidExpression")
	case "delete":
		return p.unsupportedExpr(node, "DeleteExpression")
	default:
		loc := p.loc(node)
		p.errors = append(p.errors, MakeDiagnostic(
			"Unsupported unary prefix operator", SeverityError, &loc))
		return BigIntLiteral{Value: big.NewInt(0)}
	}

	return UnaryExpr{Op: op, Operand: operand}
}

func (p *parseContext) parseUpdateExpression(node *sitter.Node) Expression {
	// update_expression: i++ or ++i or i-- or --i
	argNode := node.ChildByFieldName("argument")
	opNode := node.ChildByFieldName("operator")

	if argNode == nil {
		// Fallback: figure out prefix vs postfix by child order
		for i := 0; i < int(node.ChildCount()); i++ {
			child := node.Child(i)
			text := p.nodeText(child)
			if text == "++" || text == "--" {
				opNode = child
			} else {
				argNode = child
			}
		}
	}

	if argNode == nil {
		return BigIntLiteral{Value: big.NewInt(0)}
	}

	operand := p.parseExpression(argNode)
	if operand == nil {
		operand = BigIntLiteral{Value: big.NewInt(0)}
	}

	opText := ""
	if opNode != nil {
		opText = p.nodeText(opNode)
	}

	// Determine prefix vs postfix: if operator comes before argument
	prefix := false
	if opNode != nil {
		prefix = opNode.StartByte() < argNode.StartByte()
	}

	if opText == "++" {
		return IncrementExpr{Operand: operand, Prefix: prefix}
	}
	return DecrementExpr{Operand: operand, Prefix: prefix}
}

func (p *parseContext) parseCallExpression(node *sitter.Node) Expression {
	funcNode := node.ChildByFieldName("function")
	argsNode := node.ChildByFieldName("arguments")

	if funcNode == nil {
		// Fallback
		funcNode = node.Child(0)
	}

	if funcNode == nil {
		return BigIntLiteral{Value: big.NewInt(0)}
	}

	// tree-sitter models a tagged template (foo`ab`) as a call whose
	// arguments are a template_string.
	if argsNode != nil && argsNode.Type() == "template_string" {
		return p.unsupportedExpr(node, "TaggedTemplateExpression")
	}

	// Special-case asm({ body, in_arity?, out_arity? }) — normalise the
	// object-literal argument into a CallExpr with three positional args
	// (body, in_arity, out_arity) so downstream passes only have to know
	// how to walk a CallExpr. Both the hex-string body form and the
	// array-form body are supported; the array form is encoded to a hex
	// string at parse time so all downstream passes see identical IR.
	// The optional generic type argument asm<T>(...) flags the
	// expression form, captured on CallExpr.AsmReturnType.
	if funcNode.Type() == "identifier" && p.nodeText(funcNode) == "asm" {
		return p.parseAsmCall(node, argsNode)
	}

	callee := p.parseExpression(funcNode)
	if callee == nil {
		callee = Identifier{Name: "unknown"}
	}

	var args []Expression
	if argsNode != nil {
		args = p.parseCallArgs(argsNode)
	}

	return CallExpr{Callee: callee, Args: args}
}

// parseAsmCall decodes an asm({ body, in_arity?, out_arity? }) call into a
// CallExpr whose positional args are
//
//	[ByteStringLiteral(body), BigIntLiteral(in_arity), BigIntLiteral(out_arity)].
//
// Two surface body shapes are accepted:
//   - Hex string literal:  body: '76a90088ac'
//   - Array of opcode names / push() calls:
//     body: [OP_DUP, OP_HASH160, push('1234abcd'), OP_EQUALVERIFY]
//     Each element is encoded to its byte representation at parse time,
//     so the resulting IR is byte-identical to the equivalent hex body.
//
// The optional generic type argument asm<T>({...}) marks the expression
// form; the captured T is stashed on CallExpr.AsmReturnType. T must be one
// of bigint, boolean, or ByteString.
//
// On malformed input we still return a syntactically valid CallExpr so
// later passes can produce additional diagnostics without crashing.
func (p *parseContext) parseAsmCall(callNode, argsNode *sitter.Node) Expression {
	calleeExpr := Identifier{Name: "asm"}

	// Capture the generic type argument asm<T>({...}) if present, BEFORE
	// arg-shape diagnostics so the expression form still records its
	// return type even when other args are malformed.
	asmReturnType := p.parseAsmGenericTypeArg(callNode)

	// Collect the call arguments (skip punctuation).
	var callArgs []*sitter.Node
	if argsNode != nil {
		for i := 0; i < int(argsNode.ChildCount()); i++ {
			child := argsNode.Child(i)
			t := child.Type()
			if t == "(" || t == ")" || t == "," {
				continue
			}
			callArgs = append(callArgs, child)
		}
	}

	if len(callArgs) != 1 {
		p.addError(fmt.Sprintf("asm() expects exactly one object-literal argument { body, in_arity?, out_arity? }, got %d arguments", len(callArgs)))
		return CallExpr{Callee: calleeExpr, Args: nil, AsmReturnType: asmReturnType}
	}

	objNode := callArgs[0]
	if objNode.Type() != "object" {
		p.addError(fmt.Sprintf("asm() argument must be an object literal { body: '<hex>', in_arity?: <int>, out_arity?: <int> }, got '%s'", objNode.Type()))
		return CallExpr{Callee: calleeExpr, Args: nil, AsmReturnType: asmReturnType}
	}

	var bodyExpr Expression
	var inArityExpr Expression
	var outArityExpr Expression

	for i := 0; i < int(objNode.ChildCount()); i++ {
		prop := objNode.Child(i)
		if prop.Type() != "pair" {
			continue
		}
		keyNode := prop.ChildByFieldName("key")
		valNode := prop.ChildByFieldName("value")
		if keyNode == nil || valNode == nil {
			continue
		}
		key := p.nodeText(keyNode)

		switch key {
		case "body":
			if valNode.Type() == "string" || valNode.Type() == "template_string" {
				raw := p.nodeText(valNode)
				if len(raw) >= 2 {
					raw = raw[1 : len(raw)-1]
				}
				bodyExpr = ByteStringLiteral{Value: raw}
			} else if valNode.Type() == "array" {
				encoded := p.encodeAsmArrayBody(valNode)
				bodyExpr = ByteStringLiteral{Value: encoded}
			} else {
				p.addError(fmt.Sprintf("asm() body must be a hex string literal or an array of opcode names / push() calls; got '%s'.", valNode.Type()))
				bodyExpr = ByteStringLiteral{Value: ""}
			}
		case "in_arity":
			if parsed, ok := p.parseArityLiteral(valNode, "in_arity"); ok {
				inArityExpr = BigIntLiteral{Value: big.NewInt(parsed)}
			}
		case "out_arity":
			if parsed, ok := p.parseArityLiteral(valNode, "out_arity"); ok {
				outArityExpr = BigIntLiteral{Value: big.NewInt(parsed)}
			}
		default:
			p.addError(fmt.Sprintf("asm() does not accept the '%s' field; valid fields are 'body', 'in_arity', 'out_arity'.", key))
		}
	}

	if bodyExpr == nil {
		p.addError("asm() requires a 'body' field with a hex string literal value")
		bodyExpr = ByteStringLiteral{Value: ""}
	}
	// Defaults: in_arity=0, out_arity=1. The out_arity=1 default reflects
	// the public-method-must-terminate-truthy invariant.
	if inArityExpr == nil {
		inArityExpr = BigIntLiteral{Value: big.NewInt(0)}
	}
	if outArityExpr == nil {
		outArityExpr = BigIntLiteral{Value: big.NewInt(1)}
	}

	return CallExpr{
		Callee:        calleeExpr,
		Args:          []Expression{bodyExpr, inArityExpr, outArityExpr},
		AsmReturnType: asmReturnType,
	}
}

// parseAsmGenericTypeArg parses the optional generic type argument on
// asm<T>({...}). Returns the captured primitive type name when present and
// valid, or "" if the call has no type argument. Pushes a diagnostic (and
// returns "") when the type argument is present but not a primitive value
// type (bigint / boolean / ByteString).
func (p *parseContext) parseAsmGenericTypeArg(callNode *sitter.Node) string {
	typeArgsNode := p.findChildByType(callNode, "type_arguments")
	if typeArgsNode == nil {
		return ""
	}
	var typeArgs []*sitter.Node
	for i := 0; i < int(typeArgsNode.ChildCount()); i++ {
		child := typeArgsNode.Child(i)
		t := child.Type()
		if t == "<" || t == ">" || t == "," {
			continue
		}
		typeArgs = append(typeArgs, child)
	}
	if len(typeArgs) == 0 {
		return ""
	}
	if len(typeArgs) > 1 {
		p.addError(fmt.Sprintf("asm<T>() takes at most one type argument, got %d", len(typeArgs)))
		return ""
	}
	text := strings.TrimSpace(p.nodeText(typeArgs[0]))
	if text == "bigint" || text == "boolean" || text == "ByteString" {
		return text
	}
	p.addError(fmt.Sprintf("asm<T>() return type must be 'bigint', 'boolean', or 'ByteString'; got '%s'", text))
	return ""
}

// encodeAsmArrayBody encodes an asm({ body: [OP_DUP, push(0x42), ...] })
// array literal to its hex byte representation. Uses the same push-encoding
// helpers as the emit pass so the resulting bytes are byte-identical to what
// the emitter would produce for the equivalent literal.
func (p *parseContext) encodeAsmArrayBody(arrayNode *sitter.Node) string {
	var hexStr string
	for i := 0; i < int(arrayNode.ChildCount()); i++ {
		elem := arrayNode.Child(i)
		t := elem.Type()
		if t == "[" || t == "]" || t == "," {
			continue
		}

		if t == "identifier" {
			name := p.nodeText(elem)
			b, ok := codegen.OpcodeByte(name)
			if !ok {
				p.addError(fmt.Sprintf("Unknown opcode '%s' in asm() body array. Expected an OP_* identifier (e.g. OP_DUP, OP_HASH160) or a push(...) call.", name))
				continue
			}
			hexStr += fmt.Sprintf("%02x", b)
			continue
		}

		if t == "call_expression" {
			calleeNode := elem.ChildByFieldName("function")
			if calleeNode == nil || calleeNode.Type() != "identifier" || p.nodeText(calleeNode) != "push" {
				calleeText := ""
				if calleeNode != nil {
					calleeText = p.nodeText(calleeNode)
				}
				p.addError(fmt.Sprintf("asm() body array call must be 'push(<literal>)', got '%s(...)'", calleeText))
				continue
			}
			pushArgsNode := elem.ChildByFieldName("arguments")
			var pushArgs []*sitter.Node
			if pushArgsNode != nil {
				for j := 0; j < int(pushArgsNode.ChildCount()); j++ {
					c := pushArgsNode.Child(j)
					ct := c.Type()
					if ct == "(" || ct == ")" || ct == "," {
						continue
					}
					pushArgs = append(pushArgs, c)
				}
			}
			if len(pushArgs) != 1 {
				p.addError(fmt.Sprintf("push() takes exactly one literal argument, got %d", len(pushArgs)))
				continue
			}
			if pushed, ok := p.encodeAsmPushLiteral(pushArgs[0]); ok {
				hexStr += pushed
			}
			continue
		}

		p.addError(fmt.Sprintf("asm() body array element must be an opcode identifier (e.g. OP_DUP) or a push(<literal>) call; got '%s'", t))
	}
	return hexStr
}

// encodeAsmPushLiteral encodes a literal argument passed to push(...) inside
// an asm() body array. Returns the encoded hex string and true, or "" and
// false if the literal is unrecognised (with a diagnostic pushed).
func (p *parseContext) encodeAsmPushLiteral(node *sitter.Node) (string, bool) {
	switch node.Type() {
	case "number":
		text := p.nodeText(node)
		numStr := text
		if strings.HasSuffix(numStr, "n") {
			numStr = numStr[:len(numStr)-1]
		}
		bi := new(big.Int)
		if _, ok := bi.SetString(numStr, 0); !ok {
			if _, ok2 := bi.SetString(numStr, 10); !ok2 {
				p.addError(fmt.Sprintf("push() argument is not a valid integer literal: '%s'", text))
				return "", false
			}
		}
		h, _ := codegen.EncodePushBigInt(bi)
		return h, true

	case "unary_expression":
		opNode := node.ChildByFieldName("operator")
		argNode := node.ChildByFieldName("argument")
		if opNode != nil && argNode != nil && p.nodeText(opNode) == "-" && argNode.Type() == "number" {
			text := p.nodeText(argNode)
			numStr := text
			if strings.HasSuffix(numStr, "n") {
				numStr = numStr[:len(numStr)-1]
			}
			bi := new(big.Int)
			if _, ok := bi.SetString(numStr, 0); !ok {
				if _, ok2 := bi.SetString(numStr, 10); !ok2 {
					p.addError(fmt.Sprintf("push() argument is not a valid integer literal: '%s'", text))
					return "", false
				}
			}
			bi.Neg(bi)
			h, _ := codegen.EncodePushBigInt(bi)
			return h, true
		}
		p.addError("push() argument must be a literal value (bigint, number, boolean, or hex string), got prefix expression")
		return "", false

	case "true":
		return "51", true // OP_TRUE
	case "false":
		return "00", true // OP_FALSE (alias of OP_0)

	case "string", "template_string":
		raw := p.nodeText(node)
		if len(raw) >= 2 {
			raw = raw[1 : len(raw)-1]
		}
		if len(raw)%2 != 0 || !isHexString(raw) {
			p.addError(fmt.Sprintf("push() ByteString argument must be even-length hex (got '%s')", raw))
			return "", false
		}
		bytes := make([]byte, len(raw)/2)
		for i := range bytes {
			v := new(big.Int)
			v.SetString(raw[i*2:i*2+2], 16)
			bytes[i] = byte(v.Int64())
		}
		return codegen.EncodePushBytesHex(bytes), true
	}

	p.addError(fmt.Sprintf("push() argument must be a literal value (bigint, number, boolean, or hex string), got '%s'", node.Type()))
	return "", false
}

// parseArityLiteral decodes a non-negative integer literal arity field for
// asm(). Returns the value and true, or 0 and false (with a diagnostic) on
// error.
func (p *parseContext) parseArityLiteral(node *sitter.Node, fieldName string) (int64, bool) {
	switch node.Type() {
	case "number":
		text := p.nodeText(node)
		numStr := text
		if strings.HasSuffix(numStr, "n") {
			numStr = numStr[:len(numStr)-1]
		}
		bi := new(big.Int)
		if _, ok := bi.SetString(numStr, 0); !ok {
			if _, ok2 := bi.SetString(numStr, 10); !ok2 {
				p.addError(fmt.Sprintf("asm() %s must be a non-negative integer literal, got '%s'", fieldName, text))
				return 0, false
			}
		}
		if bi.Sign() < 0 {
			p.addError(fmt.Sprintf("asm() %s must be a non-negative integer literal, got '%s'", fieldName, text))
			return 0, false
		}
		// Range-check BEFORE narrowing: bi.Int64() truncates modulo 2^64, so
		// `in_arity: 18446744073709551618` used to become 2 and compile to
		// exactly the same bytes as `in_arity: 2`. CL-BUG-127.
		n, err := ir.IntValueExact(bi, fmt.Sprintf("asm() %s", fieldName))
		if err != nil {
			p.addError(err.Error())
			return 0, false
		}
		return int64(n), true
	case "unary_expression":
		p.addError(fmt.Sprintf("asm() %s must be a non-negative integer literal", fieldName))
		return 0, false
	default:
		p.addError(fmt.Sprintf("asm() %s must be a non-negative integer literal, got '%s'", fieldName, node.Type()))
		return 0, false
	}
}

func (p *parseContext) parseCallArgs(node *sitter.Node) []Expression {
	var args []Expression
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		t := child.Type()
		if t == "(" || t == ")" || t == "," {
			continue
		}
		expr := p.parseExpression(child)
		if expr != nil {
			args = append(args, expr)
		}
	}
	return args
}

func (p *parseContext) parseMemberExpression(node *sitter.Node) Expression {
	objNode := node.ChildByFieldName("object")
	propNode := node.ChildByFieldName("property")

	if objNode == nil || propNode == nil {
		// Fallback
		if node.ChildCount() >= 3 {
			objNode = node.Child(0)
			propNode = node.Child(2) // skip the "."
		}
	}

	if objNode == nil || propNode == nil {
		return BigIntLiteral{Value: big.NewInt(0)}
	}

	propName := p.nodeText(propNode)

	// this.x -> PropertyAccessExpr
	if objNode.Type() == "this" {
		return PropertyAccessExpr{Property: propName}
	}

	object := p.parseExpression(objNode)
	if object == nil {
		object = Identifier{Name: "unknown"}
	}

	return MemberExpr{Object: object, Property: propName}
}

func (p *parseContext) parseSubscriptExpression(node *sitter.Node) Expression {
	objNode := node.ChildByFieldName("object")
	indexNode := node.ChildByFieldName("index")

	if objNode == nil || indexNode == nil {
		return BigIntLiteral{Value: big.NewInt(0)}
	}

	object := p.parseExpression(objNode)
	index := p.parseExpression(indexNode)
	if object == nil || index == nil {
		return BigIntLiteral{Value: big.NewInt(0)}
	}

	return IndexAccessExpr{Object: object, Index: index}
}

func (p *parseContext) parseTernaryExpression(node *sitter.Node) Expression {
	condNode := node.ChildByFieldName("condition")
	consNode := node.ChildByFieldName("consequence")
	altNode := node.ChildByFieldName("alternative")

	if condNode == nil || consNode == nil || altNode == nil {
		return BigIntLiteral{Value: big.NewInt(0)}
	}

	condition := p.parseExpression(condNode)
	consequent := p.parseExpression(consNode)
	alternate := p.parseExpression(altNode)

	if condition == nil || consequent == nil || alternate == nil {
		return BigIntLiteral{Value: big.NewInt(0)}
	}

	return TernaryExpr{
		Condition:  condition,
		Consequent: consequent,
		Alternate:  alternate,
	}
}

func (p *parseContext) parseStringLiteral(node *sitter.Node) Expression {
	text := p.nodeText(node)
	// Remove quotes
	if len(text) >= 2 {
		text = text[1 : len(text)-1]
	}
	return ByteStringLiteral{Value: text}
}

func (p *parseContext) parseParenExpression(node *sitter.Node) Expression {
	// parenthesized_expression: "(" expression ")"
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child.Type() != "(" && child.Type() != ")" && child.Type() != "comment" {
			return p.parseExpression(child)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// countChildrenByType counts direct children of the given tree-sitter type.
//
// The declaration-list rule (W5) needs to know that a SECOND declarator exists,
// which findChildByType cannot express: it stops at the first match, which is
// exactly how every later declarator used to disappear without a diagnostic.
func (p *parseContext) countChildrenByType(node *sitter.Node, typeName string) int {
	n := 0
	for i := 0; i < int(node.ChildCount()); i++ {
		if node.Child(i).Type() == typeName {
			n++
		}
	}
	return n
}

// extraDeclaratorError is the W5 diagnostic, shared verbatim with the other
// tiers that drive a full TypeScript parser and can therefore SEE a declaration
// list at all (ts-morph in the reference tier, swc in rust).
func extraDeclaratorError(count int) string {
	return fmt.Sprintf(
		"Multiple variable declarations in a single statement are not supported "+
			"(%d declared). Declare one variable per statement: every declarator after "+
			"the first is discarded before the AST is built, so anything it calls -- a guard, "+
			"an assert reached through a private helper -- is silently absent from the "+
			"emitted script.",
		count,
	)
}

func (p *parseContext) findChildByType(node *sitter.Node, typeName string) *sitter.Node {
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child.Type() == typeName {
			return child
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// F-213 measure (A) for the .runar.ts surface
// ---------------------------------------------------------------------------

// tsNestFrame is one node on the iterative walk's path.
type tsNestFrame struct {
	typ   string
	level int
	// chain counts the edges above this node that each become one level of
	// the Rúnar expression tree: a binary operand, a member / subscript
	// object, a callee (see tsParseNestingViolation).
	chain int
	// condParen: a parenthesized_expression that is the syntactic condition
	// of an if / while / do / switch (the TS AST has no node for it).
	condParen bool
	// prefix: an update_expression whose operator comes first (`++x`).
	prefix bool
	// genericArgs: a type_arguments list of a generic_type (`FixedArray<..>`).
	genericArgs bool
}

func tsIsStatementType(t string) bool {
	return t == "statement_block" || t == "lexical_declaration" || t == "variable_declaration" ||
		strings.HasSuffix(t, "_statement")
}

// tsChildNestFrame is the frame of a child of parent, mirroring the TS
// reference's tsChildNesting (packages/runar-compiler/src/passes/01-parse.ts)
// over the tree-sitter tree: a statement inside a body (+1; a block is free
// unless it is itself a nested statement), each expression slot of a
// statement / declaration, a parenthesised group, a call or `new` argument,
// a subscript index, an array element, a ternary arm, a prefix-unary operand,
// a nested type argument, an operand of an intersection / union type. Binary
// operands, member objects and callees add nothing. tree-sitter's else_clause, an if's condition parentheses and a
// for's condition expression_statement have no TS AST node and are mapped
// through.
func tsChildNestFrame(parent tsNestFrame, child *sitter.Node, field string) tsNestFrame {
	ct := child.Type()
	f := tsNestFrame{typ: ct, level: parent.level, chain: parent.chain}
	if !child.IsNamed() || ct == "comment" {
		return f
	}
	switch parent.typ {
	case "binary_expression":
		f.chain++
	case "member_expression", "subscript_expression":
		if field == "object" {
			f.chain++
		}
	case "call_expression":
		if field == "function" {
			f.chain++
		}
	}
	pk := parent.typ
	if pk == "else_clause" {
		pk = "if_statement"
	}
	switch ct {
	case "update_expression":
		if first := child.Child(0); first != nil && !first.IsNamed() {
			f.prefix = true
		}
	case "type_arguments":
		f.genericArgs = pk == "generic_type"
	}
	if pk == "for_statement" {
		switch field {
		case "initializer", "condition":
			return f
		case "increment":
			f.level++
			return f
		}
	}
	if tsIsStatementType(ct) && (pk == "statement_block" || tsIsStatementType(pk)) {
		if !(ct == "statement_block" && pk != "statement_block") {
			f.level++
		}
		return f
	}
	switch pk {
	case "expression_statement", "return_statement", "throw_statement":
		f.level++
	case "if_statement", "while_statement", "do_statement", "switch_statement":
		if field == "condition" || field == "value" {
			f.level++
			f.condParen = ct == "parenthesized_expression"
		}
	case "variable_declarator", "public_field_definition", "required_parameter", "optional_parameter":
		if field == "value" {
			f.level++
		}
	case "parenthesized_expression":
		if !parent.condParen {
			f.level++
		}
	case "unary_expression", "array", "arguments":
		f.level++
	case "update_expression":
		if parent.prefix {
			f.level++
		}
	case "subscript_expression":
		if field == "index" {
			f.level++
		}
	case "ternary_expression":
		if field != "condition" {
			f.level++
		}
	case "type_arguments":
		if parent.genericArgs {
			f.level++
		}
	case "intersection_type", "union_type":
		// N-311: each operand of an intersection / union type. tree-sitter
		// builds `A & B & C` left-deep, as intersection(intersection(A, B), C);
		// the TS reference keeps it one flat list, so a same-operator left
		// operand continues the list and adds nothing.
		if !(ct == pk && child.PrevSibling() == nil) {
			f.level++
		}
	}
	return f
}

// tsParseNestingViolation returns the first node whose parse nesting
// (measure A) exceeds MaxSourceNesting, or nil. It walks the tree with a
// TreeCursor, iteratively, before any recursive pass touches the tree.
//
// It also refuses a node reached through more than MaxSourceNesting chain
// edges (binary operand, member / subscript object, callee). The converter
// turns each such parent into a Rúnar node holding the converted child, so a
// path of k chain edges is a Rúnar expression at least k deep (k-1 if the
// innermost edge is `this.x`, which becomes a leaf, plus 1 for the leaf):
// measure (B) is then > MaxSourceNesting and withNestingLimit would refuse
// the source anyway. Refusing it here keeps the recursive converter off the
// left-deep chains the grammar builds by iteration (`a + a + …`, `a.b.b…`,
// `a[0][0]…`), whose recursion on Go's stack is quadratic in GC stack
// scanning and fatal past the 1 GB stack ceiling.
func tsParseNestingViolation(root *sitter.Node) *sitter.Node {
	cur := sitter.NewTreeCursor(root)
	defer cur.Close()
	stack := []tsNestFrame{{typ: root.Type()}}
	for {
		top := stack[len(stack)-1]
		if top.level > MaxSourceNesting || top.chain > MaxSourceNesting {
			return cur.CurrentNode()
		}
		if cur.GoToFirstChild() {
			stack = append(stack, tsChildNestFrame(top, cur.CurrentNode(), cur.CurrentFieldName()))
			continue
		}
		for {
			if len(stack) == 1 {
				return nil
			}
			if cur.GoToNextSibling() {
				stack[len(stack)-1] = tsChildNestFrame(stack[len(stack)-2], cur.CurrentNode(), cur.CurrentFieldName())
				break
			}
			cur.GoToParent()
			stack = stack[:len(stack)-1]
		}
	}
}
