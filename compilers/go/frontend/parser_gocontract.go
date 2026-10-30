package frontend

import (
	"encoding/hex"
	"fmt"
	"go/ast"
	"go/parser"
	"go/scanner"
	"go/token"
	"go/types"
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

// bytesToHex returns the lowercase hex encoding of b.
func bytesToHex(b []byte) string {
	return hex.EncodeToString(b)
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

// ParseGoContract parses a Go contract syntax (.runar.go) source file and
// produces the standard Rúnar AST. Uses Go's built-in go/parser.
func ParseGoContract(source []byte, fileName string) *ParseResult {
	// DoS-bound size guard, enforced at every exported parser entry, not
	// just ParseSource. F-177.
	if res := sourceSizeGuardResult(source); res != nil {
		return res
	}
	// F-026: every number token, extended over the [0-9A-Za-z_] characters
	// glued to it, must be a Go integer literal. go/parser would refuse most
	// malformed ones with its own words; this gives them the shared text.
	if diags := checkGoNumericLiterals(source, fileName); len(diags) > 0 {
		return &ParseResult{Errors: diags}
	}
	// N-407: go/parser takes Unicode letters into identifiers; the TS
	// reference (01-parse-go.ts) refuses any non-ASCII character outside a
	// comment or a string with its "Unexpected character" diagnostic.
	if diags := checkGoNonASCIITokens(source, fileName); len(diags) > 0 {
		return &ParseResult{Errors: diags}
	}
	return withNestingLimit(func() *ParseResult { return parseGoContractSurface(source, fileName) })
}

// goParseErrorText renders go/parser's error with 0-based columns. go/scanner
// formats its positions 1-based; every Rúnar diagnostic column is 0-based
// (N-078, R88a), so each position is rebased the way locAt rebases AST ones.
var goIllegalCharRe = regexp.MustCompile(`^illegal character U\+[0-9A-F]+ '(.+)'$`)

func goParseErrorText(err error) string {
	list, ok := err.(scanner.ErrorList)
	if !ok || len(list) == 0 {
		return err.Error()
	}
	e := list[0]
	msg := e.Msg
	// N-214: go/scanner's "illegal character U+00A7 '§'" is the TS reference's
	// "Unexpected character '§'" (same character, same position).
	if m := goIllegalCharRe.FindStringSubmatch(msg); m != nil {
		msg = "Unexpected character '" + m[1] + "'"
	}
	text := e.Error()
	if e.Pos.IsValid() && e.Pos.Column > 0 {
		// Formatted here, not by token.Position.String, which drops a
		// column of 0.
		text = fmt.Sprintf("%s:%d:%d: %s", e.Pos.Filename, e.Pos.Line, e.Pos.Column-1, msg)
	}
	if len(list) > 1 {
		text += fmt.Sprintf(" (and %d more errors)", len(list)-1)
	}
	return text
}

// goParserDepthErrors are go/parser's own recursion bounds (max nesting depth
// 100,000; max resolver scope depth 1,000). Both sit far past
// MaxSourceNesting, so a source that trips one is over-nested by F-213's
// measures too and gets the shared diagnostic, not go/parser's text.
var goParserDepthErrors = []string{"exceeded max nesting depth", "exceeded max scope depth"}

func parseGoContractSurface(source []byte, fileName string) *ParseResult {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, fileName, source, parser.ParseComments|parser.SkipObjectResolution)
	if err != nil {
		for _, depthErr := range goParserDepthErrors {
			if strings.Contains(err.Error(), depthErr) {
				return sourceNestingResult(&SourceLocation{File: fileName, Line: 1, Column: 0})
			}
		}
		return &ParseResult{Errors: []Diagnostic{{Message: fmt.Sprintf("Go parse error: %v", goParseErrorText(err)), Severity: SeverityError}}}
	}

	// F-213 measure (A), iteratively over go/ast, before the recursive
	// converter walks the tree.
	if bad := goParseNestingViolation(file); bad != nil {
		loc := SourceLocation{File: fileName}
		if pos := fset.Position(bad.Pos()); pos.IsValid() {
			loc = SourceLocation{File: fileName, Line: pos.Line, Column: pos.Column - 1}
		}
		return sourceNestingResult(&loc)
	}

	p := &goContractParser{
		fset:     fset,
		file:     file,
		fileName: fileName,
	}
	p.collectGoDirectives(source)

	contract := p.extractContract()
	p.reportStrayGoDirectives()
	if contract == nil && len(p.errors) == 0 {
		p.addError(goNoContractMessage)
	}
	p.errors = append(p.errors, p.idents.collisionDiagnostics()...)

	return &ParseResult{
		Contract: contract,
		Errors:   p.errors,
	}
}

// checkGoNumericLiterals scans source with go/scanner (Go's own lexer, so
// strings, runes and comments are skipped exactly) and refuses every number
// token that is not a Go integer literal with the shared F-026 diagnostic.
func checkGoNumericLiterals(source []byte, fileName string) []Diagnostic {
	fset := token.NewFileSet()
	f := fset.AddFile(fileName, -1, len(source))
	var s scanner.Scanner
	s.Init(f, source, func(token.Position, string) {}, 0)
	var diags []Diagnostic
	covered := -1
	// Converted once: a per-token string(source) made this quadratic in the
	// number of numeric literals (minutes on a 4 MiB source of `[0]`s).
	src := string(source)
	for {
		pos, tok, _ := s.Scan()
		if tok == token.EOF {
			break
		}
		if tok != token.INT && tok != token.FLOAT && tok != token.IMAG {
			continue
		}
		start := f.Offset(pos)
		if start < covered {
			continue
		}
		end := scanNumberEnd(src, start)
		// A FLOAT / IMAG token may run past the identifier characters (`1.5`).
		for tok != token.INT && end < len(source) && (source[end] == '.' || isNumberContinue(source[end])) {
			end++
		}
		covered = end
		text := string(source[start:end])
		if parseIntLiteral("go", text) == nil {
			p := f.Position(pos)
			diags = append(diags, lexDiag(invalidIntegerLiteralMsg("go", text), fileName, p.Line, p.Column-1))
		}
	}
	return diags
}

// checkGoNonASCIITokens (N-407) scans source with go/scanner, so comments,
// strings and runes are skipped exactly, and refuses the first non-ASCII
// character of every identifier (go/scanner admits Unicode letters) and every
// illegal non-ASCII character (U+00A0, U+2003, ...) with the TS reference's
// "Unexpected character '<c>'" at that character.
func checkGoNonASCIITokens(source []byte, fileName string) []Diagnostic {
	fset := token.NewFileSet()
	f := fset.AddFile(fileName, -1, len(source))
	var s scanner.Scanner
	s.Init(f, source, func(token.Position, string) {}, 0)
	var diags []Diagnostic
	for {
		pos, tok, lit := s.Scan()
		if tok == token.EOF {
			break
		}
		if tok != token.IDENT && tok != token.ILLEGAL {
			continue
		}
		for i, r := range lit {
			if r >= 0x80 {
				p := f.Position(pos + token.Pos(i))
				diags = append(diags, lexDiag(fmt.Sprintf("Unexpected character '%c'", r), fileName, p.Line, p.Column-1))
				break
			}
		}
	}
	return diags
}

// ---------------------------------------------------------------------------
// Parser internals
// ---------------------------------------------------------------------------

type goContractParser struct {
	fset         *token.FileSet
	file         *ast.File
	fileName     string
	errors       []Diagnostic
	receiverName string // current method's receiver name (e.g. "c", "m", "self")

	// F-017: declared (spelling, Rúnar name) pairs.
	idents declaredIdents

	// N-093: every `//runar:` directive comment in the file, in source order,
	// and the `func` keyword offsets of the func declarations whose sighash
	// directives were resolved (consumed).
	directives []goDirective
	consumed   map[int]bool
}

// goDirective (N-093) is a Go DSL directive comment `//runar:<name> <args>`
// (Go's own `//go:` convention: no space after `//`). nextTok is the byte
// offset of the first token after the comment, so a directive attaches to the
// declaration that follows it with only comments and blank lines in between.
type goDirective struct {
	name, args string
	nextTok    int
	loc        SourceLocation
}

// collectGoDirectives (N-093) records every `//runar:` line comment and the
// token that follows it. go/scanner is Go's own lexer, so comments, strings
// and runes are recognised exactly; the semicolons it inserts at line ends
// are not tokens of the source and are skipped. Mirrors the directive
// capture of the TS reference tokenizer (01-parse-go.ts).
func (p *goContractParser) collectGoDirectives(source []byte) {
	p.consumed = map[int]bool{}
	fset := token.NewFileSet()
	f := fset.AddFile(p.fileName, -1, len(source))
	var s scanner.Scanner
	s.Init(f, source, func(token.Position, string) {}, scanner.ScanComments)
	var pending []int // indices into p.directives awaiting their next token
	for {
		pos, tok, lit := s.Scan()
		if tok == token.SEMICOLON && lit == "\n" {
			continue
		}
		off := f.Offset(pos)
		if tok == token.COMMENT {
			if strings.HasPrefix(lit, "//runar:") {
				body := strings.TrimSuffix(lit[len("//runar:"):], "\r")
				n := strings.IndexAny(body, " \t")
				if n < 0 {
					n = len(body)
				}
				p.directives = append(p.directives, goDirective{
					name: body[:n],
					args: body[n:],
					loc:  p.locAt(f.Position(pos)),
				})
				pending = append(pending, len(p.directives)-1)
			}
			continue
		}
		for _, i := range pending {
			p.directives[i].nextTok = off
		}
		pending = pending[:0]
		if tok == token.EOF {
			break
		}
	}
}

// goSighashFor (N-093) resolves the `//runar:sighash` directives attached to
// the func declaration fd (directly above it, with only comments and blank
// lines between), with the shared diagnostics.
func (p *goContractParser) goSighashFor(fd *ast.FuncDecl, name string, isPublic bool, loc SourceLocation) *int {
	off := p.fset.Position(fd.Pos()).Offset
	p.consumed[off] = true
	var specs []*string
	for _, d := range p.directives {
		if d.nextTok != off || d.name != "sighash" {
			continue
		}
		if d.args == "" || goSighashArgsRE.MatchString(d.args) {
			specs = append(specs, nativeSighashSpec(d.args))
		} else {
			specs = append(specs, nil)
		}
	}
	v, msg := resolveNativeSighash(name, isPublic, specs)
	if msg != "" {
		errLoc := loc
		p.errors = append(p.errors, Diagnostic{Message: msg, Severity: SeverityError, Loc: &errLoc})
	}
	return v
}

// goSighashArgsRE is the segment rule of extractSighashDirective: the flag
// text starts with a space/tab and holds only flag-name characters, `|`,
// spaces and tabs.
var goSighashArgsRE = regexp.MustCompile(`^[ \t][A-Za-z0-9_| \t]*$`)

// reportStrayGoDirectives (N-093) refuses every directive that is unknown or
// attached to no func declaration that becomes a contract method (a func the
// parser skips — e.g. a package-level init() — would drop it silently).
func (p *goContractParser) reportStrayGoDirectives() {
	for _, d := range p.directives {
		if d.name == "sighash" && p.consumed[d.nextTok] {
			continue
		}
		msg := LostDirectiveMsg("@sighash")
		if d.name != "sighash" {
			msg = unknownGoDirectiveMessage(d.name + d.args)
		}
		errLoc := d.loc
		p.errors = append(p.errors, Diagnostic{Message: msg, Severity: SeverityError, Loc: &errLoc})
	}
}

// goRunarTagRE extracts the `runar` key of a struct tag (N-093).
var goRunarTagRE = regexp.MustCompile(`(?:^|\s)runar:"([^"]*)"`)

// F-010 diagnostics — emitted verbatim by every tier's .runar.go parser
// (TS reference: goNoContractMessage / goMultipleContractsMessage /
// goForeignReceiverMessage in packages/runar-compiler/src/passes/01-parse-go.ts).
const goNoContractMessage = "no Rúnar contract struct found in Go source"

func goMultipleContractsMessage(first, second string) string {
	return fmt.Sprintf("multiple Rúnar contract structs found in Go source: '%s' and '%s'; "+
		"exactly one struct may embed runar.SmartContract, runar.StatefulSmartContract or runar.UnsafeSmartContract", first, second)
}

func goForeignReceiverMessage(method, receiverType, contract string) string {
	return fmt.Sprintf("method '%s' has receiver type '%s', not the contract type '%s'; "+
		"methods on other types are not allowed", method, receiverType, contract)
}

func (p *goContractParser) addError(msg string) {
	p.errors = append(p.errors, Diagnostic{Message: msg, Severity: SeverityError})
}

// locAt converts a go/token position into a Rúnar SourceLocation.
//
// Rúnar source maps use 1-based line / 0-based column (the convention the
// TypeScript reference tier emits, and the one this tier's own .runar.{ts,
// sol,move,py} frontends already produce). go/token reports 1-based
// columns, so the column is rebased here — at the single boundary where
// go/token positions enter the AST. Converting here rather than in
// codegen/emit.go is deliberate: emit.go is shared by every frontend, and
// the already-0-based ones would be corrupted by a blanket adjustment.
//
// An invalid position (token.NoPos) yields Line 0 / Column 0; the clamp
// keeps such an "unknown" location at 0 instead of producing -1.
//
// Diagnostic columns are 0-based too (N-078, R88a): messages that embed a
// position print locAt(pos).Column, never the raw 1-based pos.Column.
func (p *goContractParser) locAt(pos token.Position) SourceLocation {
	col := pos.Column - 1
	if col < 0 {
		col = 0
	}
	return SourceLocation{File: p.fileName, Line: pos.Line, Column: col}
}

func (p *goContractParser) extractContract() *ContractNode {
	var contractName string
	var parentClass string
	var properties []PropertyNode
	var methods []MethodNode

	// Find the struct type that embeds runar.SmartContract or runar.StatefulSmartContract
	for _, decl := range p.file.Decls {
		genDecl, ok := decl.(*ast.GenDecl)
		if !ok || genDecl.Tok != token.TYPE {
			continue
		}
		for _, spec := range genDecl.Specs {
			typeSpec, ok := spec.(*ast.TypeSpec)
			if !ok {
				continue
			}
			structType, ok := typeSpec.Type.(*ast.StructType)
			if !ok {
				continue
			}

			// Check for runar.SmartContract / runar.StatefulSmartContract embed
			found := false
			structParent := ""
			for _, field := range structType.Fields.List {
				if sel, ok := field.Type.(*ast.SelectorExpr); ok {
					if ident, ok := sel.X.(*ast.Ident); ok && ident.Name == "runar" {
						switch sel.Sel.Name {
						case "SmartContract":
							structParent = "SmartContract"
							found = true
						case "StatefulSmartContract":
							structParent = "StatefulSmartContract"
							found = true
						case "UnsafeSmartContract":
							structParent = "UnsafeSmartContract"
							found = true
						}
					}
				}
			}
			if !found {
				continue
			}

			// F-010: exactly one contract struct. The first one is the
			// contract; any further one is refused, never merged into it.
			if contractName != "" {
				p.addError(goMultipleContractsMessage(contractName, typeSpec.Name.Name))
				continue
			}
			contractName = typeSpec.Name.Name
			parentClass = structParent

			// Extract properties (non-embed fields)
			for _, field := range structType.Fields.List {
				// Skip the embed
				if _, ok := field.Type.(*ast.SelectorExpr); ok && len(field.Names) == 0 {
					continue
				}
				if len(field.Names) == 0 {
					continue
				}

				for _, name := range field.Names {
					propName := p.idents.declare(name.Name, goFieldToCamel(name.Name))
					propType := p.resolveType(field.Type)

					// Check struct tag. The `runar` key holds comma-separated
					// options (N-093): `readonly`, and `embedAlways` — the
					// native spelling of the `@embedAlways` directive — in
					// any order.
					readonly := false
					embedAlways := false
					if field.Tag != nil {
						tagStr := field.Tag.Value
						if unq, err := strconv.Unquote(tagStr); err == nil {
							tagStr = unq
						}
						if m := goRunarTagRE.FindStringSubmatch(tagStr); m != nil {
							for _, o := range strings.Split(m[1], ",") {
								switch strings.TrimSpace(o) {
								case "readonly":
									readonly = true
								case "embedAlways":
									embedAlways = true
								}
							}
						}
					}

					pos := p.fset.Position(field.Pos())
					properties = append(properties, PropertyNode{
						Name:           propName,
						Type:           propType,
						Readonly:       readonly,
						EmbedAlways:    embedAlways,
						SourceLocation: p.locAt(pos),
					})
				}
			}
		}
	}

	if contractName == "" {
		return nil
	}

	// Find methods on this contract type
	for _, decl := range p.file.Decls {
		funcDecl, ok := decl.(*ast.FuncDecl)
		if !ok || funcDecl.Recv == nil {
			continue
		}

		// F-010: the receiver — value or pointer — must be the contract
		// type. A method on any other type is refused: it used to become a
		// public entry point whenever its receiver was a value.
		if len(funcDecl.Recv.List) == 0 {
			continue
		}
		recvType := funcDecl.Recv.List[0].Type
		if star, ok := recvType.(*ast.StarExpr); ok {
			recvType = star.X
		}
		if recvName := types.ExprString(recvType); recvName != contractName {
			p.addError(goForeignReceiverMessage(funcDecl.Name.Name, recvName, contractName))
			continue
		}

		methodName := p.idents.declare(funcDecl.Name.Name, goFieldToCamel(funcDecl.Name.Name))
		// Exported (capitalized) = public
		visibility := "private"
		if funcDecl.Name.IsExported() {
			visibility = "public"
		}

		// Extract receiver name for property access resolution. N-018: an
		// unnamed receiver `(Type)` binds no name at all -- real Go forbids
		// referencing it in the method body -- so it must not default to
		// "c", which would wrongly turn a same-spelled parameter into a
		// self-reference.
		if len(funcDecl.Recv.List[0].Names) > 0 {
			p.receiverName = funcDecl.Recv.List[0].Names[0].Name
		} else {
			p.receiverName = ""
		}

		params := p.extractParams(funcDecl.Type.Params)
		p.checkReturnTypes(funcDecl, methodName, visibility == "public")
		body := p.extractStatements(funcDecl.Body)

		pos := p.fset.Position(funcDecl.Pos())
		methods = append(methods, MethodNode{
			Name:           methodName,
			Params:         params,
			Body:           body,
			Visibility:     visibility,
			SighashType:    p.goSighashFor(funcDecl, methodName, visibility == "public", p.locAt(pos)),
			SourceLocation: p.locAt(pos),
		})
	}

	// Find standalone (non-method) functions — treated as private helpers.
	// These are package-level functions without a receiver, e.g.:
	//   func testInternal(amount runar.Bigint) runar.Bigint { ... }
	// They become private methods with no access to contract state.
	for _, decl := range p.file.Decls {
		funcDecl, ok := decl.(*ast.FuncDecl)
		if !ok || funcDecl.Recv != nil {
			continue // skip methods (already handled above)
		}
		// Skip the package-level init() or main() functions
		if funcDecl.Name.Name == "init" || funcDecl.Name.Name == "main" {
			// N-300: a //runar:sighash above it is refused as on a private
			// func, with the same diagnostic as the TS reference (which
			// parses these as private helpers).
			pos := p.fset.Position(funcDecl.Pos())
			p.goSighashFor(funcDecl, goFieldToCamel(funcDecl.Name.Name), false, p.locAt(pos))
			continue
		}
		// F-010: an exported standalone function is a private helper too,
		// exactly as in the TS reference.

		methodName := p.idents.declare(funcDecl.Name.Name, goFieldToCamel(funcDecl.Name.Name))
		p.receiverName = "" // no receiver for standalone functions

		params := p.extractParams(funcDecl.Type.Params)
		p.checkReturnTypes(funcDecl, methodName, false)
		body := p.extractStatements(funcDecl.Body)

		pos := p.fset.Position(funcDecl.Pos())
		methods = append(methods, MethodNode{
			Name:           methodName,
			Params:         params,
			Body:           body,
			Visibility:     "private",
			SighashType:    p.goSighashFor(funcDecl, methodName, false, p.locAt(pos)),
			SourceLocation: p.locAt(pos),
		})
	}

	// Extract Init() method as property initializers, if present.
	// Init() is a special method that sets default values on properties.
	var finalMethods []MethodNode
	for _, m := range methods {
		if m.Name == "init" && len(m.Params) == 0 {
			// Extract property assignments as initializers
			for _, stmt := range m.Body {
				if assign, ok := stmt.(AssignmentStmt); ok {
					if pa, ok := assign.Target.(PropertyAccessExpr); ok {
						for i := range properties {
							if properties[i].Name == pa.Property {
								properties[i].Initializer = assign.Value
								break
							}
						}
					}
				}
			}
		} else {
			finalMethods = append(finalMethods, m)
		}
	}
	methods = finalMethods

	// Build constructor (only non-initialized properties)
	var uninitProps []PropertyNode
	for _, prop := range properties {
		if prop.Initializer == nil {
			uninitProps = append(uninitProps, prop)
		}
	}

	constructorParams := make([]ParamNode, len(uninitProps))
	for i, prop := range uninitProps {
		constructorParams[i] = ParamNode{Name: prop.Name, Type: prop.Type}
	}

	// super(...) call as first statement
	superArgs := make([]Expression, len(uninitProps))
	for i, prop := range uninitProps {
		superArgs[i] = Identifier{Name: prop.Name}
	}
	superCall := ExpressionStmt{
		Expr: CallExpr{
			Callee: Identifier{Name: "super"},
			Args:   superArgs,
		},
		SourceLocation: SourceLocation{File: p.fileName, Line: 1, Column: 0},
	}

	// Property assignments
	constructorBody := make([]Statement, 0, 1+len(uninitProps))
	constructorBody = append(constructorBody, superCall)
	for _, prop := range uninitProps {
		constructorBody = append(constructorBody, AssignmentStmt{
			Target:         PropertyAccessExpr{Property: prop.Name},
			Value:          Identifier{Name: prop.Name},
			SourceLocation: SourceLocation{File: p.fileName, Line: 1, Column: 0},
		})
	}

	return &ContractNode{
		Name:        contractName,
		ParentClass: parentClass,
		Properties:  properties,
		Constructor: MethodNode{
			Name:           "constructor",
			Params:         constructorParams,
			Body:           constructorBody,
			Visibility:     "public",
			SourceLocation: SourceLocation{File: p.fileName, Line: 1, Column: 0},
		},
		Methods:    methods,
		SourceFile: p.fileName,
	}
}

func (p *goContractParser) resolveType(expr ast.Expr) TypeNode {
	switch e := expr.(type) {
	case *ast.SelectorExpr:
		if ident, ok := e.X.(*ast.Ident); ok && ident.Name == "runar" {
			return mapGoType(e.Sel.Name)
		}
		return CustomType{Name: fmt.Sprintf("%v.%s", e.X, e.Sel.Name)}
	case *ast.Ident:
		// Go's own int64 and bool are the documented spellings of bigint and
		// boolean (docs/formats/go.md "Type Mapping").
		switch e.Name {
		case "int64":
			return PrimitiveType{Name: "bigint"}
		case "bool":
			return PrimitiveType{Name: "boolean"}
		}
		return mapGoType(e.Name)
	case *ast.ArrayType:
		if e.Len != nil {
			if lit, ok := e.Len.(*ast.BasicLit); ok {
				length, _ := strconv.Atoi(lit.Value)
				return FixedArrayType{Element: p.resolveType(e.Elt), Length: length}
			}
		}
		return p.resolveType(e.Elt)
	}
	return CustomType{Name: "unknown"}
}

func mapGoType(name string) TypeNode {
	typeMap := map[string]string{
		"Int":             "bigint",
		"Bigint":          "bigint",
		"BigintBig":       "bigint",
		"Bool":            "boolean",
		"ByteString":      "ByteString",
		"PubKey":          "PubKey",
		"Sig":             "Sig",
		"Sha256":          "Sha256",
		"Sha256Digest":    "Sha256",
		"Ripemd160":       "Ripemd160",
		"Ripemd160Hash":   "Ripemd160",
		"Addr":            "Addr",
		"SigHashPreimage": "SigHashPreimage",
		"RabinSig":        "RabinSig",
		"RabinPubKey":     "RabinPubKey",
		"Point":           "Point",
		"P256Point":       "P256Point",
		"P384Point":       "P384Point",
	}
	if mapped, ok := typeMap[name]; ok {
		if IsPrimitiveType(mapped) {
			return PrimitiveType{Name: mapped}
		}
	}
	if IsPrimitiveType(name) {
		return PrimitiveType{Name: name}
	}
	return CustomType{Name: name}
}

func (p *goContractParser) extractParams(fieldList *ast.FieldList) []ParamNode {
	if fieldList == nil {
		return nil
	}
	var params []ParamNode
	for _, field := range fieldList.List {
		paramType := p.resolveType(field.Type)
		for _, name := range field.Names {
			params = append(params, ParamNode{
				Name: p.idents.declare(name.Name, goFieldToCamel(name.Name)),
				Type: paramType,
			})
		}
	}
	return params
}

// checkReturnTypes (N-331): the AST keeps no return type, so a result whose
// type names something that is not a Rúnar type is refused here.
func (p *goContractParser) checkReturnTypes(fd *ast.FuncDecl, methodName string, isPublic bool) {
	if fd.Type.Results == nil {
		return
	}
	loc := p.locAt(p.fset.Position(fd.Pos()))
	for _, field := range fd.Type.Results.List {
		// Go's own `bool` is the documented spelling of `boolean` (docs/formats/go.md)
		// and every other tier's .runar.go parser accepts it as a result type.
		if id, ok := field.Type.(*ast.Ident); ok && id.Name == "bool" {
			// N-332: a public method may not declare any result, `bool` included.
			if isPublic {
				d := Diagnostic{Message: PublicReturnTypeMsg(methodName), Severity: SeverityError, Loc: &loc}
				p.errors = append(p.errors, d)
			}
			continue
		}
		if d := UnknownReturnTypeDiagnostic(p.resolveType(field.Type), methodName, loc, isPublic); d != nil {
			p.errors = append(p.errors, *d)
		}
	}
}

func (p *goContractParser) extractStatements(block *ast.BlockStmt) []Statement {
	if block == nil {
		return nil
	}
	var stmts []Statement
	for _, stmt := range block.List {
		s := p.convertStatement(stmt)
		if s != nil {
			stmts = append(stmts, s)
		} else {
			pos := p.fset.Position(stmt.Pos())
			p.addError(fmt.Sprintf(
				"unsupported Go statement at %s:%d:%d — not valid in Rúnar contract",
				p.fileName, pos.Line, p.locAt(pos).Column))
		}
	}
	return stmts
}

func (p *goContractParser) convertStatement(stmt ast.Stmt) Statement {
	pos := p.fset.Position(stmt.Pos())
	loc := p.locAt(pos)

	switch s := stmt.(type) {
	case *ast.ExprStmt:
		expr := p.convertExpression(s.X)
		if expr == nil {
			return nil
		}
		return ExpressionStmt{Expr: expr, SourceLocation: loc}

	case *ast.AssignStmt:
		if len(s.Lhs) == 1 && len(s.Rhs) == 1 {
			if s.Tok == token.DEFINE { // :=
				target := p.convertExpression(s.Lhs[0])
				init := p.convertExpression(s.Rhs[0])
				if target == nil || init == nil {
					return nil
				}
				name := ""
				if ident, ok := target.(Identifier); ok {
					name = ident.Name
					if raw, ok := s.Lhs[0].(*ast.Ident); ok {
						p.idents.declare(raw.Name, name)
					}
				}
				return VariableDeclStmt{
					Name:           name,
					Mutable:        true,
					Init:           init,
					SourceLocation: loc,
				}
			}
			target := p.convertExpression(s.Lhs[0])
			value := p.convertExpression(s.Rhs[0])
			if target == nil || value == nil {
				return nil
			}
			if s.Tok == token.ASSIGN {
				return AssignmentStmt{Target: target, Value: value, SourceLocation: loc}
			}
			// Compound assignment: desugar `x op= rhs` to `x = x op rhs`.
			binOp, ok := goCompoundAssignOps[s.Tok]
			if !ok {
				p.addError(fmt.Sprintf(
					"unsupported compound assignment operator %q at %s:%d:%d",
					s.Tok.String(), p.fileName, pos.Line, p.locAt(pos).Column))
				return nil
			}
			return AssignmentStmt{
				Target:         target,
				Value:          BinaryExpr{Op: binOp, Left: target, Right: value},
				SourceLocation: loc,
			}
		}

	case *ast.DeclStmt:
		genDecl, ok := s.Decl.(*ast.GenDecl)
		if !ok {
			return nil
		}
		for _, spec := range genDecl.Specs {
			valueSpec, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			if len(valueSpec.Names) > 0 && len(valueSpec.Values) > 0 {
				name := p.idents.declare(valueSpec.Names[0].Name, goFieldToCamel(valueSpec.Names[0].Name))
				init := p.convertExpression(valueSpec.Values[0])
				if init == nil {
					return nil
				}
				mutable := genDecl.Tok == token.VAR
				var typeNode TypeNode
				if valueSpec.Type != nil {
					typeNode = p.resolveType(valueSpec.Type)
				}
				return VariableDeclStmt{
					Name:           name,
					Type:           typeNode,
					Mutable:        mutable,
					Init:           init,
					SourceLocation: loc,
				}
			}
		}

	case *ast.IfStmt:
		cond := p.convertExpression(s.Cond)
		if cond == nil {
			return nil
		}
		thenBlock := p.extractStatements(s.Body)
		var elseBlock []Statement
		if s.Else != nil {
			switch e := s.Else.(type) {
			case *ast.BlockStmt:
				elseBlock = p.extractStatements(e)
			case *ast.IfStmt:
				// `else if` — Go's parser represents this as an
				// IfStmt nested directly in the Else field (no
				// enclosing block). Treat the nested IfStmt as a
				// single statement in the else block.
				if inner := p.convertStatement(e); inner != nil {
					elseBlock = []Statement{inner}
				}
			}
		}
		return IfStmt{
			Condition:      cond,
			Then:           thenBlock,
			Else:           elseBlock,
			SourceLocation: loc,
		}

	case *ast.ForStmt:
		var initStmt VariableDeclStmt
		if s.Init != nil {
			if init := p.convertStatement(s.Init); init != nil {
				if vd, ok := init.(VariableDeclStmt); ok {
					initStmt = vd
				}
			}
		}
		cond := p.convertExpression(s.Cond)
		var update Statement
		if s.Post != nil {
			update = p.convertStatement(s.Post)
		}
		body := p.extractStatements(s.Body)
		return ForStmt{
			Init:           initStmt,
			Condition:      cond,
			Update:         update,
			Body:           body,
			SourceLocation: loc,
		}

	case *ast.ReturnStmt:
		var value Expression
		if len(s.Results) > 0 {
			value = p.convertExpression(s.Results[0])
		}
		return ReturnStmt{Value: value, SourceLocation: loc}

	case *ast.IncDecStmt:
		operand := p.convertExpression(s.X)
		if operand == nil {
			return nil
		}
		if s.Tok == token.INC {
			return ExpressionStmt{
				Expr:           IncrementExpr{Operand: operand, Prefix: false},
				SourceLocation: loc,
			}
		}
		return ExpressionStmt{
			Expr:           DecrementExpr{Operand: operand, Prefix: false},
			SourceLocation: loc,
		}
	}

	return nil
}

func (p *goContractParser) convertExpression(expr ast.Expr) Expression {
	switch e := expr.(type) {
	case *ast.BasicLit:
		switch e.Kind {
		case token.INT:
			bi := new(big.Int)
			if _, ok := bi.SetString(e.Value, 0); !ok {
				bi = big.NewInt(0)
			}
			return BigIntLiteral{Value: bi}
		case token.STRING:
			s, _ := strconv.Unquote(e.Value)
			return ByteStringLiteral{Value: s}
		}

	case *ast.Ident:
		name := goFieldToCamel(e.Name)
		if name == "true" {
			return BoolLiteral{Value: true}
		}
		if name == "false" {
			return BoolLiteral{Value: false}
		}
		return Identifier{Name: name}

	case *ast.SelectorExpr:
		// runar.FuncName -> function call identifier
		if ident, ok := e.X.(*ast.Ident); ok {
			if ident.Name == "runar" {
				return Identifier{Name: mapGoBuiltin(e.Sel.Name)}
			}
			// receiver.Field -> property access (e.g. c.Count, m.Value).
			// N-018: this must be an exact match on the actual declared
			// receiver name, never a hardcoded "c"/"self" -- that wrongly
			// turned ANY same-spelled parameter or local into a
			// self-reference even when the receiver was named something
			// else, or unnamed (p.receiverName == "", which real Go forbids
			// referencing at all).
			if p.receiverName != "" && ident.Name == p.receiverName {
				return PropertyAccessExpr{Property: goFieldToCamel(e.Sel.Name)}
			}
			// Any other package selector (math.Log, fmt.Println, etc.) is not valid Rúnar
			pos := p.fset.Position(e.Pos())
			p.addError(fmt.Sprintf(
				"unsupported expression '%s.%s' at %s:%d:%d — only runar.* builtins and contract field access are allowed",
				ident.Name, e.Sel.Name, p.fileName, pos.Line, p.locAt(pos).Column))
			return nil
		}
		obj := p.convertExpression(e.X)
		return MemberExpr{Object: obj, Property: goFieldToCamel(e.Sel.Name)}

	case *ast.CallExpr:
		// Handle type conversions: runar.Int(0), runar.Bigint(x), runar.BigintBig(x) -> inner value
		if sel, ok := e.Fun.(*ast.SelectorExpr); ok {
			if ident, ok := sel.X.(*ast.Ident); ok && ident.Name == "runar" {
				typeName := sel.Sel.Name
				if (typeName == "Int" || typeName == "Bigint" || typeName == "BigintBig" || typeName == "Bool") && len(e.Args) == 1 {
					return p.convertExpression(e.Args[0])
				}
				// runar.ByteString("literal") -> ByteStringLiteral with hex-encoded bytes
				// runar.ByteString(variable) -> unwrap (type conversion no-op)
				if typeName == "ByteString" && len(e.Args) == 1 {
					if lit, ok := e.Args[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
						raw, err := strconv.Unquote(lit.Value)
						if err == nil {
							return ByteStringLiteral{Value: bytesToHex([]byte(raw))}
						}
					}
					return p.convertExpression(e.Args[0])
				}
				// BigintBig operator helpers: Go disallows `a < b` / `a == b` /
				// `a % b` on *big.Int, so DSL contracts reach for helper
				// functions. Rewrite those calls into the equivalent Rúnar
				// BinaryExpr so they lower to the same Script opcodes as plain
				// int64 operators.
				if op, ok := bigintBigOpFor(typeName); ok && len(e.Args) == 2 {
					left := p.convertExpression(e.Args[0])
					right := p.convertExpression(e.Args[1])
					if left != nil && right != nil {
						return BinaryExpr{Op: op, Left: left, Right: right}
					}
				}
			}
		}

		// A call target or an argument that does not convert must fail the
		// whole call. Dropping an argument would silently change the call's
		// arity — and for a variable-arity builtin that compiles clean as the
		// wrong overload. Each site reports only if the recursive conversion
		// did not already report a more precise cause, so one bad
		// subexpression yields one diagnostic rather than a cascade.
		before := len(p.errors)
		callee := p.convertExpression(e.Fun)
		if callee == nil {
			if len(p.errors) == before {
				pos := p.fset.Position(e.Fun.Pos())
				p.addError(fmt.Sprintf(
					"unsupported call target at %s:%d:%d — not valid in Rúnar contract",
					p.fileName, pos.Line, p.locAt(pos).Column))
			}
			return nil
		}
		var args []Expression
		for i, arg := range e.Args {
			before = len(p.errors)
			a := p.convertExpression(arg)
			if a == nil {
				if len(p.errors) == before {
					pos := p.fset.Position(arg.Pos())
					p.addError(fmt.Sprintf(
						"unsupported expression at %s:%d:%d — argument %d of this call is not valid in Rúnar contract",
						p.fileName, pos.Line, p.locAt(pos).Column, i+1))
				}
				return nil
			}
			args = append(args, a)
		}
		// runar.Assert(expr) -> assert(expr)
		if ident, ok := callee.(Identifier); ok && ident.Name == "assert" {
			return CallExpr{Callee: Identifier{Name: "assert"}, Args: args}
		}
		// runar.FuncName(args) -> funcName(args) for builtins
		return CallExpr{Callee: callee, Args: args}

	case *ast.BinaryExpr:
		if msg, ambiguous := goAmbiguousPrecedenceMessage(e); ambiguous {
			p.addError(msg) // N-056: see go_precedence.go
			return nil
		}
		left := p.convertExpression(e.X)
		right := p.convertExpression(e.Y)
		if left == nil || right == nil {
			return nil
		}
		// F-074: `a &^ b` (bit clear) is `a & ~b`, which is what the TS
		// reference's lexer produces for it (`&` then prefix `^`).
		if e.Op == token.AND_NOT {
			return BinaryExpr{Op: "&", Left: left, Right: UnaryExpr{Op: "~", Operand: right}}
		}
		op, ok := mapGoOp(e.Op)
		if !ok {
			p.addError(fmt.Sprintf("Unsupported binary operator: '%s'", e.Op))
			return nil
		}
		return BinaryExpr{Op: op, Left: left, Right: right}

	case *ast.UnaryExpr:
		operand := p.convertExpression(e.X)
		if operand == nil {
			return nil
		}
		switch e.Op {
		case token.NOT:
			return UnaryExpr{Op: "!", Operand: operand}
		case token.SUB:
			return UnaryExpr{Op: "-", Operand: operand}
		case token.XOR:
			return UnaryExpr{Op: "~", Operand: operand}
		}

	case *ast.ParenExpr:
		return p.convertExpression(e.X)

	case *ast.IndexExpr:
		obj := p.convertExpression(e.X)
		idx := p.convertExpression(e.Index)
		return IndexAccessExpr{Object: obj, Index: idx}

	case *ast.CompositeLit:
		// Array composite literal: `[9]runar.Bigint{0, 0, ...}` or the
		// elided-length variant `[...]T{...}`. Only array-shaped
		// composites are supported; struct composites are not valid
		// Rúnar expressions.
		if _, ok := e.Type.(*ast.ArrayType); ok || e.Type == nil {
			elements := make([]Expression, 0, len(e.Elts))
			for _, elt := range e.Elts {
				ex := p.convertExpression(elt)
				if ex == nil {
					return nil
				}
				elements = append(elements, ex)
			}
			return ArrayLiteralExpr{Elements: elements}
		}
		return nil
	}

	return nil
}

// goCompoundAssignOps maps Go compound-assignment tokens to the Rúnar binary
// operator they desugar to. Limited to the set the TS reference Go-surface
// parser accepts (01-parse-go.ts: += -= *= /= %=); every other compound
// operator (&= |= ^= <<= >>= &^=) is a parse error, for frontend parity.
var goCompoundAssignOps = map[token.Token]string{
	token.ADD_ASSIGN: "+",
	token.SUB_ASSIGN: "-",
	token.MUL_ASSIGN: "*",
	token.QUO_ASSIGN: "/",
	token.REM_ASSIGN: "%",
}

// mapGoOp maps a Go binary token to its Rúnar operator; false for a token it
// has no mapping for, which the caller refuses (F-074: it used to return "+").
func mapGoOp(op token.Token) (string, bool) {
	switch op {
	case token.ADD:
		return "+", true
	case token.SUB:
		return "-", true
	case token.MUL:
		return "*", true
	case token.QUO:
		return "/", true
	case token.REM:
		return "%", true
	case token.EQL:
		return "===", true
	case token.NEQ:
		return "!==", true
	case token.LSS:
		return "<", true
	case token.LEQ:
		return "<=", true
	case token.GTR:
		return ">", true
	case token.GEQ:
		return ">=", true
	case token.LAND:
		return "&&", true
	case token.LOR:
		return "||", true
	case token.AND:
		return "&", true
	case token.OR:
		return "|", true
	case token.XOR:
		return "^", true
	case token.SHL:
		return "<<", true
	case token.SHR:
		return ">>", true
	}
	return "", false
}

// bigintBigOpFor returns the Rúnar binary-operator string that the named
// BigintBig helper rewrites to (e.g. `BigintBigLess` → `<`). The second
// return is false for unrecognised names. The set mirrors the helpers
// defined in `packages/runar-go/runar.go`.
func bigintBigOpFor(name string) (string, bool) {
	switch name {
	case "BigintBigLess":
		return "<", true
	case "BigintBigLessEq":
		return "<=", true
	case "BigintBigGreater":
		return ">", true
	case "BigintBigGreaterEq":
		return ">=", true
	case "BigintBigEqual":
		return "===", true
	case "BigintBigNotEqual":
		return "!==", true
	case "BigintBigAdd":
		return "+", true
	case "BigintBigSub":
		return "-", true
	case "BigintBigMul":
		return "*", true
	case "BigintBigMod":
		return "%", true
	case "BigintBigDiv":
		return "/", true
	}
	return "", false
}

func mapGoBuiltin(name string) string {
	builtinMap := map[string]string{
		"Assert":            "assert",
		"Hash160":           "hash160",
		"Hash256":           "hash256",
		"Sha256":            "sha256",
		"Sha256Hash":        "sha256",
		"Ripemd160":         "ripemd160",
		"CheckSig":          "checkSig",
		"CheckMultiSig":     "checkMultiSig",
		"CheckPreimage":     "checkPreimage",
		"VerifyRabinSig":    "verifyRabinSig",
		"VerifyWOTS":              "verifyWOTS",
		"VerifySLHDSA_SHA2_128s":  "verifySLHDSA_SHA2_128s",
		"VerifySLHDSA_SHA2_128f":  "verifySLHDSA_SHA2_128f",
		"VerifySLHDSA_SHA2_192s":  "verifySLHDSA_SHA2_192s",
		"VerifySLHDSA_SHA2_192f":  "verifySLHDSA_SHA2_192f",
		"VerifySLHDSA_SHA2_256s":  "verifySLHDSA_SHA2_256s",
		"VerifySLHDSA_SHA2_256f":  "verifySLHDSA_SHA2_256f",
		"VerifySP1FRI":           "verifySP1FRI",
		"VerifyECDSAP256":         "verifyECDSA_P256",
		"VerifyECDSAP384":         "verifyECDSA_P384",
		"Num2Bin":           "num2bin",
		"Bin2Num":           "bin2num",
		// `Int2Str` is the spelling docs/formats/go.md documents. Without it the
		// default rule camel-cases the leading character to `int2Str`, which is
		// registered nowhere — the call is rejected as an unknown function.
		"Int2Str":           "int2str",
		"Bin2NumBig":        "bin2num",
		"Num2BinBig":        "num2bin",

		// the *Big peers of abs / gcd. Same rule as Num2BinBig / Bin2NumBig above: the
		// suffix names a different Go RUNTIME type (*big.Int, so the Go-side mock does not
		// narrow at MinInt64), not a different Script operation -- OP_ABS and the gcd
		// builtin are arbitrary-width after Genesis. These were mapped in ZERO tiers while
		// `Abs(math.MinInt64)` and `Gcd(math.MinInt64, 0)` in packages/runar-go panic
		// telling the author to use them, naming the .runar.go parser as the thing that
		// lowers them.
		"AbsBig":            "abs",
		"GcdBig":            "gcd",
		"Cat":               "cat",
		"Substr":            "substr",
		"Len":               "len",
		"ReverseBytes":      "reverseBytes",
		"ExtractLocktime":   "extractLocktime",
		"ExtractOutputHash": "extractOutputHash",
		"ExtractPrevOutputScript": "extractPrevOutputScript",
		"RequireOutputP2PKH":      "requireOutputP2PKH",
		"CurrentBlockHeight":      "currentBlockHeight",
		"ContinuationAmount":      "continuationAmount",
		"AddOutput":         "addOutput",
		"AddRawOutput":      "addRawOutput",
		"AddDataOutput":     "addDataOutput",
		"GetStateScript":    "getStateScript",
		"Safediv":           "safediv",
		"Safemod":           "safemod",
		"Clamp":             "clamp",
		"Sign":              "sign",
		"Pow":               "pow",
		"MulDiv":            "mulDiv",
		"PercentOf":         "percentOf",
		"Sqrt":              "sqrt",
		"Gcd":               "gcd",
		"Divmod":            "divmod",
		"Log2":              "log2",
		"ToBool":            "bool",
		// BN254 contract-compatible wrappers (Point/Bigint types)
		"Bn254G1AddP":       "bn254G1Add",
		"Bn254G1ScalarMulP": "bn254G1ScalarMul",
		"Bn254G1NegateP":    "bn254G1Negate",
		"Bn254G1OnCurveP":   "bn254G1OnCurve",
		"Bn254FieldNegP":    "bn254FieldNeg",
		// *Big variants — compile to the same Script builtins. The Go-mock
		// runtime runs real gnark-crypto pairing instead of returning true,
		// so contracts that type fields as BigintBig get real soundness
		// coverage under `go test`.
		"Bn254G1AddBigP":        "bn254G1Add",
		"Bn254G1ScalarMulBigP":  "bn254G1ScalarMul",
		"Bn254G1NegateBigP":     "bn254G1Negate",
		"Bn254G1OnCurveBigP":    "bn254G1OnCurve",
		"Bn254FieldNegBigP":     "bn254FieldNeg",
		"Bn254MultiPairing4Big": "bn254MultiPairing4",
		"Bn254MultiPairing3Big": "bn254MultiPairing3",
		// Poseidon2 Merkle variadic wrapper (individual args instead of arrays)
		"MerkleRootPoseidon2KBv": "merkleRootPoseidon2KB",
	}
	if mapped, ok := builtinMap[name]; ok {
		return mapped
	}
	return goFieldToCamel(name)
}

// goFieldToCamel converts a Go-style exported name to camelCase.
// e.g., "PubKeyHash" -> "pubKeyHash", "AddOutput" -> "addOutput"
func goFieldToCamel(name string) string {
	if len(name) == 0 {
		return name
	}
	// If it starts with lowercase, it's already camelCase
	r := []rune(name)
	if !unicode.IsUpper(r[0]) {
		return name
	}
	// R-254: what used to be here scanned the leading run of uppercase runes and
	// then branched on its length — but every branch did the same thing, and the
	// comment above the last one ("lowercase all but the last one",
	// "PubKeyHash -> stays as-is") described neither the code below it nor the
	// behaviour this function's own doc comment promises. The `i == 0` branch
	// was unreachable too: r[0] is known uppercase here, so the scan always
	// advances at least once.
	//
	// Go exported names are converted by lowercasing the first letter. That is
	// what the code did; it is now also what it says. "HTTPServer" becomes
	// "hTTPServer" — not "httpServer" — and no caller wants otherwise, because
	// the Rúnar side of this mapping is a field name the author wrote.
	r[0] = unicode.ToLower(r[0])
	return string(r)
}

// ---------------------------------------------------------------------------
// F-213 measure (A) for the .runar.go surface
// ---------------------------------------------------------------------------

// goNestItem is one go/ast node on the iterative walk's work list.
type goNestItem struct {
	node  ast.Node
	level int
	// chain counts the edges above node that each become one level of the
	// Rúnar expression tree (see goParseNestingViolation).
	chain int
}

// goNestChildren returns the children of it.node with their parse nesting,
// mirroring the TS reference's hand-written .runar.go parser
// (packages/runar-compiler/src/passes/01-parse-go.ts): +1 per statement in a
// body (an `else if` is a statement of the else branch), +1 per expression
// slot of a statement (a `for` init / post statement is not itself counted,
// its expressions are), +1 per parenthesised group, prefix-unary operand,
// call argument, index expression, composite-literal element and nested
// array element type. Binary operands, selectors and callees add nothing.
func goNestChildren(it goNestItem) []goNestItem {
	lv := it.level
	var out []goNestItem
	addChain := func(n ast.Node, level, chain int) {
		if n != nil {
			out = append(out, goNestItem{node: n, level: level, chain: chain})
		}
	}
	add := func(n ast.Node, level int) { addChain(n, level, it.chain) }
	addExprs := func(es []ast.Expr, level int) {
		for _, e := range es {
			add(e, level)
		}
	}
	switch n := it.node.(type) {
	case *ast.BlockStmt:
		for _, s := range n.List {
			add(s, lv+1)
		}
	case *ast.IfStmt:
		add(n.Init, lv+1)
		add(n.Cond, lv+1)
		if n.Body != nil {
			add(n.Body, lv)
		}
		if elseIf, ok := n.Else.(*ast.IfStmt); ok {
			add(elseIf, lv+1)
		} else {
			add(n.Else, lv)
		}
	case *ast.ForStmt:
		add(n.Init, lv)
		add(n.Cond, lv+1)
		add(n.Post, lv)
		if n.Body != nil {
			add(n.Body, lv)
		}
	case *ast.RangeStmt:
		add(n.Key, lv+1)
		add(n.Value, lv+1)
		add(n.X, lv+1)
		if n.Body != nil {
			add(n.Body, lv)
		}
	case *ast.ExprStmt:
		add(n.X, lv+1)
	case *ast.AssignStmt:
		addExprs(n.Lhs, lv+1)
		addExprs(n.Rhs, lv+1)
	case *ast.IncDecStmt:
		add(n.X, lv+1)
	case *ast.ReturnStmt:
		addExprs(n.Results, lv+1)
	case *ast.ValueSpec:
		add(n.Type, lv)
		addExprs(n.Values, lv+1)
	case *ast.ParenExpr:
		add(n.X, lv+1)
	case *ast.UnaryExpr:
		add(n.X, lv+1)
	case *ast.CallExpr:
		addChain(n.Fun, lv, it.chain+1)
		addExprs(n.Args, lv+1)
	case *ast.IndexExpr:
		addChain(n.X, lv, it.chain+1)
		add(n.Index, lv+1)
	case *ast.SelectorExpr:
		addChain(n.X, lv, it.chain+1)
	case *ast.CompositeLit:
		add(n.Type, lv)
		addExprs(n.Elts, lv+1)
	case *ast.ArrayType:
		add(n.Len, lv)
		add(n.Elt, lv+1)
	case *ast.BinaryExpr:
		addChain(n.X, lv, it.chain+1)
		addChain(n.Y, lv, it.chain+1)
	default:
		// Every other node: its direct children, at the same level.
		// ast.Inspect is stopped one level down, so this never recurses.
		ast.Inspect(it.node, func(c ast.Node) bool {
			if c == it.node {
				return true
			}
			add(c, lv)
			return false
		})
	}
	return out
}

// goParseNestingViolation returns the first node whose parse nesting
// (measure A) exceeds MaxSourceNesting, or nil. Iterative, run before the
// recursive converter. Like the .runar.ts walk it also refuses a node reached
// through more than MaxSourceNesting+1 chain edges (binary operand, index /
// selector object, callee): convertExpression turns each such parent into a
// Rúnar node holding the converted child, except at the innermost two edges
// of a `runar.Int(x)`-style conversion (callee, then selector on the bare
// `runar` identifier), which build no node. A path of k chain edges is thus
// a Rúnar expression at least k-1 deep, so measure (B) would refuse the tree
// anyway; refusing here keeps the recursive converter off a left-deep chain
// hundreds of thousands of levels deep.
func goParseNestingViolation(file *ast.File) ast.Node {
	work := []goNestItem{{node: file}}
	for len(work) > 0 {
		it := work[len(work)-1]
		work = work[:len(work)-1]
		if it.level > MaxSourceNesting || it.chain > MaxSourceNesting+1 {
			return it.node
		}
		work = append(work, goNestChildren(it)...)
	}
	return nil
}
