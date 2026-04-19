package frontend

import (
	"encoding/hex"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"math/big"
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
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, fileName, source, parser.ParseComments)
	if err != nil {
		return &ParseResult{Errors: []Diagnostic{{Message: fmt.Sprintf("Go parse error: %v", err), Severity: SeverityError}}}
	}

	p := &goContractParser{
		fset:     fset,
		file:     file,
		fileName: fileName,
	}

	contract := p.extractContract()
	if contract == nil && len(p.errors) == 0 {
		p.addError("no Rúnar contract struct found in Go source")
	}

	return &ParseResult{
		Contract: contract,
		Errors:   p.errors,
	}
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
}

func (p *goContractParser) addError(msg string) {
	p.errors = append(p.errors, Diagnostic{Message: msg, Severity: SeverityError})
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
			for _, field := range structType.Fields.List {
				if sel, ok := field.Type.(*ast.SelectorExpr); ok {
					if ident, ok := sel.X.(*ast.Ident); ok && ident.Name == "runar" {
						switch sel.Sel.Name {
						case "SmartContract":
							parentClass = "SmartContract"
							found = true
						case "StatefulSmartContract":
							parentClass = "StatefulSmartContract"
							found = true
						}
					}
				}
			}
			if !found {
				continue
			}

			contractName = typeSpec.Name.Name

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
					propName := goFieldToCamel(name.Name)
					propType := p.resolveType(field.Type)

					// Check struct tag for readonly
					readonly := false
					if field.Tag != nil {
						tagStr := field.Tag.Value
						if strings.Contains(tagStr, `runar:"readonly"`) {
							readonly = true
						}
					}

					pos := p.fset.Position(field.Pos())
					properties = append(properties, PropertyNode{
						Name:     propName,
						Type:     propType,
						Readonly: readonly,
						SourceLocation: SourceLocation{
							File:   p.fileName,
							Line:   pos.Line,
							Column: pos.Column,
						},
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

		// Check receiver is *ContractName
		if len(funcDecl.Recv.List) == 0 {
			continue
		}
		recvType := funcDecl.Recv.List[0].Type
		if star, ok := recvType.(*ast.StarExpr); ok {
			if ident, ok := star.X.(*ast.Ident); ok {
				if ident.Name != contractName {
					continue
				}
			}
		}

		methodName := goFieldToCamel(funcDecl.Name.Name)
		// Exported (capitalized) = public
		visibility := "private"
		if funcDecl.Name.IsExported() {
			visibility = "public"
		}

		// Extract receiver name for property access resolution
		if len(funcDecl.Recv.List[0].Names) > 0 {
			p.receiverName = funcDecl.Recv.List[0].Names[0].Name
		} else {
			p.receiverName = "c" // default
		}

		params := p.extractParams(funcDecl.Type.Params)
		body := p.extractStatements(funcDecl.Body)

		pos := p.fset.Position(funcDecl.Pos())
		methods = append(methods, MethodNode{
			Name:       methodName,
			Params:     params,
			Body:       body,
			Visibility: visibility,
			SourceLocation: SourceLocation{
				File:   p.fileName,
				Line:   pos.Line,
				Column: pos.Column,
			},
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
			continue
		}
		// Standalone functions must be unexported (private helpers)
		if funcDecl.Name.IsExported() {
			continue
		}

		methodName := goFieldToCamel(funcDecl.Name.Name)
		p.receiverName = "" // no receiver for standalone functions

		params := p.extractParams(funcDecl.Type.Params)
		body := p.extractStatements(funcDecl.Body)

		pos := p.fset.Position(funcDecl.Pos())
		methods = append(methods, MethodNode{
			Name:       methodName,
			Params:     params,
			Body:       body,
			Visibility: "private",
			SourceLocation: SourceLocation{
				File:   p.fileName,
				Line:   pos.Line,
				Column: pos.Column,
			},
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
		SourceLocation: SourceLocation{File: p.fileName, Line: 1, Column: 1},
	}

	// Property assignments
	constructorBody := make([]Statement, 0, 1+len(uninitProps))
	constructorBody = append(constructorBody, superCall)
	for _, prop := range uninitProps {
		constructorBody = append(constructorBody, AssignmentStmt{
			Target:         PropertyAccessExpr{Property: prop.Name},
			Value:          Identifier{Name: prop.Name},
			SourceLocation: SourceLocation{File: p.fileName, Line: 1, Column: 1},
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
			SourceLocation: SourceLocation{File: p.fileName, Line: 1, Column: 1},
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
				Name: goFieldToCamel(name.Name),
				Type: paramType,
			})
		}
	}
	return params
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
				p.fileName, pos.Line, pos.Column))
		}
	}
	return stmts
}

func (p *goContractParser) convertStatement(stmt ast.Stmt) Statement {
	pos := p.fset.Position(stmt.Pos())
	loc := SourceLocation{File: p.fileName, Line: pos.Line, Column: pos.Column}

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
			return AssignmentStmt{Target: target, Value: value, SourceLocation: loc}
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
				name := goFieldToCamel(valueSpec.Names[0].Name)
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
			// receiver.Field -> property access (e.g. c.Count, m.Value)
			if ident.Name == p.receiverName || ident.Name == "c" || ident.Name == "self" {
				return PropertyAccessExpr{Property: goFieldToCamel(e.Sel.Name)}
			}
			// Any other package selector (math.Log, fmt.Println, etc.) is not valid Rúnar
			pos := p.fset.Position(e.Pos())
			p.addError(fmt.Sprintf(
				"unsupported expression '%s.%s' at %s:%d:%d — only runar.* builtins and contract field access are allowed",
				ident.Name, e.Sel.Name, p.fileName, pos.Line, pos.Column))
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

		callee := p.convertExpression(e.Fun)
		var args []Expression
		for _, arg := range e.Args {
			a := p.convertExpression(arg)
			if a != nil {
				args = append(args, a)
			}
		}
		// runar.Assert(expr) -> assert(expr)
		if ident, ok := callee.(Identifier); ok && ident.Name == "assert" {
			return CallExpr{Callee: Identifier{Name: "assert"}, Args: args}
		}
		// runar.FuncName(args) -> funcName(args) for builtins
		return CallExpr{Callee: callee, Args: args}

	case *ast.BinaryExpr:
		left := p.convertExpression(e.X)
		right := p.convertExpression(e.Y)
		op := mapGoOp(e.Op)
		if left == nil || right == nil {
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

func mapGoOp(op token.Token) string {
	switch op {
	case token.ADD:
		return "+"
	case token.SUB:
		return "-"
	case token.MUL:
		return "*"
	case token.QUO:
		return "/"
	case token.REM:
		return "%"
	case token.EQL:
		return "==="
	case token.NEQ:
		return "!=="
	case token.LSS:
		return "<"
	case token.LEQ:
		return "<="
	case token.GTR:
		return ">"
	case token.GEQ:
		return ">="
	case token.LAND:
		return "&&"
	case token.LOR:
		return "||"
	case token.AND:
		return "&"
	case token.OR:
		return "|"
	case token.XOR:
		return "^"
	case token.SHL:
		return "<<"
	case token.SHR:
		return ">>"
	}
	return "+"
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
		"VerifyECDSAP256":         "verifyECDSA_P256",
		"VerifyECDSAP384":         "verifyECDSA_P384",
		"Num2Bin":           "num2bin",
		"Bin2Num":           "bin2num",
		"Bin2NumBig":        "bin2num",
		"Num2BinBig":        "num2bin",
		"Cat":               "cat",
		"Substr":            "substr",
		"Len":               "len",
		"ReverseBytes":      "reverseBytes",
		"ExtractLocktime":   "extractLocktime",
		"ExtractOutputHash": "extractOutputHash",
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
	// Find the prefix of uppercase runes
	i := 0
	for i < len(r) && unicode.IsUpper(r[i]) {
		i++
	}
	if i == 0 {
		return name
	}
	if i == 1 {
		// Simple case: just lowercase the first letter
		r[0] = unicode.ToLower(r[0])
		return string(r)
	}
	// Multiple uppercase: lowercase all but the last one
	// e.g., "HTTPServer" -> "httpServer", "PubKeyHash" -> stays as-is since P is single
	// Actually for Go exported names, just lowercase the first letter
	r[0] = unicode.ToLower(r[0])
	return string(r)
}
