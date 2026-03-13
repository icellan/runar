package frontend

import (
	"fmt"
	"strings"
)

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

// TypeCheckResult holds the output of the type checking pass.
type TypeCheckResult struct {
	Contract *ContractNode // same AST, types verified
	Errors   []string
}

// TypeCheck type-checks a Rúnar AST. Returns the same AST plus any errors.
func TypeCheck(contract *ContractNode) *TypeCheckResult {
	checker := newTypeChecker(contract)

	checker.checkConstructor()
	for _, method := range contract.Methods {
		checker.checkMethod(method)
	}

	return &TypeCheckResult{
		Contract: contract,
		Errors:   checker.errors,
	}
}

// ---------------------------------------------------------------------------
// Built-in function signatures
// ---------------------------------------------------------------------------

type funcSig struct {
	params     []string
	returnType string
}

var builtinFunctions = map[string]funcSig{
	"sha256":            {params: []string{"ByteString"}, returnType: "Sha256"},
	"ripemd160":         {params: []string{"ByteString"}, returnType: "Ripemd160"},
	"hash160":           {params: []string{"ByteString"}, returnType: "Ripemd160"},
	"hash256":           {params: []string{"ByteString"}, returnType: "Sha256"},
	"checkSig":          {params: []string{"Sig", "PubKey"}, returnType: "boolean"},
	"checkMultiSig":     {params: []string{"Sig[]", "PubKey[]"}, returnType: "boolean"},
	"assert":            {params: []string{"boolean"}, returnType: "void"},
	"len":               {params: []string{"ByteString"}, returnType: "bigint"},
	"cat":               {params: []string{"ByteString", "ByteString"}, returnType: "ByteString"},
	"substr":            {params: []string{"ByteString", "bigint", "bigint"}, returnType: "ByteString"},
	"num2bin":           {params: []string{"bigint", "bigint"}, returnType: "ByteString"},
	"bin2num":           {params: []string{"ByteString"}, returnType: "bigint"},
	"checkPreimage":     {params: []string{"SigHashPreimage"}, returnType: "boolean"},
	"verifyRabinSig":    {params: []string{"ByteString", "RabinSig", "ByteString", "RabinPubKey"}, returnType: "boolean"},
	"verifyWOTS":        {params: []string{"ByteString", "ByteString", "ByteString"}, returnType: "boolean"},
	"verifySLHDSA_SHA2_128s": {params: []string{"ByteString", "ByteString", "ByteString"}, returnType: "boolean"},
	"verifySLHDSA_SHA2_128f": {params: []string{"ByteString", "ByteString", "ByteString"}, returnType: "boolean"},
	"verifySLHDSA_SHA2_192s": {params: []string{"ByteString", "ByteString", "ByteString"}, returnType: "boolean"},
	"verifySLHDSA_SHA2_192f": {params: []string{"ByteString", "ByteString", "ByteString"}, returnType: "boolean"},
	"verifySLHDSA_SHA2_256s": {params: []string{"ByteString", "ByteString", "ByteString"}, returnType: "boolean"},
	"verifySLHDSA_SHA2_256f": {params: []string{"ByteString", "ByteString", "ByteString"}, returnType: "boolean"},
	"ecAdd":              {params: []string{"Point", "Point"}, returnType: "Point"},
	"ecMul":              {params: []string{"Point", "bigint"}, returnType: "Point"},
	"ecMulGen":           {params: []string{"bigint"}, returnType: "Point"},
	"ecNegate":           {params: []string{"Point"}, returnType: "Point"},
	"ecOnCurve":          {params: []string{"Point"}, returnType: "boolean"},
	"ecModReduce":        {params: []string{"bigint", "bigint"}, returnType: "bigint"},
	"ecEncodeCompressed": {params: []string{"Point"}, returnType: "ByteString"},
	"ecMakePoint":        {params: []string{"bigint", "bigint"}, returnType: "Point"},
	"ecPointX":           {params: []string{"Point"}, returnType: "bigint"},
	"ecPointY":           {params: []string{"Point"}, returnType: "bigint"},
	"sha256Compress":    {params: []string{"ByteString", "ByteString"}, returnType: "ByteString"},
	"sha256Finalize":    {params: []string{"ByteString", "ByteString", "bigint"}, returnType: "ByteString"},
	"blake3Compress":    {params: []string{"ByteString", "ByteString"}, returnType: "ByteString"},
	"blake3Hash":        {params: []string{"ByteString"}, returnType: "ByteString"},
	"abs":               {params: []string{"bigint"}, returnType: "bigint"},
	"min":               {params: []string{"bigint", "bigint"}, returnType: "bigint"},
	"max":               {params: []string{"bigint", "bigint"}, returnType: "bigint"},
	"within":            {params: []string{"bigint", "bigint", "bigint"}, returnType: "boolean"},
	"safediv":           {params: []string{"bigint", "bigint"}, returnType: "bigint"},
	"safemod":           {params: []string{"bigint", "bigint"}, returnType: "bigint"},
	"clamp":             {params: []string{"bigint", "bigint", "bigint"}, returnType: "bigint"},
	"sign":              {params: []string{"bigint"}, returnType: "bigint"},
	"pow":               {params: []string{"bigint", "bigint"}, returnType: "bigint"},
	"mulDiv":            {params: []string{"bigint", "bigint", "bigint"}, returnType: "bigint"},
	"percentOf":         {params: []string{"bigint", "bigint"}, returnType: "bigint"},
	"sqrt":              {params: []string{"bigint"}, returnType: "bigint"},
	"gcd":               {params: []string{"bigint", "bigint"}, returnType: "bigint"},
	"divmod":            {params: []string{"bigint", "bigint"}, returnType: "bigint"},
	"log2":              {params: []string{"bigint"}, returnType: "bigint"},
	"bool":              {params: []string{"bigint"}, returnType: "boolean"},
	"reverseBytes":      {params: []string{"ByteString"}, returnType: "ByteString"},
	"split":             {params: []string{"ByteString", "bigint"}, returnType: "ByteString"},
	"left":              {params: []string{"ByteString", "bigint"}, returnType: "ByteString"},
	"right":             {params: []string{"ByteString", "bigint"}, returnType: "ByteString"},
	"int2str":           {params: []string{"bigint", "bigint"}, returnType: "ByteString"},
	"toByteString":      {params: []string{"ByteString"}, returnType: "ByteString"},
	"exit":              {params: []string{"boolean"}, returnType: "void"},
	"pack":              {params: []string{"bigint"}, returnType: "ByteString"},
	"unpack":            {params: []string{"ByteString"}, returnType: "bigint"},
	"extractVersion":       {params: []string{"SigHashPreimage"}, returnType: "bigint"},
	"extractHashPrevouts":  {params: []string{"SigHashPreimage"}, returnType: "Sha256"},
	"extractHashSequence":  {params: []string{"SigHashPreimage"}, returnType: "Sha256"},
	"extractOutpoint":      {params: []string{"SigHashPreimage"}, returnType: "ByteString"},
	"extractInputIndex":    {params: []string{"SigHashPreimage"}, returnType: "bigint"},
	"extractScriptCode":    {params: []string{"SigHashPreimage"}, returnType: "ByteString"},
	"extractAmount":        {params: []string{"SigHashPreimage"}, returnType: "bigint"},
	"extractSequence":      {params: []string{"SigHashPreimage"}, returnType: "bigint"},
	"extractOutputHash":    {params: []string{"SigHashPreimage"}, returnType: "Sha256"},
	"extractOutputs":       {params: []string{"SigHashPreimage"}, returnType: "Sha256"},
	"extractLocktime":      {params: []string{"SigHashPreimage"}, returnType: "bigint"},
	"extractSigHashType":   {params: []string{"SigHashPreimage"}, returnType: "bigint"},
}

// ---------------------------------------------------------------------------
// Subtyping
// ---------------------------------------------------------------------------

var byteStringSubtypes = map[string]bool{
	"ByteString":     true,
	"PubKey":         true,
	"Sig":            true,
	"Sha256":         true,
	"Ripemd160":      true,
	"Addr":           true,
	"SigHashPreimage": true,
	"Point":          true,
}

var bigintSubtypes = map[string]bool{
	"bigint":      true,
	"RabinSig":    true,
	"RabinPubKey": true,
}

func isSubtype(actual, expected string) bool {
	if actual == expected {
		return true
	}
	// <inferred> and <unknown> are compatible with anything
	if actual == "<inferred>" || actual == "<unknown>" {
		return true
	}
	if expected == "<inferred>" || expected == "<unknown>" {
		return true
	}
	if expected == "ByteString" && byteStringSubtypes[actual] {
		return true
	}
	if expected == "bigint" && bigintSubtypes[actual] {
		return true
	}
	if strings.HasSuffix(expected, "[]") && strings.HasSuffix(actual, "[]") {
		return isSubtype(actual[:len(actual)-2], expected[:len(expected)-2])
	}
	return false
}

func isBigintFamily(t string) bool {
	return bigintSubtypes[t]
}

func isByteFamily(t string) bool {
	return byteStringSubtypes[t]
}

// ---------------------------------------------------------------------------
// Type environment
// ---------------------------------------------------------------------------

type typeEnv struct {
	scopes []map[string]string
}

func newTypeEnv() *typeEnv {
	return &typeEnv{scopes: []map[string]string{make(map[string]string)}}
}

func (e *typeEnv) pushScope() {
	e.scopes = append(e.scopes, make(map[string]string))
}

func (e *typeEnv) popScope() {
	if len(e.scopes) > 0 {
		e.scopes = e.scopes[:len(e.scopes)-1]
	}
}

func (e *typeEnv) define(name, typ string) {
	e.scopes[len(e.scopes)-1][name] = typ
}

func (e *typeEnv) lookup(name string) (string, bool) {
	for i := len(e.scopes) - 1; i >= 0; i-- {
		if t, ok := e.scopes[i][name]; ok {
			return t, true
		}
	}
	return "", false
}

// ---------------------------------------------------------------------------
// Type checker
// ---------------------------------------------------------------------------

// affineTypes are types whose values can be consumed at most once.
var affineTypes = map[string]bool{
	"Sig":             true,
	"SigHashPreimage": true,
}

// consumingFunctions maps function names to the parameter indices that
// consume affine values.
var consumingFunctions = map[string][]int{
	"checkSig":      {0},
	"checkMultiSig": {0},
	"checkPreimage": {0},
}

type typeChecker struct {
	contract       *ContractNode
	errors         []string
	propTypes      map[string]string
	methodSigs     map[string]funcSig
	consumedValues map[string]bool
}

func newTypeChecker(contract *ContractNode) *typeChecker {
	tc := &typeChecker{
		contract:       contract,
		propTypes:      make(map[string]string),
		methodSigs:     make(map[string]funcSig),
		consumedValues: make(map[string]bool),
	}

	for _, prop := range contract.Properties {
		tc.propTypes[prop.Name] = typeNodeToString(prop.Type)
	}

	// For StatefulSmartContract, add the implicit txPreimage property
	if contract.ParentClass == "StatefulSmartContract" {
		tc.propTypes["txPreimage"] = "SigHashPreimage"
	}

	for _, method := range contract.Methods {
		params := make([]string, len(method.Params))
		for i, p := range method.Params {
			params[i] = typeNodeToString(p.Type)
		}
		retType := "void"
		if method.Visibility != "public" {
			retType = inferMethodReturnType(method)
		}
		tc.methodSigs[method.Name] = funcSig{params: params, returnType: retType}
	}

	return tc
}

func (tc *typeChecker) addError(msg string) {
	tc.errors = append(tc.errors, msg)
}

func (tc *typeChecker) checkConstructor() {
	ctor := tc.contract.Constructor
	env := newTypeEnv()

	// Reset affine tracking for this scope
	tc.consumedValues = make(map[string]bool)

	for _, param := range ctor.Params {
		env.define(param.Name, typeNodeToString(param.Type))
	}
	for _, prop := range tc.contract.Properties {
		env.define(prop.Name, typeNodeToString(prop.Type))
	}

	tc.checkStatements(ctor.Body, env)
}

func (tc *typeChecker) checkMethod(method MethodNode) {
	env := newTypeEnv()

	// Reset affine tracking for this method
	tc.consumedValues = make(map[string]bool)

	for _, param := range method.Params {
		env.define(param.Name, typeNodeToString(param.Type))
	}

	tc.checkStatements(method.Body, env)
}

func (tc *typeChecker) checkStatements(stmts []Statement, env *typeEnv) {
	for _, stmt := range stmts {
		tc.checkStatement(stmt, env)
	}
}

func (tc *typeChecker) checkStatement(stmt Statement, env *typeEnv) {
	switch s := stmt.(type) {
	case VariableDeclStmt:
		initType := tc.inferExprType(s.Init, env)
		if s.Type != nil {
			declaredType := typeNodeToString(s.Type)
			if !isSubtype(initType, declaredType) {
				tc.addError(fmt.Sprintf("type '%s' is not assignable to type '%s'", initType, declaredType))
			}
			env.define(s.Name, declaredType)
		} else {
			env.define(s.Name, initType)
		}

	case AssignmentStmt:
		targetType := tc.inferExprType(s.Target, env)
		valueType := tc.inferExprType(s.Value, env)
		if !isSubtype(valueType, targetType) {
			tc.addError(fmt.Sprintf("type '%s' is not assignable to type '%s'", valueType, targetType))
		}

	case IfStmt:
		condType := tc.inferExprType(s.Condition, env)
		if condType != "boolean" {
			tc.addError(fmt.Sprintf("if condition must be boolean, got '%s'", condType))
		}
		env.pushScope()
		tc.checkStatements(s.Then, env)
		env.popScope()
		if len(s.Else) > 0 {
			env.pushScope()
			tc.checkStatements(s.Else, env)
			env.popScope()
		}

	case ForStmt:
		env.pushScope()
		tc.checkStatement(s.Init, env)
		condType := tc.inferExprType(s.Condition, env)
		if condType != "boolean" {
			tc.addError(fmt.Sprintf("for loop condition must be boolean, got '%s'", condType))
		}
		tc.checkStatements(s.Body, env)
		env.popScope()

	case ExpressionStmt:
		tc.inferExprType(s.Expr, env)

	case ReturnStmt:
		if s.Value != nil {
			tc.inferExprType(s.Value, env)
		}
	}
}

// ---------------------------------------------------------------------------
// Type inference
// ---------------------------------------------------------------------------

func (tc *typeChecker) inferExprType(expr Expression, env *typeEnv) string {
	switch e := expr.(type) {
	case BigIntLiteral:
		return "bigint"
	case BoolLiteral:
		return "boolean"
	case ByteStringLiteral:
		return "ByteString"

	case Identifier:
		if e.Name == "this" {
			return "<this>"
		}
		if e.Name == "super" {
			return "<super>"
		}
		if t, ok := env.lookup(e.Name); ok {
			return t
		}
		if _, ok := builtinFunctions[e.Name]; ok {
			return "<builtin>"
		}
		return "<unknown>"

	case PropertyAccessExpr:
		if t, ok := tc.propTypes[e.Property]; ok {
			return t
		}
		return "<unknown>"

	case MemberExpr:
		objType := tc.inferExprType(e.Object, env)
		if objType == "<this>" {
			if t, ok := tc.propTypes[e.Property]; ok {
				return t
			}
			if _, ok := tc.methodSigs[e.Property]; ok {
				return "<method>"
			}
			if e.Property == "getStateScript" {
				return "<method>"
			}
			return "<unknown>"
		}
		if id, ok := e.Object.(Identifier); ok && id.Name == "SigHash" {
			return "bigint"
		}
		return "<unknown>"

	case BinaryExpr:
		return tc.checkBinaryExpr(e, env)

	case UnaryExpr:
		return tc.checkUnaryExpr(e, env)

	case CallExpr:
		return tc.checkCallExpr(e, env)

	case TernaryExpr:
		condType := tc.inferExprType(e.Condition, env)
		if condType != "boolean" {
			tc.addError(fmt.Sprintf("ternary condition must be boolean, got '%s'", condType))
		}
		consType := tc.inferExprType(e.Consequent, env)
		altType := tc.inferExprType(e.Alternate, env)
		if consType != altType {
			if isSubtype(altType, consType) {
				return consType
			}
			if isSubtype(consType, altType) {
				return altType
			}
		}
		return consType

	case IndexAccessExpr:
		objType := tc.inferExprType(e.Object, env)
		indexType := tc.inferExprType(e.Index, env)
		if !isBigintFamily(indexType) {
			tc.addError(fmt.Sprintf("array index must be bigint, got '%s'", indexType))
		}
		if strings.HasSuffix(objType, "[]") {
			return objType[:len(objType)-2]
		}
		return "<unknown>"

	case IncrementExpr:
		operandType := tc.inferExprType(e.Operand, env)
		if !isBigintFamily(operandType) {
			tc.addError(fmt.Sprintf("++ operator requires bigint, got '%s'", operandType))
		}
		return "bigint"

	case DecrementExpr:
		operandType := tc.inferExprType(e.Operand, env)
		if !isBigintFamily(operandType) {
			tc.addError(fmt.Sprintf("-- operator requires bigint, got '%s'", operandType))
		}
		return "bigint"
	}

	return "<unknown>"
}

func (tc *typeChecker) checkBinaryExpr(e BinaryExpr, env *typeEnv) string {
	leftType := tc.inferExprType(e.Left, env)
	rightType := tc.inferExprType(e.Right, env)

	// Arithmetic: bigint x bigint -> bigint
	// Special case: ByteString + ByteString -> ByteString (OP_CAT / byte concatenation)
	switch e.Op {
	case "+":
		if isByteFamily(leftType) && isByteFamily(rightType) {
			return "ByteString"
		}
		if !isBigintFamily(leftType) {
			tc.addError(fmt.Sprintf("left operand of '+' must be bigint or ByteString, got '%s'", leftType))
		}
		if !isBigintFamily(rightType) {
			tc.addError(fmt.Sprintf("right operand of '+' must be bigint or ByteString, got '%s'", rightType))
		}
		return "bigint"

	case "-", "*", "/", "%":
		if !isBigintFamily(leftType) {
			tc.addError(fmt.Sprintf("left operand of '%s' must be bigint, got '%s'", e.Op, leftType))
		}
		if !isBigintFamily(rightType) {
			tc.addError(fmt.Sprintf("right operand of '%s' must be bigint, got '%s'", e.Op, rightType))
		}
		return "bigint"

	case "<", "<=", ">", ">=":
		if !isBigintFamily(leftType) {
			tc.addError(fmt.Sprintf("left operand of '%s' must be bigint, got '%s'", e.Op, leftType))
		}
		if !isBigintFamily(rightType) {
			tc.addError(fmt.Sprintf("right operand of '%s' must be bigint, got '%s'", e.Op, rightType))
		}
		return "boolean"

	case "===", "!==":
		// Allow comparison between compatible types (both ByteString family or both bigint family)
		compatible := isSubtype(leftType, rightType) || isSubtype(rightType, leftType) ||
			(byteStringSubtypes[leftType] && byteStringSubtypes[rightType]) ||
			(bigintSubtypes[leftType] && bigintSubtypes[rightType])
		if !compatible {
			if leftType != "<unknown>" && rightType != "<unknown>" {
				tc.addError(fmt.Sprintf("cannot compare '%s' and '%s' with '%s'", leftType, rightType, e.Op))
			}
		}
		return "boolean"

	case "&&", "||":
		if leftType != "boolean" && leftType != "<unknown>" {
			tc.addError(fmt.Sprintf("left operand of '%s' must be boolean, got '%s'", e.Op, leftType))
		}
		if rightType != "boolean" && rightType != "<unknown>" {
			tc.addError(fmt.Sprintf("right operand of '%s' must be boolean, got '%s'", e.Op, rightType))
		}
		return "boolean"

	case "<<", ">>":
		if !isBigintFamily(leftType) {
			tc.addError(fmt.Sprintf("left operand of '%s' must be bigint, got '%s'", e.Op, leftType))
		}
		if !isBigintFamily(rightType) {
			tc.addError(fmt.Sprintf("right operand of '%s' must be bigint, got '%s'", e.Op, rightType))
		}
		return "bigint"

	case "&", "|", "^":
		// Bitwise operators: bigint x bigint -> bigint, or ByteString x ByteString -> ByteString
		if isByteFamily(leftType) && isByteFamily(rightType) {
			return "ByteString"
		}
		if !isBigintFamily(leftType) {
			tc.addError(fmt.Sprintf("left operand of '%s' must be bigint or ByteString, got '%s'", e.Op, leftType))
		}
		if !isBigintFamily(rightType) {
			tc.addError(fmt.Sprintf("right operand of '%s' must be bigint or ByteString, got '%s'", e.Op, rightType))
		}
		return "bigint"
	}

	return "<unknown>"
}

func (tc *typeChecker) checkUnaryExpr(e UnaryExpr, env *typeEnv) string {
	operandType := tc.inferExprType(e.Operand, env)

	switch e.Op {
	case "!":
		if operandType != "boolean" && operandType != "<unknown>" {
			tc.addError(fmt.Sprintf("operand of '!' must be boolean, got '%s'", operandType))
		}
		return "boolean"
	case "-":
		if !isBigintFamily(operandType) {
			tc.addError(fmt.Sprintf("operand of unary '-' must be bigint, got '%s'", operandType))
		}
		return "bigint"
	case "~":
		// Bitwise NOT: bigint -> bigint, or ByteString -> ByteString
		if isByteFamily(operandType) {
			return "ByteString"
		}
		if !isBigintFamily(operandType) {
			tc.addError(fmt.Sprintf("operand of '~' must be bigint or ByteString, got '%s'", operandType))
		}
		return "bigint"
	}

	return "<unknown>"
}

func (tc *typeChecker) checkCallExpr(e CallExpr, env *typeEnv) string {
	// super() call
	if id, ok := e.Callee.(Identifier); ok && id.Name == "super" {
		for _, arg := range e.Args {
			tc.inferExprType(arg, env)
		}
		return "void"
	}

	// Direct builtin call
	if id, ok := e.Callee.(Identifier); ok {
		if sig, ok := builtinFunctions[id.Name]; ok {
			return tc.checkCallArgs(id.Name, sig, e.Args, env)
		}
		// Check if it's a known contract method
		if sig, ok := tc.methodSigs[id.Name]; ok {
			return tc.checkCallArgs(id.Name, sig, e.Args, env)
		}
		// Check if it's a local variable
		if _, found := env.lookup(id.Name); found {
			for _, arg := range e.Args {
				tc.inferExprType(arg, env)
			}
			return "<unknown>"
		}
		tc.errors = append(tc.errors, fmt.Sprintf(
			"unknown function '%s' — only Rúnar built-in functions and contract methods are allowed", id.Name))
		for _, arg := range e.Args {
			tc.inferExprType(arg, env)
		}
		return "<unknown>"
	}

	// this.method() via PropertyAccessExpr
	if pa, ok := e.Callee.(PropertyAccessExpr); ok {
		if pa.Property == "getStateScript" {
			return "ByteString"
		}
		if pa.Property == "addOutput" || pa.Property == "addRawOutput" {
			for _, arg := range e.Args {
				tc.inferExprType(arg, env)
			}
			return "void"
		}
		if sig, ok := tc.methodSigs[pa.Property]; ok {
			return tc.checkCallArgs(pa.Property, sig, e.Args, env)
		}
		tc.errors = append(tc.errors, fmt.Sprintf(
			"unknown method 'this.%s' — only Rúnar built-in methods and contract methods are allowed", pa.Property))
		for _, arg := range e.Args {
			tc.inferExprType(arg, env)
		}
		return "<unknown>"
	}

	// this.method() via MemberExpr
	if me, ok := e.Callee.(MemberExpr); ok {
		objType := tc.inferExprType(me.Object, env)
		if objType == "<this>" || (func() bool {
			id, ok := me.Object.(Identifier)
			return ok && id.Name == "this"
		})() {
			if me.Property == "getStateScript" {
				return "ByteString"
			}
			if sig, ok := tc.methodSigs[me.Property]; ok {
				return tc.checkCallArgs(me.Property, sig, e.Args, env)
			}
		}
		// Not this.method — reject (e.g. Math.floor)
		objName := "<expr>"
		if id, ok := me.Object.(Identifier); ok {
			objName = id.Name
		}
		tc.errors = append(tc.errors, fmt.Sprintf(
			"unknown function '%s.%s' — only Rúnar built-in functions and contract methods are allowed",
			objName, me.Property))
		for _, arg := range e.Args {
			tc.inferExprType(arg, env)
		}
		return "<unknown>"
	}

	// Fallback — unknown callee shape
	tc.errors = append(tc.errors, "unsupported function call expression — only Rúnar built-in functions and contract methods are allowed")
	tc.inferExprType(e.Callee, env)
	for _, arg := range e.Args {
		tc.inferExprType(arg, env)
	}
	return "<unknown>"
}

func (tc *typeChecker) checkCallArgs(funcName string, sig funcSig, args []Expression, env *typeEnv) string {
	// assert special case
	if funcName == "assert" {
		if len(args) < 1 || len(args) > 2 {
			tc.addError(fmt.Sprintf("assert() expects 1 or 2 arguments, got %d", len(args)))
		}
		if len(args) >= 1 {
			condType := tc.inferExprType(args[0], env)
			if condType != "boolean" && condType != "<unknown>" {
				tc.addError(fmt.Sprintf("assert() condition must be boolean, got '%s'", condType))
			}
		}
		if len(args) >= 2 {
			tc.inferExprType(args[1], env)
		}
		return sig.returnType
	}

	// checkMultiSig special case
	if funcName == "checkMultiSig" {
		for _, arg := range args {
			tc.inferExprType(arg, env)
		}
		tc.checkAffineConsumption(funcName, args, env)
		return sig.returnType
	}

	// Standard arg count check
	if len(args) != len(sig.params) {
		tc.addError(fmt.Sprintf("%s() expects %d argument(s), got %d", funcName, len(sig.params), len(args)))
	}

	count := len(args)
	if count > len(sig.params) {
		count = len(sig.params)
	}

	for i := 0; i < count; i++ {
		argType := tc.inferExprType(args[i], env)
		expectedType := sig.params[i]
		if !isSubtype(argType, expectedType) && argType != "<unknown>" {
			tc.addError(fmt.Sprintf("argument %d of %s(): expected '%s', got '%s'", i+1, funcName, expectedType, argType))
		}
	}

	for i := count; i < len(args); i++ {
		tc.inferExprType(args[i], env)
	}

	// Affine type enforcement
	tc.checkAffineConsumption(funcName, args, env)

	return sig.returnType
}

// checkAffineConsumption enforces that affine-typed values (Sig,
// SigHashPreimage) are consumed at most once by a consuming function.
func (tc *typeChecker) checkAffineConsumption(funcName string, args []Expression, env *typeEnv) {
	consumedIndices, ok := consumingFunctions[funcName]
	if !ok {
		return
	}

	for _, paramIndex := range consumedIndices {
		if paramIndex >= len(args) {
			continue
		}

		arg := args[paramIndex]
		id, isIdent := arg.(Identifier)
		if !isIdent {
			continue
		}

		argType, found := env.lookup(id.Name)
		if !found || !affineTypes[argType] {
			continue
		}

		if tc.consumedValues[id.Name] {
			tc.addError(fmt.Sprintf("affine value '%s' has already been consumed", id.Name))
		} else {
			tc.consumedValues[id.Name] = true
		}
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Private method return type inference
// ---------------------------------------------------------------------------

// inferMethodReturnType walks the body of a private method, collects
// return statement expressions, infers their types statically, and returns
// a unified return type. Falls back to "void" if no return statements.
func inferMethodReturnType(method MethodNode) string {
	returnTypes := collectReturnTypes(method.Body)
	if len(returnTypes) == 0 {
		return "void"
	}

	first := returnTypes[0]
	allSame := true
	for _, t := range returnTypes[1:] {
		if t != first {
			allSame = false
			break
		}
	}
	if allSame {
		return first
	}

	// Check if all are in the bigint family
	allBigint := true
	for _, t := range returnTypes {
		if !bigintSubtypes[t] {
			allBigint = false
			break
		}
	}
	if allBigint {
		return "bigint"
	}

	// Check if all are in the ByteString family
	allBytes := true
	for _, t := range returnTypes {
		if !byteStringSubtypes[t] {
			allBytes = false
			break
		}
	}
	if allBytes {
		return "ByteString"
	}

	// Check if all are boolean
	allBool := true
	for _, t := range returnTypes {
		if t != "boolean" {
			allBool = false
			break
		}
	}
	if allBool {
		return "boolean"
	}

	return first
}

// collectReturnTypes recursively collects inferred types from return
// statements in a list of statements.
func collectReturnTypes(stmts []Statement) []string {
	var types []string
	for _, stmt := range stmts {
		switch s := stmt.(type) {
		case ReturnStmt:
			if s.Value != nil {
				types = append(types, inferExprTypeStatic(s.Value))
			}
		case IfStmt:
			types = append(types, collectReturnTypes(s.Then)...)
			if len(s.Else) > 0 {
				types = append(types, collectReturnTypes(s.Else)...)
			}
		case ForStmt:
			types = append(types, collectReturnTypes(s.Body)...)
		}
	}
	return types
}

// inferExprTypeStatic performs lightweight expression type inference
// without a type environment. Used for inferring return types of private
// methods before the full type-check pass runs.
func inferExprTypeStatic(expr Expression) string {
	switch e := expr.(type) {
	case BigIntLiteral:
		return "bigint"
	case BoolLiteral:
		return "boolean"
	case ByteStringLiteral:
		return "ByteString"
	case Identifier:
		if e.Name == "true" || e.Name == "false" {
			return "boolean"
		}
		return "<unknown>"
	case BinaryExpr:
		switch e.Op {
		case "+", "-", "*", "/", "%", "&", "|", "^", "<<", ">>":
			return "bigint"
		default:
			// Comparison, equality, logical operators -> boolean
			return "boolean"
		}
	case UnaryExpr:
		if e.Op == "!" {
			return "boolean"
		}
		return "bigint" // '-' and '~'
	case CallExpr:
		if id, ok := e.Callee.(Identifier); ok {
			if sig, ok := builtinFunctions[id.Name]; ok {
				return sig.returnType
			}
		}
		if pa, ok := e.Callee.(PropertyAccessExpr); ok {
			if sig, ok := builtinFunctions[pa.Property]; ok {
				return sig.returnType
			}
		}
		return "<unknown>"
	case TernaryExpr:
		consType := inferExprTypeStatic(e.Consequent)
		if consType != "<unknown>" {
			return consType
		}
		return inferExprTypeStatic(e.Alternate)
	case IncrementExpr, DecrementExpr:
		return "bigint"
	}
	return "<unknown>"
}

func typeNodeToString(node TypeNode) string {
	if node == nil {
		return "<unknown>"
	}
	switch n := node.(type) {
	case PrimitiveType:
		return n.Name
	case FixedArrayType:
		return typeNodeToString(n.Element) + "[]"
	case CustomType:
		return n.Name
	}
	return "<unknown>"
}
