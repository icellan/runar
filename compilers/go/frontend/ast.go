// Package frontend implements passes 1-4 of the Rúnar compiler in Go:
// parse, validate, typecheck, and ANF lowering.
package frontend

// ---------------------------------------------------------------------------
// Source locations
// ---------------------------------------------------------------------------

// SourceLocation represents a position in a source file.
type SourceLocation struct {
	File   string
	Line   int
	Column int
}

// ---------------------------------------------------------------------------
// Type nodes
// ---------------------------------------------------------------------------

// TypeNode represents a type annotation in the Rúnar AST.
type TypeNode interface {
	typeNodeMarker()
}

// PrimitiveType is a built-in scalar type like bigint, boolean, ByteString, etc.
type PrimitiveType struct {
	Name string // e.g. "bigint", "boolean", "ByteString", "PubKey", ...
}

func (PrimitiveType) typeNodeMarker() {}

// FixedArrayType is a fixed-length array type: FixedArray<T, N>.
type FixedArrayType struct {
	Element TypeNode
	Length  int
}

func (FixedArrayType) typeNodeMarker() {}

// CustomType is an unrecognized type reference.
type CustomType struct {
	Name string
}

func (CustomType) typeNodeMarker() {}

// ---------------------------------------------------------------------------
// Top-level nodes
// ---------------------------------------------------------------------------

// ContractNode is the parsed representation of a Rúnar smart contract class.
type ContractNode struct {
	Name        string
	ParentClass string // "SmartContract" or "StatefulSmartContract"
	Properties  []PropertyNode
	Constructor MethodNode
	Methods     []MethodNode
	SourceFile  string
}

// PropertyNode represents a contract property declaration.
type PropertyNode struct {
	Name           string
	Type           TypeNode
	Readonly       bool
	Initializer    Expression // may be nil — literal default value
	SourceLocation SourceLocation
}

// MethodNode represents a contract method or constructor.
type MethodNode struct {
	Name           string
	Params         []ParamNode
	Body           []Statement
	Visibility     string // "public" or "private"
	SourceLocation SourceLocation
}

// ParamNode represents a method parameter.
type ParamNode struct {
	Name string
	Type TypeNode
}

// ---------------------------------------------------------------------------
// Statements
// ---------------------------------------------------------------------------

// Statement is the interface for all AST statement nodes.
type Statement interface {
	stmtMarker()
}

// VariableDeclStmt represents `const x: T = expr` or `let x: T = expr`.
type VariableDeclStmt struct {
	Name           string
	Type           TypeNode // may be nil
	Mutable        bool     // const = false, let = true
	Init           Expression
	SourceLocation SourceLocation
}

func (VariableDeclStmt) stmtMarker() {}

// AssignmentStmt represents `target = value`.
type AssignmentStmt struct {
	Target         Expression
	Value          Expression
	SourceLocation SourceLocation
}

func (AssignmentStmt) stmtMarker() {}

// IfStmt represents an if/else statement.
type IfStmt struct {
	Condition      Expression
	Then           []Statement
	Else           []Statement // may be nil
	SourceLocation SourceLocation
}

func (IfStmt) stmtMarker() {}

// ForStmt represents a for loop with constant bounds.
type ForStmt struct {
	Init           VariableDeclStmt
	Condition      Expression
	Update         Statement
	Body           []Statement
	SourceLocation SourceLocation
}

func (ForStmt) stmtMarker() {}

// ReturnStmt represents a return statement.
type ReturnStmt struct {
	Value          Expression // may be nil
	SourceLocation SourceLocation
}

func (ReturnStmt) stmtMarker() {}

// ExpressionStmt represents an expression used as a statement.
type ExpressionStmt struct {
	Expr           Expression
	SourceLocation SourceLocation
}

func (ExpressionStmt) stmtMarker() {}

// ---------------------------------------------------------------------------
// Expressions
// ---------------------------------------------------------------------------

// Expression is the interface for all AST expression nodes.
type Expression interface {
	exprMarker()
}

// BinaryExpr represents a binary operation like `a + b`.
type BinaryExpr struct {
	Op    string // "+", "-", "*", "/", "%", "===", "!==", "<", "<=", ">", ">=", "&&", "||", "&", "|", "^"
	Left  Expression
	Right Expression
}

func (BinaryExpr) exprMarker() {}

// UnaryExpr represents a unary operation like `!a`, `-a`, `~a`.
type UnaryExpr struct {
	Op      string // "!", "-", "~"
	Operand Expression
}

func (UnaryExpr) exprMarker() {}

// CallExpr represents a function/method call.
type CallExpr struct {
	Callee Expression
	Args   []Expression
}

func (CallExpr) exprMarker() {}

// MemberExpr represents a member access like `obj.property` (not `this.x`).
type MemberExpr struct {
	Object   Expression
	Property string
}

func (MemberExpr) exprMarker() {}

// Identifier represents a variable or name reference.
type Identifier struct {
	Name string
}

func (Identifier) exprMarker() {}

// BigIntLiteral represents a bigint literal like `42n`.
type BigIntLiteral struct {
	Value int64
}

func (BigIntLiteral) exprMarker() {}

// BoolLiteral represents a boolean literal.
type BoolLiteral struct {
	Value bool
}

func (BoolLiteral) exprMarker() {}

// ByteStringLiteral represents a hex-encoded byte string literal.
type ByteStringLiteral struct {
	Value string // hex-encoded
}

func (ByteStringLiteral) exprMarker() {}

// TernaryExpr represents a conditional expression: `cond ? a : b`.
type TernaryExpr struct {
	Condition  Expression
	Consequent Expression
	Alternate  Expression
}

func (TernaryExpr) exprMarker() {}

// PropertyAccessExpr represents `this.x` (property access on the contract).
type PropertyAccessExpr struct {
	Property string
}

func (PropertyAccessExpr) exprMarker() {}

// IndexAccessExpr represents `arr[i]`.
type IndexAccessExpr struct {
	Object Expression
	Index  Expression
}

func (IndexAccessExpr) exprMarker() {}

// IncrementExpr represents `i++` or `++i`.
type IncrementExpr struct {
	Operand Expression
	Prefix  bool
}

func (IncrementExpr) exprMarker() {}

// DecrementExpr represents `i--` or `--i`.
type DecrementExpr struct {
	Operand Expression
	Prefix  bool
}

func (DecrementExpr) exprMarker() {}

// ArrayLiteralExpr represents an array literal: [a, b, c].
type ArrayLiteralExpr struct {
	Elements []Expression
}

func (ArrayLiteralExpr) exprMarker() {}

// ---------------------------------------------------------------------------
// Primitive type names
// ---------------------------------------------------------------------------

var primitiveTypeNames = map[string]bool{
	"bigint":         true,
	"boolean":        true,
	"ByteString":     true,
	"PubKey":         true,
	"Sig":            true,
	"Sha256":         true,
	"Ripemd160":      true,
	"Addr":           true,
	"SigHashPreimage": true,
	"RabinSig":       true,
	"RabinPubKey":    true,
	"void":           true,
	"Point":          true,
}

// IsPrimitiveType returns true if the name is a recognized Rúnar primitive type.
func IsPrimitiveType(name string) bool {
	return primitiveTypeNames[name]
}
