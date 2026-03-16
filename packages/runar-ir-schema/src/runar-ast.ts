/**
 * Rúnar AST — the typed abstract syntax tree produced by the parser (Pass 1).
 *
 * This representation is still high-level: it preserves source locations,
 * syntactic sugar (for-loops, ternary expressions, increment/decrement), and
 * the original type annotations written by the user.
 */

// ---------------------------------------------------------------------------
// Source locations
// ---------------------------------------------------------------------------

export interface SourceLocation {
  file: string;
  line: number;
  column: number;
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type PrimitiveTypeName =
  | 'bigint'
  | 'boolean'
  | 'ByteString'
  | 'PubKey'
  | 'Sig'
  | 'Sha256'
  | 'Ripemd160'
  | 'Addr'
  | 'SigHashPreimage'
  | 'RabinSig'
  | 'RabinPubKey'
  | 'Point';

export interface PrimitiveTypeNode {
  kind: 'primitive_type';
  name: PrimitiveTypeName;
}

export interface FixedArrayTypeNode {
  kind: 'fixed_array_type';
  element: TypeNode;
  length: number;
}

export interface CustomTypeNode {
  kind: 'custom_type';
  name: string;
}

export type TypeNode = PrimitiveTypeNode | FixedArrayTypeNode | CustomTypeNode;

// ---------------------------------------------------------------------------
// Top-level nodes
// ---------------------------------------------------------------------------

export interface ContractNode {
  kind: 'contract';
  name: string;
  parentClass: 'SmartContract' | 'StatefulSmartContract';
  properties: PropertyNode[];
  constructor: MethodNode;
  methods: MethodNode[];
  sourceFile: string;
}

export interface PropertyNode {
  kind: 'property';
  name: string;
  type: TypeNode;
  readonly: boolean;
  initializer?: Expression;
  sourceLocation: SourceLocation;
}

export interface MethodNode {
  kind: 'method';
  name: string;
  params: ParamNode[];
  body: Statement[];
  visibility: 'public' | 'private';
  sourceLocation: SourceLocation;
}

export interface ParamNode {
  kind: 'param';
  name: string;
  type: TypeNode;
}

// ---------------------------------------------------------------------------
// Statements
// ---------------------------------------------------------------------------

export interface VariableDeclStatement {
  kind: 'variable_decl';
  name: string;
  type?: TypeNode;
  init: Expression;
  sourceLocation: SourceLocation;
}

export interface AssignmentStatement {
  kind: 'assignment';
  target: Expression;
  value: Expression;
  sourceLocation: SourceLocation;
}

export interface IfStatement {
  kind: 'if_statement';
  condition: Expression;
  then: Statement[];
  else?: Statement[];
  sourceLocation: SourceLocation;
}

export interface ForStatement {
  kind: 'for_statement';
  init: VariableDeclStatement;
  condition: Expression;
  update: Statement;
  body: Statement[];
  sourceLocation: SourceLocation;
}

export interface ReturnStatement {
  kind: 'return_statement';
  value?: Expression;
  sourceLocation: SourceLocation;
}

export interface ExpressionStatement {
  kind: 'expression_statement';
  expression: Expression;
  sourceLocation: SourceLocation;
}

export type Statement =
  | VariableDeclStatement
  | AssignmentStatement
  | IfStatement
  | ForStatement
  | ReturnStatement
  | ExpressionStatement;

// ---------------------------------------------------------------------------
// Expressions
// ---------------------------------------------------------------------------

export type BinaryOp =
  | '+'
  | '-'
  | '*'
  | '/'
  | '%'
  | '==='
  | '!=='
  | '<'
  | '<='
  | '>'
  | '>='
  | '&&'
  | '||'
  | '&'
  | '|'
  | '^'
  | '<<'
  | '>>';

export type UnaryOp = '!' | '-' | '~';

export interface BinaryExpr {
  kind: 'binary_expr';
  op: BinaryOp;
  left: Expression;
  right: Expression;
}

export interface UnaryExpr {
  kind: 'unary_expr';
  op: UnaryOp;
  operand: Expression;
}

export interface CallExpr {
  kind: 'call_expr';
  callee: Expression;
  args: Expression[];
}

export interface MemberExpr {
  kind: 'member_expr';
  object: Expression;
  property: string;
}

export interface Identifier {
  kind: 'identifier';
  name: string;
}

export interface BigIntLiteral {
  kind: 'bigint_literal';
  value: bigint;
}

export interface BoolLiteral {
  kind: 'bool_literal';
  value: boolean;
}

export interface ByteStringLiteral {
  kind: 'bytestring_literal';
  value: string; // hex-encoded
}

export interface TernaryExpr {
  kind: 'ternary_expr';
  condition: Expression;
  consequent: Expression;
  alternate: Expression;
}

export interface PropertyAccessExpr {
  kind: 'property_access';
  property: string; // `this.x` → property = "x"
}

export interface IndexAccessExpr {
  kind: 'index_access';
  object: Expression;
  index: Expression;
}

export interface IncrementExpr {
  kind: 'increment_expr';
  operand: Expression;
  prefix: boolean;
}

export interface DecrementExpr {
  kind: 'decrement_expr';
  operand: Expression;
  prefix: boolean;
}

export interface ArrayLiteralExpr {
  kind: 'array_literal';
  elements: Expression[];
}

export type Expression =
  | BinaryExpr
  | UnaryExpr
  | CallExpr
  | MemberExpr
  | Identifier
  | BigIntLiteral
  | BoolLiteral
  | ByteStringLiteral
  | TernaryExpr
  | PropertyAccessExpr
  | IndexAccessExpr
  | IncrementExpr
  | DecrementExpr
  | ArrayLiteralExpr;
