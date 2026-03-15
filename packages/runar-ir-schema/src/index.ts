/**
 * runar-ir-schema — type definitions, JSON schemas, and validators for every
 * intermediate representation in the Rúnar compiler pipeline.
 *
 * Re-exports everything so consumers can `import { ANFProgram, validateANF } from 'runar-ir-schema'`.
 */

// Rúnar AST (Pass 1 output)
export type {
  SourceLocation,
  PrimitiveTypeName,
  PrimitiveTypeNode,
  FixedArrayTypeNode,
  CustomTypeNode,
  TypeNode,
  ContractNode,
  PropertyNode,
  MethodNode,
  ParamNode,
  VariableDeclStatement,
  AssignmentStatement,
  IfStatement,
  ForStatement,
  ReturnStatement,
  ExpressionStatement,
  Statement,
  BinaryOp,
  UnaryOp,
  BinaryExpr,
  UnaryExpr,
  CallExpr,
  MemberExpr,
  Identifier,
  BigIntLiteral,
  BoolLiteral,
  ByteStringLiteral,
  TernaryExpr,
  PropertyAccessExpr,
  IndexAccessExpr,
  IncrementExpr,
  DecrementExpr,
  Expression,
} from './runar-ast.js';

// ANF IR (Pass 4 output — canonical conformance boundary)
export type {
  ANFProgram,
  ANFProperty,
  ANFMethod,
  ANFParam,
  ANFBinding,
  LoadParam,
  LoadProp,
  LoadConst,
  BinOp,
  UnaryOp as ANFUnaryOp,
  Call,
  MethodCall,
  If,
  Loop,
  Assert,
  UpdateProp,
  GetStateScript,
  CheckPreimage,
  AddOutput,
  ANFValue,
} from './anf-ir.js';

// Stack IR (Pass 5 output)
export type {
  StackProgram,
  StackMethod,
  StackSourceLoc,
  PushOp,
  DupOp,
  SwapOp,
  RollOp,
  PickOp,
  DropOp,
  OpcodeOp,
  IfOp,
  NipOp,
  OverOp,
  RotOp,
  TuckOp,
  PlaceholderOp,
  StackOp,
} from './stack-ir.js';

// Compiled artifact (Pass 6 output)
export type {
  ABIParam,
  ABIConstructor,
  ABIMethod,
  ABI,
  SourceMapping,
  SourceMap,
  StateField,
  ConstructorSlot,
  RunarArtifact,
} from './artifact.js';

// Validators
export {
  validateANF,
  validateArtifact,
  assertValidANF,
  assertValidArtifact,
} from './validators.js';
export type {
  ValidationResult,
  ValidationSuccess,
  ValidationFailure,
  ValidationError,
} from './validators.js';

// Canonical JSON
export {
  canonicalJsonStringify,
  canonicalise,
} from './canonical-json.js';
