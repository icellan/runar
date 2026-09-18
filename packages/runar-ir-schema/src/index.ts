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
  BindingVariant,
  ANFProgram,
  ANFProperty,
  ANFSyntheticArrayLevel,
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
  // R-251: members of the ANFValue union that the barrel did not re-export, so
  // a consumer could import ANFValue and not name the member to narrow it to.
  AddRawOutput,
  AddDataOutput,
  DeserializeState,
  ArrayLiteral,
  RawScript,
  ANFValue,
} from './anf-ir.js';

export { MERGED_LOCAL_TEMP_PREFIX } from './anf-ir.js';

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
  // R-251: members of the StackOp union, same omission.
  PushCodeSepIndexOp,
  VerifyCodePartLenOp,
  RawBytesOp,
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
  CodeSepIndexSlot,
  TemplateDigest,
  TemplateDigestPiece,
  RunarArtifact,
} from './artifact.js';

// State-tail byte layout (shared width table: compiler + SDK + verifiers)
export {
  STATE_FIELD_WIDTHS,
  annotateStateFieldLayout,
  totalStateByteLength,
} from './state-layout.js';
export type { StateFieldEncoding } from './state-layout.js';

// Constructor-slot value encoding (shared classification: compiler + CLI + SDKs)
export { ABI_VALUE_ENCODINGS, abiValueEncoding } from './abi-type-encoding.js';
export type { AbiValueEncoding } from './abi-type-encoding.js';

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

// Input limits + typed error (foundation for size guards, item 5)
export { InputLimits, CanonicalJsonError } from './input-limits.js';
export type { InputLimitsKey } from './input-limits.js';

// Hard error for unknown ANF kinds (item 3 / F-003)
export { UnknownANFKindError } from './unknown-anf-kind-error.js';
