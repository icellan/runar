/**
 * Pass 1: Parse
 *
 * Multi-format parser dispatcher. Detects the source format by file extension
 * and routes to the appropriate parser:
 *   - `.runar.ts`   → TypeScript (ts-morph)
 *   - `.runar.sol`  → Solidity-like syntax
 *   - `.runar.move` → Move-style resource language
 *   - `.runar.py`   → Python (hand-written tokenizer with INDENT/DEDENT + recursive descent)
 *   - `.runar.go`   → Go (hand-written tokenizer + recursive descent, extends ParserCore)
 *   - `.runar.rs`   → Rust (hand-written tokenizer + recursive descent, extends ParserCore)
 *   - `.runar.zig`  → Zig (hand-written tokenizer + recursive descent, extends ParserCore)
 *   - `.runar.java` → Java (hand-written tokenizer + recursive descent)
 */

import {
  Project,
  SyntaxKind,
  Node,
  ts,
} from 'ts-morph';
import type {
  CallExpression,
  ClassDeclaration,
  MethodDeclaration,
  ConstructorDeclaration,
  ParameterDeclaration,
} from 'ts-morph';

import type {
  ContractNode,
  PropertyNode,
  MethodNode,
  ParamNode,
  TypeNode,
  PrimitiveTypeName,
  Statement,
  Expression,
  SourceLocation,
  BinaryOp,
  UnaryOp,
  VariableDeclStatement,
  IfStatement,
  ForStatement,
  ReturnStatement,
} from '../ir/index.js';
import type { CompilerDiagnostic } from '../errors.js';
import { makeDiagnostic } from '../errors.js';
import { parseSolSource } from './01-parse-sol.js';
import { parseMoveSource } from './01-parse-move.js';
import { parsePythonSource } from './01-parse-python.js';
import { parseGoSource } from './01-parse-go.js';
import { parseRustSource } from './01-parse-rust.js';
import { parseRubySource } from './01-parse-ruby.js';
import { parseZigSource } from './01-parse-zig.js';
import { parseJavaSource } from './01-parse-java.js';
import { OPCODES } from './06-emit.js';
import {
  encodePushBigIntHex,
  encodePushBytesHex,
  byteToHex,
} from './push-encoding.js';

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export interface ParseResult {
  contract: ContractNode | null;
  errors: CompilerDiagnostic[];
}

/**
 * Parse a Rúnar source string and extract the contract AST.
 *
 * Auto-detects the source format by file extension and dispatches to the
 * appropriate parser. All parsers produce the same Rúnar AST.
 */
export function parse(source: string, fileName?: string): ParseResult {
  const errors: CompilerDiagnostic[] = [];
  const file = fileName ?? 'contract.ts';

  // Multi-format dispatch based on file extension
  if (file.endsWith('.runar.sol')) {
    return parseSolSource(source, file);
  }
  if (file.endsWith('.runar.move')) {
    return parseMoveSource(source, file);
  }
  if (file.endsWith('.runar.py')) {
    return parsePythonSource(source, file);
  }
  if (file.endsWith('.runar.go')) {
    return parseGoSource(source, file);
  }
  if (file.endsWith('.runar.rs')) {
    return parseRustSource(source, file);
  }
  if (file.endsWith('.runar.rb')) {
    return parseRubySource(source, file);
  }
  if (file.endsWith('.runar.zig')) {
    return parseZigSource(source, file);
  }
  if (file.endsWith('.runar.java')) {
    return parseJavaSource(source, file);
  }

  // Default: TypeScript parser (for .runar.ts and any unrecognized extension)

  const project = new Project({
    useInMemoryFileSystem: true,
    compilerOptions: {
      target: ts.ScriptTarget.ES2022,
      strict: true,
      noEmit: true,
    },
  });

  const sourceFile = project.createSourceFile(file, source);

  // Find the class that extends SmartContract, StatefulSmartContract,
  // or UnsafeSmartContract (the asm() escape hatch).
  const VALID_BASE_CLASSES = new Set([
    'SmartContract',
    'StatefulSmartContract',
    'UnsafeSmartContract',
  ]);
  const classes = sourceFile.getClasses();
  let contractClass: ClassDeclaration | undefined;
  let detectedParentClass: 'SmartContract' | 'StatefulSmartContract' | 'UnsafeSmartContract' = 'SmartContract';

  for (const cls of classes) {
    const ext = cls.getExtends();
    if (ext) {
      const baseText = ext.getExpression().getText();
      if (VALID_BASE_CLASSES.has(baseText)) {
        if (contractClass) {
          errors.push(makeDiagnostic(
            'Only one SmartContract subclass is allowed per file',
            'error',
            locFromNode(cls, file),
          ));
        }
        contractClass = cls;
        detectedParentClass = baseText as 'SmartContract' | 'StatefulSmartContract' | 'UnsafeSmartContract';
      }
    }
  }

  if (!contractClass) {
    errors.push(makeDiagnostic(
      'No class extending SmartContract, StatefulSmartContract, or UnsafeSmartContract found',
      'error',
      { file, line: 1, column: 0 },
    ));
    return { contract: null, errors };
  }

  const contractName = contractClass.getName() ?? 'UnnamedContract';

  // Extract properties
  const properties = parseProperties(contractClass, file, errors);

  // Extract constructor
  const ctors = contractClass.getConstructors();
  let constructorNode: MethodNode;
  if (ctors.length === 0) {
    errors.push(makeDiagnostic(
      'Contract must have a constructor',
      'error',
      locFromNode(contractClass, file),
    ));
    constructorNode = {
      kind: 'method',
      name: 'constructor',
      params: [],
      body: [],
      visibility: 'public',
      sourceLocation: locFromNode(contractClass, file),
    };
  } else {
    constructorNode = parseConstructor(ctors[0]!, file, errors);
  }

  // Extract methods
  const methods = parseMethods(contractClass, file, errors);

  const contract: ContractNode = {
    kind: 'contract',
    name: contractName,
    parentClass: detectedParentClass,
    properties,
    constructor: constructorNode,
    methods,
    sourceFile: file,
  };

  return { contract, errors };
}

// ---------------------------------------------------------------------------
// Properties
// ---------------------------------------------------------------------------

function parseProperties(
  cls: ClassDeclaration,
  file: string,
  errors: CompilerDiagnostic[],
): PropertyNode[] {
  const result: PropertyNode[] = [];

  for (const prop of cls.getProperties()) {
    const name = prop.getName();
    const isReadonly = prop.isReadonly();
    const typeNodeTsm = prop.getTypeNode();

    let type: TypeNode;
    if (typeNodeTsm) {
      type = parseTypeNode(typeNodeTsm, file, errors);
    } else {
      errors.push(makeDiagnostic(
        `Property '${name}' must have an explicit type annotation`,
        'error',
        locFromNode(prop, file),
      ));
      type = { kind: 'custom_type', name: 'unknown' };
    }

    // Parse property initializer (e.g. `count: bigint = 0n`)
    let initializer: Expression | undefined;
    const initExpr = prop.getInitializer();
    if (initExpr) {
      initializer = parseExpression(initExpr, file, errors);
    }

    result.push({
      kind: 'property',
      name,
      type,
      readonly: isReadonly,
      initializer,
      sourceLocation: locFromNode(prop, file),
    });
  }

  return result;
}

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

function parseConstructor(
  ctor: ConstructorDeclaration,
  file: string,
  errors: CompilerDiagnostic[],
): MethodNode {
  const params = parseParams(ctor.getParameters(), file, errors);
  const body = parseStatements(ctor.getBody()!, file, errors);

  return {
    kind: 'method',
    name: 'constructor',
    params,
    body,
    visibility: 'public',
    sourceLocation: locFromNode(ctor, file),
  };
}

// ---------------------------------------------------------------------------
// Methods
// ---------------------------------------------------------------------------

function parseMethods(
  cls: ClassDeclaration,
  file: string,
  errors: CompilerDiagnostic[],
): MethodNode[] {
  const result: MethodNode[] = [];

  for (const method of cls.getMethods()) {
    result.push(parseMethod(method, file, errors));
  }

  return result;
}

function parseMethod(
  method: MethodDeclaration,
  file: string,
  errors: CompilerDiagnostic[],
): MethodNode {
  const name = method.getName();
  const params = parseParams(method.getParameters(), file, errors);

  let visibility: 'public' | 'private' = 'private';
  if (method.hasModifier(SyntaxKind.PublicKeyword)) {
    visibility = 'public';
  }

  const bodyNode = method.getBody();
  const body = bodyNode ? parseStatements(bodyNode, file, errors) : [];

  return {
    kind: 'method',
    name,
    params,
    body,
    visibility,
    sourceLocation: locFromNode(method, file),
  };
}

// ---------------------------------------------------------------------------
// Parameters
// ---------------------------------------------------------------------------

function parseParams(
  params: ParameterDeclaration[],
  file: string,
  errors: CompilerDiagnostic[],
): ParamNode[] {
  const result: ParamNode[] = [];

  for (const param of params) {
    const name = param.getName();
    const typeNodeTsm = param.getTypeNode();

    let type: TypeNode;
    if (typeNodeTsm) {
      type = parseTypeNode(typeNodeTsm, file, errors);
    } else {
      errors.push(makeDiagnostic(
        `Parameter '${name}' must have an explicit type annotation`,
        'error',
        locFromNode(param, file),
      ));
      type = { kind: 'custom_type', name: 'unknown' };
    }

    result.push({ kind: 'param', name, type });
  }

  return result;
}

// ---------------------------------------------------------------------------
// Type nodes
// ---------------------------------------------------------------------------

const PRIMITIVE_TYPES = new Set<string>([
  'bigint', 'boolean', 'ByteString', 'PubKey', 'Sig', 'Sha256',
  'Ripemd160', 'Addr', 'SigHashPreimage', 'RabinSig', 'RabinPubKey', 'Point',
  'P256Point', 'P384Point', 'void',
]);

/**
 * Type-name aliases recognised by the TS parser. `Sha256Digest` is the
 * cross-language spelling exposed by runar-lang (`packages/runar-lang/src/types.ts`);
 * Go, Rust, Python, Zig, and Ruby parsers already map it to the canonical
 * `Sha256` primitive — the TS parser has to do the same so contracts can use
 * the alias in field/param annotations.
 */
const TYPE_ALIASES: Record<string, PrimitiveTypeName> = {
  Sha256Digest: 'Sha256',
};

function parseTypeNode(
  typeNode: Node,
  file: string,
  errors: CompilerDiagnostic[],
): TypeNode {
  const text = typeNode.getText().trim();
  const nodeKind = typeNode.getKind();

  // Keyword types (bigint, boolean, void)
  if (nodeKind === SyntaxKind.BigIntKeyword) {
    return { kind: 'primitive_type', name: 'bigint' };
  }
  if (nodeKind === SyntaxKind.BooleanKeyword) {
    return { kind: 'primitive_type', name: 'boolean' };
  }
  if (nodeKind === SyntaxKind.VoidKeyword) {
    return { kind: 'primitive_type', name: 'void' };
  }

  // Check for primitive types by text (covers TypeReference nodes like Sha256, PubKey, etc.)
  if (PRIMITIVE_TYPES.has(text)) {
    return { kind: 'primitive_type', name: text as PrimitiveTypeName };
  }
  if (TYPE_ALIASES[text]) {
    return { kind: 'primitive_type', name: TYPE_ALIASES[text]! };
  }

  // Check for FixedArray<T, N> and other type references
  if (nodeKind === SyntaxKind.TypeReference) {
    const typeRef = typeNode.asKindOrThrow(SyntaxKind.TypeReference);
    const typeName = typeRef.getTypeName().getText();

    if (typeName === 'FixedArray') {
      const typeArgs = typeRef.getTypeArguments();
      if (typeArgs.length !== 2) {
        errors.push(makeDiagnostic(
          'FixedArray requires exactly 2 type arguments: FixedArray<T, N>',
          'error',
          locFromNode(typeNode, file),
        ));
        return { kind: 'custom_type', name: text };
      }

      const elementType = parseTypeNode(typeArgs[0]!, file, errors);
      const sizeText = typeArgs[1]!.getText().trim();
      const size = parseInt(sizeText, 10);

      if (isNaN(size) || size <= 0) {
        errors.push(makeDiagnostic(
          `FixedArray size must be a positive integer literal, got '${sizeText}'`,
          'error',
          locFromNode(typeArgs[1]!, file),
        ));
        return { kind: 'custom_type', name: text };
      }

      return { kind: 'fixed_array_type', element: elementType, length: size };
    }

    // Other type references -- might be a primitive like Sha256 used as a reference
    if (PRIMITIVE_TYPES.has(typeName)) {
      return { kind: 'primitive_type', name: typeName as PrimitiveTypeName };
    }
    if (TYPE_ALIASES[typeName]) {
      return { kind: 'primitive_type', name: TYPE_ALIASES[typeName]! };
    }

    // Unknown type reference
    return { kind: 'custom_type', name: typeName };
  }

  // Fallback
  errors.push(makeDiagnostic(
    `Unsupported type: '${text}'`,
    'warning',
    locFromNode(typeNode, file),
  ));
  return { kind: 'custom_type', name: text };
}

// ---------------------------------------------------------------------------
// Statements
// ---------------------------------------------------------------------------

function parseStatements(
  blockOrBody: Node,
  file: string,
  errors: CompilerDiagnostic[],
): Statement[] {
  const result: Statement[] = [];

  // Block can be a Block node or a SourceFile
  const stmts = blockOrBody.getChildrenOfKind(SyntaxKind.Block).length > 0
    ? blockOrBody.getFirstChildByKindOrThrow(SyntaxKind.Block).getStatements()
    : (blockOrBody.isKind(SyntaxKind.Block)
        ? blockOrBody.getStatements()
        : []);

  for (const stmt of stmts) {
    const parsed = parseStatement(stmt, file, errors);
    if (parsed) {
      result.push(parsed);
    }
  }

  return result;
}

function parseBlockStatements(
  block: Node,
  file: string,
  errors: CompilerDiagnostic[],
): Statement[] {
  if (block.isKind(SyntaxKind.Block)) {
    const result: Statement[] = [];
    for (const stmt of block.getStatements()) {
      const parsed = parseStatement(stmt, file, errors);
      if (parsed) {
        result.push(parsed);
      }
    }
    return result;
  }
  // Single statement (no braces)
  const parsed = parseStatement(block, file, errors);
  return parsed ? [parsed] : [];
}

function parseStatement(
  node: Node,
  file: string,
  errors: CompilerDiagnostic[],
): Statement | null {
  const kind = node.getKind();

  switch (kind) {
    case SyntaxKind.VariableStatement:
      return parseVariableStatement(node, file, errors);

    case SyntaxKind.ExpressionStatement:
      return parseExpressionStatement(node, file, errors);

    case SyntaxKind.IfStatement:
      return parseIfStatement(node, file, errors);

    case SyntaxKind.ForStatement:
      return parseForStatement(node, file, errors);

    case SyntaxKind.ReturnStatement:
      return parseReturnStatement(node, file, errors);

    default:
      errors.push(makeDiagnostic(
        `Unsupported statement kind: ${node.getKindName()}`,
        'error',
        locFromNode(node, file),
      ));
      return null;
  }
}

function parseVariableStatement(
  node: Node,
  file: string,
  errors: CompilerDiagnostic[],
): VariableDeclStatement | null {
  const varStmt = node.asKindOrThrow(SyntaxKind.VariableStatement);
  const declList = varStmt.getDeclarationList();
  const decls = declList.getDeclarations();

  if (decls.length === 0) {
    return null;
  }

  // Warn about multiple declarations in a single statement
  if (decls.length > 1) {
    errors.push(makeDiagnostic(
      'Multiple variable declarations in a single statement are not supported. Declare one variable per statement.',
      'warning',
      locFromNode(node, file),
    ));
  }

  // We only handle single-declaration variable statements
  const decl = decls[0]!;
  const name = decl.getName();

  const flags = declList.getFlags();
  const isConst = (flags & ts.NodeFlags.Const) !== 0;

  const initExpr = decl.getInitializer();
  let init: Expression;
  if (initExpr) {
    init = parseExpression(initExpr, file, errors);
  } else {
    errors.push(makeDiagnostic(
      `Variable '${name}' must have an initializer`,
      'error',
      locFromNode(decl, file),
    ));
    init = { kind: 'bigint_literal', value: 0n };
  }

  let type: TypeNode | undefined;
  const typeNodeTsm = decl.getTypeNode();
  if (typeNodeTsm) {
    type = parseTypeNode(typeNodeTsm, file, errors);
  }

  return {
    kind: 'variable_decl',
    name,
    type,
    mutable: !isConst,
    init,
    sourceLocation: locFromNode(node, file),
  };
}

function parseExpressionStatement(
  node: Node,
  file: string,
  errors: CompilerDiagnostic[],
): Statement | null {
  const exprStmt = node.asKindOrThrow(SyntaxKind.ExpressionStatement);
  const expr = exprStmt.getExpression();

  // Check if this is an assignment expression (a = b, this.x = b)
  if (expr.isKind(SyntaxKind.BinaryExpression)) {
    const binExpr = expr.asKindOrThrow(SyntaxKind.BinaryExpression);
    const opToken = binExpr.getOperatorToken().getKind();

    if (opToken === SyntaxKind.EqualsToken) {
      const target = parseExpression(binExpr.getLeft(), file, errors);
      const value = parseExpression(binExpr.getRight(), file, errors);
      return {
        kind: 'assignment',
        target,
        value,
        sourceLocation: locFromNode(node, file),
      };
    }

    // Compound assignments: +=, -=, *=, /=, %=
    const compoundOps: Record<number, BinaryOp> = {
      [SyntaxKind.PlusEqualsToken]: '+',
      [SyntaxKind.MinusEqualsToken]: '-',
      [SyntaxKind.AsteriskEqualsToken]: '*',
      [SyntaxKind.SlashEqualsToken]: '/',
      [SyntaxKind.PercentEqualsToken]: '%',
    };

    const compoundOp = compoundOps[opToken];
    if (compoundOp) {
      const target = parseExpression(binExpr.getLeft(), file, errors);
      const right = parseExpression(binExpr.getRight(), file, errors);
      const value: Expression = {
        kind: 'binary_expr',
        op: compoundOp,
        left: target,
        right,
      };
      return {
        kind: 'assignment',
        target,
        value,
        sourceLocation: locFromNode(node, file),
      };
    }
  }

  const expression = parseExpression(expr, file, errors);
  return {
    kind: 'expression_statement',
    expression,
    sourceLocation: locFromNode(node, file),
  };
}

function parseIfStatement(
  node: Node,
  file: string,
  errors: CompilerDiagnostic[],
): IfStatement {
  const ifStmt = node.asKindOrThrow(SyntaxKind.IfStatement);
  const condition = parseExpression(ifStmt.getExpression(), file, errors);
  const thenBlock = ifStmt.getThenStatement();
  const thenStmts = parseBlockStatements(thenBlock, file, errors);

  let elseStmts: Statement[] | undefined;
  const elseBlock = ifStmt.getElseStatement();
  if (elseBlock) {
    elseStmts = parseBlockStatements(elseBlock, file, errors);
  }

  return {
    kind: 'if_statement',
    condition,
    then: thenStmts,
    else: elseStmts,
    sourceLocation: locFromNode(node, file),
  };
}

function parseForStatement(
  node: Node,
  file: string,
  errors: CompilerDiagnostic[],
): ForStatement {
  const forStmt = node.asKindOrThrow(SyntaxKind.ForStatement);
  const loc = locFromNode(node, file);

  // Parse initializer: let i: bigint = 0n
  const initNode = forStmt.getInitializer();
  let init: VariableDeclStatement;

  if (initNode && initNode.isKind(SyntaxKind.VariableDeclarationList)) {
    const declList = initNode.asKindOrThrow(SyntaxKind.VariableDeclarationList);
    const decls = declList.getDeclarations();
    if (decls.length > 0) {
      const decl = decls[0]!;
      const name = decl.getName();
      const initExpr = decl.getInitializer();

      let initVal: Expression;
      if (initExpr) {
        initVal = parseExpression(initExpr, file, errors);
      } else {
        initVal = { kind: 'bigint_literal', value: 0n };
      }

      let type: TypeNode | undefined;
      const typeNodeTsm = decl.getTypeNode();
      if (typeNodeTsm) {
        type = parseTypeNode(typeNodeTsm, file, errors);
      }

      const flags = declList.getFlags();
      const isConst = (flags & ts.NodeFlags.Const) !== 0;

      init = {
        kind: 'variable_decl',
        name,
        type,
        mutable: !isConst,
        init: initVal,
        sourceLocation: locFromNode(initNode, file),
      };
    } else {
      init = makeDefaultForInit(loc);
    }
  } else {
    errors.push(makeDiagnostic(
      'For loop must have a variable declaration initializer',
      'error',
      loc,
    ));
    init = makeDefaultForInit(loc);
  }

  // Parse condition
  const condNode = forStmt.getCondition();
  let condition: Expression;
  if (condNode) {
    condition = parseExpression(condNode, file, errors);
  } else {
    errors.push(makeDiagnostic(
      'For loop must have a condition',
      'error',
      loc,
    ));
    condition = { kind: 'bool_literal', value: false };
  }

  // Parse update (incrementor)
  const updateNode = forStmt.getIncrementor();
  let update: Statement;
  if (updateNode) {
    update = parseForUpdate(updateNode, file, errors);
  } else {
    errors.push(makeDiagnostic(
      'For loop must have an update expression',
      'error',
      loc,
    ));
    update = {
      kind: 'expression_statement',
      expression: { kind: 'bigint_literal', value: 0n },
      sourceLocation: loc,
    };
  }

  // Parse body
  const bodyNode = forStmt.getStatement();
  const body = parseBlockStatements(bodyNode, file, errors);

  return {
    kind: 'for_statement',
    init,
    condition,
    update,
    body,
    sourceLocation: loc,
  };
}

function parseForUpdate(
  node: Node,
  file: string,
  errors: CompilerDiagnostic[],
): Statement {
  const loc = locFromNode(node, file);

  // i++ or i--
  if (node.isKind(SyntaxKind.PostfixUnaryExpression)) {
    const postfix = node.asKindOrThrow(SyntaxKind.PostfixUnaryExpression);
    const operand = parseExpression(postfix.getOperand(), file, errors);
    const op = postfix.getOperatorToken();

    if (op === SyntaxKind.PlusPlusToken) {
      return {
        kind: 'expression_statement',
        expression: { kind: 'increment_expr', operand, prefix: false },
        sourceLocation: loc,
      };
    } else {
      return {
        kind: 'expression_statement',
        expression: { kind: 'decrement_expr', operand, prefix: false },
        sourceLocation: loc,
      };
    }
  }

  // ++i or --i
  if (node.isKind(SyntaxKind.PrefixUnaryExpression)) {
    const prefix = node.asKindOrThrow(SyntaxKind.PrefixUnaryExpression);
    const operand = parseExpression(prefix.getOperand(), file, errors);
    const op = prefix.getOperatorToken();

    if (op === SyntaxKind.PlusPlusToken) {
      return {
        kind: 'expression_statement',
        expression: { kind: 'increment_expr', operand, prefix: true },
        sourceLocation: loc,
      };
    } else {
      return {
        kind: 'expression_statement',
        expression: { kind: 'decrement_expr', operand, prefix: true },
        sourceLocation: loc,
      };
    }
  }

  // i += 1 etc. -- parse as expression statement
  const expr = parseExpression(node, file, errors);
  return {
    kind: 'expression_statement',
    expression: expr,
    sourceLocation: loc,
  };
}

function parseReturnStatement(
  node: Node,
  file: string,
  errors: CompilerDiagnostic[],
): ReturnStatement {
  const retStmt = node.asKindOrThrow(SyntaxKind.ReturnStatement);
  const exprNode = retStmt.getExpression();

  let value: Expression | undefined;
  if (exprNode) {
    value = parseExpression(exprNode, file, errors);
  }

  return {
    kind: 'return_statement',
    value,
    sourceLocation: locFromNode(node, file),
  };
}

function makeDefaultForInit(loc: SourceLocation): VariableDeclStatement {
  return {
    kind: 'variable_decl',
    name: '_i',
    mutable: true,
    init: { kind: 'bigint_literal', value: 0n },
    sourceLocation: loc,
  };
}

// ---------------------------------------------------------------------------
// Expressions
// ---------------------------------------------------------------------------

function parseExpression(
  node: Node,
  file: string,
  errors: CompilerDiagnostic[],
): Expression {
  const kind = node.getKind();

  switch (kind) {
    case SyntaxKind.BinaryExpression:
      return parseBinaryExpression(node, file, errors);

    case SyntaxKind.PrefixUnaryExpression:
      return parsePrefixUnaryExpression(node, file, errors);

    case SyntaxKind.PostfixUnaryExpression:
      return parsePostfixUnaryExpression(node, file, errors);

    case SyntaxKind.CallExpression:
      return parseCallExpression(node, file, errors);

    case SyntaxKind.PropertyAccessExpression:
      return parsePropertyAccessExpression(node, file, errors);

    case SyntaxKind.ElementAccessExpression:
      return parseElementAccessExpression(node, file, errors);

    case SyntaxKind.Identifier:
      return { kind: 'identifier', name: node.getText(), sourceLocation: locFromNode(node, file) };

    case SyntaxKind.BigIntLiteral: {
      const text = node.getText();
      // BigInt literals in TS end with 'n', e.g. '42n'
      const numStr = text.endsWith('n') ? text.slice(0, -1) : text;
      return { kind: 'bigint_literal', value: BigInt(numStr) };
    }

    case SyntaxKind.NumericLiteral: {
      // Plain numeric literals (e.g., 42) -- treat as bigint for Rúnar
      const numText = node.getText();
      return { kind: 'bigint_literal', value: BigInt(numText) };
    }

    case SyntaxKind.TrueKeyword:
      return { kind: 'bool_literal', value: true };

    case SyntaxKind.FalseKeyword:
      return { kind: 'bool_literal', value: false };

    case SyntaxKind.StringLiteral: {
      // String literals are used for hex-encoded ByteString values
      const text = node.getText();
      // Remove quotes
      const raw = text.slice(1, -1);
      return { kind: 'bytestring_literal', value: raw, sourceLocation: locFromNode(node, file) };
    }

    case SyntaxKind.NoSubstitutionTemplateLiteral: {
      const text = node.getText();
      const raw = text.slice(1, -1);
      return { kind: 'bytestring_literal', value: raw, sourceLocation: locFromNode(node, file) };
    }

    case SyntaxKind.ConditionalExpression:
      return parseTernaryExpression(node, file, errors);

    case SyntaxKind.ParenthesizedExpression: {
      const paren = node.asKindOrThrow(SyntaxKind.ParenthesizedExpression);
      return parseExpression(paren.getExpression(), file, errors);
    }

    case SyntaxKind.ThisKeyword:
      return { kind: 'identifier', name: 'this' };

    case SyntaxKind.SuperKeyword:
      return { kind: 'identifier', name: 'super' };

    case SyntaxKind.AsExpression: {
      // Type assertions: ignore the type part and just parse the expression
      const asExpr = node.asKindOrThrow(SyntaxKind.AsExpression);
      return parseExpression(asExpr.getExpression(), file, errors);
    }

    case SyntaxKind.NonNullExpression: {
      // Non-null assertion: just parse the inner expression
      const nnExpr = node.asKindOrThrow(SyntaxKind.NonNullExpression);
      return parseExpression(nnExpr.getExpression(), file, errors);
    }

    case SyntaxKind.ArrayLiteralExpression: {
      const arrayLit = node.asKindOrThrow(SyntaxKind.ArrayLiteralExpression);
      const elements = arrayLit.getElements().map(elem => parseExpression(elem, file, errors));
      return { kind: 'array_literal', elements };
    }

    default:
      errors.push(makeDiagnostic(
        `Unsupported expression kind: ${node.getKindName()} ('${node.getText().slice(0, 50)}')`,
        'error',
        locFromNode(node, file),
      ));
      return { kind: 'bigint_literal', value: 0n };
  }
}

function parseBinaryExpression(
  node: Node,
  file: string,
  errors: CompilerDiagnostic[],
): Expression {
  const binExpr = node.asKindOrThrow(SyntaxKind.BinaryExpression);
  const left = parseExpression(binExpr.getLeft(), file, errors);
  const right = parseExpression(binExpr.getRight(), file, errors);
  const opToken = binExpr.getOperatorToken();
  const opKind = opToken.getKind();

  const OP_MAP: Record<number, BinaryOp> = {
    [SyntaxKind.PlusToken]: '+',
    [SyntaxKind.MinusToken]: '-',
    [SyntaxKind.AsteriskToken]: '*',
    [SyntaxKind.SlashToken]: '/',
    [SyntaxKind.PercentToken]: '%',
    [SyntaxKind.EqualsEqualsEqualsToken]: '===',
    [SyntaxKind.ExclamationEqualsEqualsToken]: '!==',
    [SyntaxKind.LessThanToken]: '<',
    [SyntaxKind.LessThanEqualsToken]: '<=',
    [SyntaxKind.GreaterThanToken]: '>',
    [SyntaxKind.GreaterThanEqualsToken]: '>=',
    [SyntaxKind.AmpersandAmpersandToken]: '&&',
    [SyntaxKind.BarBarToken]: '||',
    [SyntaxKind.AmpersandToken]: '&',
    [SyntaxKind.BarToken]: '|',
    [SyntaxKind.CaretToken]: '^',
    [SyntaxKind.LessThanLessThanToken]: '<<',
    [SyntaxKind.GreaterThanGreaterThanToken]: '>>',
  };

  // Handle == and != (loose equality) -- map to === and !== with a warning
  if (opKind === SyntaxKind.EqualsEqualsToken) {
    errors.push(makeDiagnostic(
      'Use === instead of == for equality comparison',
      'warning',
      locFromNode(opToken, file),
    ));
    return { kind: 'binary_expr', op: '===', left, right };
  }
  if (opKind === SyntaxKind.ExclamationEqualsToken) {
    errors.push(makeDiagnostic(
      'Use !== instead of != for inequality comparison',
      'warning',
      locFromNode(opToken, file),
    ));
    return { kind: 'binary_expr', op: '!==', left, right };
  }

  const op = OP_MAP[opKind];
  if (op) {
    return { kind: 'binary_expr', op, left, right };
  }

  errors.push(makeDiagnostic(
    `Unsupported binary operator: '${opToken.getText()}'`,
    'error',
    locFromNode(opToken, file),
  ));
  return { kind: 'binary_expr', op: '+', left, right };
}

function parsePrefixUnaryExpression(
  node: Node,
  file: string,
  errors: CompilerDiagnostic[],
): Expression {
  const prefix = node.asKindOrThrow(SyntaxKind.PrefixUnaryExpression);
  const operand = parseExpression(prefix.getOperand(), file, errors);
  const opToken = prefix.getOperatorToken();

  const UNARY_MAP: Record<number, UnaryOp> = {
    [SyntaxKind.ExclamationToken]: '!',
    [SyntaxKind.MinusToken]: '-',
    [SyntaxKind.TildeToken]: '~',
  };

  // ++ and --
  if (opToken === SyntaxKind.PlusPlusToken) {
    return { kind: 'increment_expr', operand, prefix: true };
  }
  if (opToken === SyntaxKind.MinusMinusToken) {
    return { kind: 'decrement_expr', operand, prefix: true };
  }

  const op = UNARY_MAP[opToken];
  if (op) {
    return { kind: 'unary_expr', op, operand };
  }

  errors.push(makeDiagnostic(
    `Unsupported unary prefix operator`,
    'error',
    locFromNode(node, file),
  ));
  return { kind: 'unary_expr', op: '-', operand };
}

function parsePostfixUnaryExpression(
  node: Node,
  file: string,
  errors: CompilerDiagnostic[],
): Expression {
  const postfix = node.asKindOrThrow(SyntaxKind.PostfixUnaryExpression);
  const operand = parseExpression(postfix.getOperand(), file, errors);
  const opToken = postfix.getOperatorToken();

  if (opToken === SyntaxKind.PlusPlusToken) {
    return { kind: 'increment_expr', operand, prefix: false };
  }
  if (opToken === SyntaxKind.MinusMinusToken) {
    return { kind: 'decrement_expr', operand, prefix: false };
  }

  errors.push(makeDiagnostic(
    `Unsupported postfix operator`,
    'error',
    locFromNode(node, file),
  ));
  return operand;
}

function parseCallExpression(
  node: Node,
  file: string,
  errors: CompilerDiagnostic[],
): Expression {
  const callExpr = node.asKindOrThrow(SyntaxKind.CallExpression);
  const calleeNode = callExpr.getExpression();
  const calleeText = calleeNode.getText();
  const loc = locFromNode(node, file);

  // Special-case asm({ body, in_arity?, out_arity? }) — convert the
  // object-literal argument into a synthetic call_expr with positional
  // args (body, in_arity, out_arity) so downstream passes only have to
  // know how to walk call_expr. Both the string-literal body form and
  // the array-form body (e.g. [OP_DUP, push(0x42), OP_EQUALVERIFY])
  // are supported; the array form is encoded to a hex string at parse
  // time so all downstream passes see identical IR shape. The optional
  // generic type argument `asm<T>(...)` flags the expression form,
  // where the asm return value flows into a let-binding.
  if (calleeNode.isKind(SyntaxKind.Identifier) && calleeText === 'asm') {
    return parseAsmCall(callExpr, file, errors, loc);
  }

  const callee = parseExpression(calleeNode, file, errors);
  const args: Expression[] = [];

  for (const arg of callExpr.getArguments()) {
    args.push(parseExpression(arg, file, errors));
  }

  return { kind: 'call_expr', callee, args };
}

/**
 * Decode an `asm({ body, in_arity?, out_arity? })` call into a synthetic
 * `call_expr` whose positional args are
 *   [bytestring_literal(body), bigint_literal(in_arity), bigint_literal(out_arity)].
 *
 * Two surface body shapes are accepted:
 *  - Hex string literal: `body: '76a90088ac'` (v0)
 *  - Array of opcode names / push-literals:
 *      `body: [OP_DUP, OP_HASH160, push('1234abcd'), OP_EQUALVERIFY]`
 *    Each element is encoded to its byte representation at parse time
 *    using the same encoder the emit pass uses, so the resulting IR
 *    is byte-identical to the equivalent hex string body. All
 *    downstream passes only ever see a `bytestring_literal` body.
 *
 * The optional generic type argument `asm<T>({...})` marks the
 * expression form. Captured `T` is stashed on `asmReturnType` of the
 * returned `call_expr` so the typechecker / validator can scope their
 * rules. `T` must be one of `bigint`, `boolean`, or `ByteString`.
 *
 * On any malformed input we still return a syntactically valid call_expr
 * so later passes can produce additional diagnostics without crashing.
 */
function parseAsmCall(
  callExpr: CallExpression,
  file: string,
  errors: CompilerDiagnostic[],
  loc: SourceLocation,
): Expression {
  // Re-typed callee identifier — fixed by the caller's check.
  const calleeExpr: Expression = { kind: 'identifier', name: 'asm', sourceLocation: loc };

  // Capture the generic type argument `asm<T>({...})` if present. We
  // need this BEFORE arg-shape diagnostics so the expression form
  // still records its return type even when other args are malformed.
  const asmReturnType = parseAsmGenericTypeArg(callExpr, file, errors);

  const callArgs = callExpr.getArguments();
  if (callArgs.length !== 1) {
    errors.push(makeDiagnostic(
      `asm() expects exactly one object-literal argument { body, in_arity?, out_arity? }, got ${callArgs.length} arguments`,
      'error',
      loc,
    ));
    const errExpr: Extract<Expression, { kind: 'call_expr' }> = {
      kind: 'call_expr', callee: calleeExpr, args: [], sourceLocation: loc,
    };
    if (asmReturnType) errExpr.asmReturnType = asmReturnType;
    return errExpr;
  }

  const argNode = callArgs[0]!;
  if (!argNode.isKind(SyntaxKind.ObjectLiteralExpression)) {
    errors.push(makeDiagnostic(
      `asm() argument must be an object literal { body: '<hex>', in_arity?: <int>, out_arity?: <int> }, got '${argNode.getKindName()}'`,
      'error',
      locFromNode(argNode, file),
    ));
    const errExpr: Extract<Expression, { kind: 'call_expr' }> = {
      kind: 'call_expr', callee: calleeExpr, args: [], sourceLocation: loc,
    };
    if (asmReturnType) errExpr.asmReturnType = asmReturnType;
    return errExpr;
  }

  const objLit = argNode.asKindOrThrow(SyntaxKind.ObjectLiteralExpression);
  const objLoc = locFromNode(objLit, file);

  let bodyExpr: Expression | undefined;
  let inArityExpr: Expression | undefined;
  let outArityExpr: Expression | undefined;

  for (const prop of objLit.getProperties()) {
    if (!prop.isKind(SyntaxKind.PropertyAssignment)) {
      errors.push(makeDiagnostic(
        `asm() object-literal entries must be plain property assignments (got '${prop.getKindName()}'). Shorthand, spread, and method shorthand are not supported.`,
        'error',
        locFromNode(prop, file),
      ));
      continue;
    }
    const propAssign = prop.asKindOrThrow(SyntaxKind.PropertyAssignment);
    const nameNode = propAssign.getNameNode();
    const key = nameNode.getText();
    const initNode = propAssign.getInitializerOrThrow();
    const propLoc = locFromNode(prop, file);

    switch (key) {
      case 'body': {
        // Accept either:
        //  - a hex string literal, OR
        //  - an array literal of opcode identifiers and `push(<literal>)`
        //    calls, which we encode to the same hex bytes at parse time.
        if (
          initNode.isKind(SyntaxKind.StringLiteral) ||
          initNode.isKind(SyntaxKind.NoSubstitutionTemplateLiteral)
        ) {
          const raw = initNode.getText().slice(1, -1);
          bodyExpr = { kind: 'bytestring_literal', value: raw, sourceLocation: locFromNode(initNode, file) };
        } else if (initNode.isKind(SyntaxKind.ArrayLiteralExpression)) {
          const encoded = encodeAsmArrayBody(initNode, file, errors);
          bodyExpr = { kind: 'bytestring_literal', value: encoded, sourceLocation: locFromNode(initNode, file) };
        } else {
          errors.push(makeDiagnostic(
            `asm() body must be a hex string literal or an array of opcode names / push() calls; got '${initNode.getKindName()}'.`,
            'error',
            propLoc,
          ));
          // Stamp a placeholder so downstream passes see a body and don't
          // emit a duplicate "missing body" diagnostic.
          bodyExpr = { kind: 'bytestring_literal', value: '', sourceLocation: propLoc };
        }
        break;
      }

      case 'in_arity': {
        const parsed = parseArityLiteral(initNode, 'in_arity', errors, propLoc);
        if (parsed !== null) {
          inArityExpr = { kind: 'bigint_literal', value: BigInt(parsed), sourceLocation: propLoc };
        }
        break;
      }

      case 'out_arity': {
        const parsed = parseArityLiteral(initNode, 'out_arity', errors, propLoc);
        if (parsed !== null) {
          outArityExpr = { kind: 'bigint_literal', value: BigInt(parsed), sourceLocation: propLoc };
        }
        break;
      }

      default:
        errors.push(makeDiagnostic(
          `asm() does not accept the '${key}' field; valid fields are 'body', 'in_arity', 'out_arity'.`,
          'error',
          propLoc,
        ));
        break;
    }
  }

  if (!bodyExpr) {
    errors.push(makeDiagnostic(
      `asm() requires a 'body' field with a hex string literal value`,
      'error',
      objLoc,
    ));
    bodyExpr = { kind: 'bytestring_literal', value: '', sourceLocation: objLoc };
  }

  // Defaults: in_arity=0, out_arity=1. The out_arity=1 default reflects
  // the public-method-must-terminate-truthy invariant — every public
  // method ends with a single truthy stack value, so a terminal arity-1
  // asm is the script's exit value.
  if (!inArityExpr) {
    inArityExpr = { kind: 'bigint_literal', value: 0n, sourceLocation: objLoc };
  }
  if (!outArityExpr) {
    outArityExpr = { kind: 'bigint_literal', value: 1n, sourceLocation: objLoc };
  }

  const result: Extract<Expression, { kind: 'call_expr' }> = {
    kind: 'call_expr',
    callee: calleeExpr,
    args: [bodyExpr, inArityExpr, outArityExpr],
    sourceLocation: loc,
  };
  if (asmReturnType) {
    result.asmReturnType = asmReturnType;
  }
  return result;
}

/**
 * Parse the optional generic type argument on `asm<T>({...})`. Returns
 * the captured primitive type name when present and valid, or
 * `undefined` if the call has no type argument. Pushes a diagnostic
 * (and returns `undefined`) when the type argument is present but not
 * a primitive value type (`bigint` / `boolean` / `ByteString`).
 */
function parseAsmGenericTypeArg(
  callExpr: CallExpression,
  file: string,
  errors: CompilerDiagnostic[],
): PrimitiveTypeName | undefined {
  const typeArgs = callExpr.getTypeArguments();
  if (typeArgs.length === 0) return undefined;
  if (typeArgs.length > 1) {
    errors.push(makeDiagnostic(
      `asm<T>() takes at most one type argument, got ${typeArgs.length}`,
      'error',
      locFromNode(callExpr, file),
    ));
    return undefined;
  }
  const typeArg = typeArgs[0]!;
  const text = typeArg.getText().trim();
  // Only the primitive value types are allowed. Aggregate / opaque
  // types (FixedArray, PubKey, Sig, ...) can't flow through a
  // load_const ANF binding, so we reject them up-front to keep the
  // user error close to the source.
  if (text === 'bigint' || text === 'boolean' || text === 'ByteString') {
    return text as PrimitiveTypeName;
  }
  errors.push(makeDiagnostic(
    `asm<T>() return type must be 'bigint', 'boolean', or 'ByteString'; got '${text}'`,
    'error',
    locFromNode(typeArg, file),
  ));
  return undefined;
}

/**
 * Encode an `asm({ body: [OP_DUP, push(0x42), OP_EQUALVERIFY] })` array
 * literal to its hex byte representation. Uses the same push-encoding
 * helpers as the emit pass so the resulting bytes are byte-identical
 * to what the emitter would produce for the equivalent literal.
 *
 * Each element must be either:
 *  - An Identifier matching a known opcode (e.g. `OP_DUP`), encoded
 *    to that opcode's single byte, OR
 *  - A CallExpression `push(<literal>)` where the literal is either a
 *    BigInt literal (or numeric literal), a Boolean literal, or a
 *    hex string literal (ByteString). Encodes as a length-prefixed
 *    push using MINIMALDATA rules.
 *
 * Diagnostics are pushed for unknown opcode identifiers, malformed
 * push() calls, and unrecognised element shapes. The returned hex
 * is best-effort — even on errors, well-formed elements still produce
 * their bytes so downstream passes can keep walking.
 */
function encodeAsmArrayBody(
  arrayNode: Node,
  file: string,
  errors: CompilerDiagnostic[],
): string {
  const arrayLit = arrayNode.asKindOrThrow(SyntaxKind.ArrayLiteralExpression);
  let hex = '';
  for (const elem of arrayLit.getElements()) {
    if (elem.isKind(SyntaxKind.Identifier)) {
      const name = elem.getText();
      const byte = OPCODES[name];
      if (byte === undefined) {
        errors.push(makeDiagnostic(
          `Unknown opcode '${name}' in asm() body array. Expected an OP_* identifier (e.g. OP_DUP, OP_HASH160) or a push(...) call.`,
          'error',
          locFromNode(elem, file),
        ));
        continue;
      }
      hex += byteToHex(byte);
      continue;
    }

    if (elem.isKind(SyntaxKind.CallExpression)) {
      const callee = elem.getExpression();
      if (!callee.isKind(SyntaxKind.Identifier) || callee.getText() !== 'push') {
        errors.push(makeDiagnostic(
          `asm() body array call must be 'push(<literal>)', got '${callee.getText()}(...)'`,
          'error',
          locFromNode(elem, file),
        ));
        continue;
      }
      const pushArgs = elem.getArguments();
      if (pushArgs.length !== 1) {
        errors.push(makeDiagnostic(
          `push() takes exactly one literal argument, got ${pushArgs.length}`,
          'error',
          locFromNode(elem, file),
        ));
        continue;
      }
      const pushed = encodeAsmPushLiteral(pushArgs[0]!, file, errors);
      if (pushed !== undefined) hex += pushed;
      continue;
    }

    // Anything else is a hard error — we don't silently accept it.
    errors.push(makeDiagnostic(
      `asm() body array element must be an opcode identifier (e.g. OP_DUP) or a push(<literal>) call; got '${elem.getKindName()}'`,
      'error',
      locFromNode(elem, file),
    ));
  }
  return hex;
}

/**
 * Encode a literal argument passed to `push(...)` inside an asm() body
 * array. Returns the encoded hex string for the literal, or `undefined`
 * if the literal is unrecognised (with a diagnostic pushed).
 *
 * Accepted shapes:
 *  - BigIntLiteral (`42n`): encoded via `encodePushBigIntHex` (small-int
 *    opcode where possible, else length-prefixed script-number push)
 *  - NumericLiteral (`42`): same as BigIntLiteral after coercion
 *  - PrefixUnaryExpression(-, NumericLiteral|BigIntLiteral): negative push
 *  - TrueKeyword / FalseKeyword: OP_TRUE / OP_FALSE
 *  - StringLiteral / NoSubstitutionTemplateLiteral: hex bytes -> push-data
 */
function encodeAsmPushLiteral(
  node: Node,
  file: string,
  errors: CompilerDiagnostic[],
): string | undefined {
  if (node.isKind(SyntaxKind.BigIntLiteral)) {
    const text = node.getText();
    const numStr = text.endsWith('n') ? text.slice(0, -1) : text;
    try {
      return encodePushBigIntHex(BigInt(numStr));
    } catch {
      errors.push(makeDiagnostic(
        `push() argument is not a valid BigInt literal: '${text}'`,
        'error',
        locFromNode(node, file),
      ));
      return undefined;
    }
  }

  if (node.isKind(SyntaxKind.NumericLiteral)) {
    const text = node.getText();
    const n = Number(text);
    if (!Number.isFinite(n) || Math.floor(n) !== n) {
      errors.push(makeDiagnostic(
        `push() numeric argument must be an integer, got '${text}'`,
        'error',
        locFromNode(node, file),
      ));
      return undefined;
    }
    return encodePushBigIntHex(BigInt(n));
  }

  if (node.isKind(SyntaxKind.PrefixUnaryExpression)) {
    const prefix = node.asKindOrThrow(SyntaxKind.PrefixUnaryExpression);
    if (prefix.getOperatorToken() === SyntaxKind.MinusToken) {
      const operand = prefix.getOperand();
      const inner = encodeAsmPushLiteral(operand, file, errors);
      if (inner === undefined) return undefined;
      // Re-encode as negative by reparsing — simplest way to keep the
      // script-number sign-bit logic in one place.
      if (operand.isKind(SyntaxKind.BigIntLiteral)) {
        const text = operand.getText();
        const numStr = text.endsWith('n') ? text.slice(0, -1) : text;
        try {
          return encodePushBigIntHex(-BigInt(numStr));
        } catch {
          // already diagnosed
          return undefined;
        }
      }
      if (operand.isKind(SyntaxKind.NumericLiteral)) {
        return encodePushBigIntHex(-BigInt(operand.getText()));
      }
    }
    errors.push(makeDiagnostic(
      `push() argument must be a literal value (bigint, number, boolean, or hex string), got prefix expression`,
      'error',
      locFromNode(node, file),
    ));
    return undefined;
  }

  if (node.getKind() === SyntaxKind.TrueKeyword) {
    return '51'; // OP_TRUE
  }
  if (node.getKind() === SyntaxKind.FalseKeyword) {
    return '00'; // OP_FALSE (alias of OP_0)
  }

  if (
    node.isKind(SyntaxKind.StringLiteral) ||
    node.isKind(SyntaxKind.NoSubstitutionTemplateLiteral)
  ) {
    const raw = node.getText().slice(1, -1);
    if (raw.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(raw)) {
      errors.push(makeDiagnostic(
        `push() ByteString argument must be even-length hex (got '${raw}')`,
        'error',
        locFromNode(node, file),
      ));
      return undefined;
    }
    const bytes = new Uint8Array(raw.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(raw.substr(i * 2, 2), 16);
    }
    return encodePushBytesHex(bytes);
  }

  errors.push(makeDiagnostic(
    `push() argument must be a literal value (bigint, number, boolean, or hex string), got '${node.getKindName()}'`,
    'error',
    locFromNode(node, file),
  ));
  return undefined;
}

/**
 * Decode a non-negative integer literal arity field for asm(). Returns
 * null and pushes a diagnostic on error.
 */
function parseArityLiteral(
  initNode: Node,
  fieldName: string,
  errors: CompilerDiagnostic[],
  loc: SourceLocation,
): number | null {
  // BigInt literal: `0n`, `1n`, ...
  if (initNode.isKind(SyntaxKind.BigIntLiteral)) {
    const text = initNode.getText();
    const numStr = text.endsWith('n') ? text.slice(0, -1) : text;
    const n = Number(numStr);
    if (!Number.isFinite(n) || Math.floor(n) !== n || n < 0) {
      errors.push(makeDiagnostic(
        `asm() ${fieldName} must be a non-negative integer literal, got '${text}'`,
        'error',
        loc,
      ));
      return null;
    }
    return n;
  }

  // Plain numeric literal: `0`, `1`, ...
  if (initNode.isKind(SyntaxKind.NumericLiteral)) {
    const text = initNode.getText();
    const n = Number(text);
    if (!Number.isFinite(n) || Math.floor(n) !== n || n < 0) {
      errors.push(makeDiagnostic(
        `asm() ${fieldName} must be a non-negative integer literal, got '${text}'`,
        'error',
        loc,
      ));
      return null;
    }
    return n;
  }

  // Negative number literal: `PrefixUnaryExpression(-, <num>)`.
  if (initNode.isKind(SyntaxKind.PrefixUnaryExpression)) {
    errors.push(makeDiagnostic(
      `asm() ${fieldName} must be a non-negative integer literal`,
      'error',
      loc,
    ));
    return null;
  }

  errors.push(makeDiagnostic(
    `asm() ${fieldName} must be a non-negative integer literal, got '${initNode.getKindName()}'`,
    'error',
    loc,
  ));
  return null;
}

function parsePropertyAccessExpression(
  node: Node,
  file: string,
  errors: CompilerDiagnostic[],
): Expression {
  const propAccess = node.asKindOrThrow(SyntaxKind.PropertyAccessExpression);
  const objExpr = propAccess.getExpression();
  const propName = propAccess.getName();

  // `this.x` -> PropertyAccessExpr
  if (objExpr.isKind(SyntaxKind.ThisKeyword)) {
    return { kind: 'property_access', property: propName, sourceLocation: locFromNode(node, file) };
  }

  // General member access: obj.method
  const object = parseExpression(objExpr, file, errors);
  return { kind: 'member_expr', object, property: propName, sourceLocation: locFromNode(node, file) };
}

function parseElementAccessExpression(
  node: Node,
  file: string,
  errors: CompilerDiagnostic[],
): Expression {
  const elemAccess = node.asKindOrThrow(SyntaxKind.ElementAccessExpression);
  const object = parseExpression(elemAccess.getExpression(), file, errors);
  const argExpr = elemAccess.getArgumentExpression();

  let index: Expression;
  if (argExpr) {
    index = parseExpression(argExpr, file, errors);
  } else {
    errors.push(makeDiagnostic(
      'Element access must have an index expression',
      'error',
      locFromNode(node, file),
    ));
    index = { kind: 'bigint_literal', value: 0n };
  }

  return { kind: 'index_access', object, index };
}

function parseTernaryExpression(
  node: Node,
  file: string,
  errors: CompilerDiagnostic[],
): Expression {
  const condExpr = node.asKindOrThrow(SyntaxKind.ConditionalExpression);
  const condition = parseExpression(condExpr.getCondition(), file, errors);
  const consequent = parseExpression(condExpr.getWhenTrue(), file, errors);
  const alternate = parseExpression(condExpr.getWhenFalse(), file, errors);

  return { kind: 'ternary_expr', condition, consequent, alternate };
}

// ---------------------------------------------------------------------------
// Source location helpers
// ---------------------------------------------------------------------------

function locFromNode(node: Node, file: string): SourceLocation {
  const start = node.getStartLineNumber();
  const pos = node.getStart();
  const sourceFile = node.getSourceFile();
  const lineAndCol = sourceFile.getLineAndColumnAtPos(pos);

  return {
    file,
    line: start,
    column: lineAndCol.column - 1, // 0-based
  };
}
