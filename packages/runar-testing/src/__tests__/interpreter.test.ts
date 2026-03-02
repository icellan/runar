import { describe, it, expect } from 'vitest';
import { RunarInterpreter } from '../interpreter/index.js';
import type { ContractNode, MethodNode, Statement, Expression } from 'runar-ir-schema';

// ---------------------------------------------------------------------------
// Helpers to build AST nodes
// ---------------------------------------------------------------------------

function loc() {
  return { file: 'test.ts', line: 1, column: 0 };
}

function bigintLit(value: bigint): Expression {
  return { kind: 'bigint_literal', value };
}

function boolLit(value: boolean): Expression {
  return { kind: 'bool_literal', value };
}

function ident(name: string): Expression {
  return { kind: 'identifier', name };
}

function binaryExpr(op: '+' | '-' | '*' | '/' | '===' | '!==', left: Expression, right: Expression): Expression {
  return { kind: 'binary_expr', op, left, right };
}

function callExpr(name: string, args: Expression[]): Expression {
  return { kind: 'call_expr', callee: { kind: 'identifier', name }, args };
}

function exprStmt(expression: Expression): Statement {
  return { kind: 'expression_statement', expression, sourceLocation: loc() };
}

function varDecl(name: string, init: Expression): Statement {
  return { kind: 'variable_decl', name, init, sourceLocation: loc() };
}

function returnStmt(value: Expression): Statement {
  return { kind: 'return_statement', value, sourceLocation: loc() };
}

function makeMethod(
  name: string,
  params: { name: string; type: string }[],
  body: Statement[],
  visibility: 'public' | 'private' = 'public',
): MethodNode {
  return {
    kind: 'method',
    name,
    params: params.map(p => ({
      kind: 'param' as const,
      name: p.name,
      type: { kind: 'primitive_type' as const, name: p.type as 'bigint' },
    })),
    body,
    visibility,
    sourceLocation: loc(),
  };
}

function makeContract(methods: MethodNode[]): ContractNode {
  return {
    kind: 'contract',
    name: 'TestContract',
    parentClass: 'SmartContract',
    properties: [],
    constructor: makeMethod('constructor', [], [], 'public'),
    methods,
    sourceFile: 'test.ts',
  };
}

// ---------------------------------------------------------------------------
// Arithmetic evaluation
// ---------------------------------------------------------------------------

describe('RunarInterpreter: arithmetic', () => {
  it('evaluates bigint addition', () => {
    // public add(a: bigint, b: bigint) { return a + b; }
    const method = makeMethod('add', [
      { name: 'a', type: 'bigint' },
      { name: 'b', type: 'bigint' },
    ], [
      returnStmt(binaryExpr('+', ident('a'), ident('b'))),
    ]);

    const contract = makeContract([method]);
    const interp = new RunarInterpreter({});
    const result = interp.executeMethod(contract, 'add', {
      a: { kind: 'bigint', value: 10n },
      b: { kind: 'bigint', value: 20n },
    });

    expect(result.success).toBe(true);
    expect(result.returnValue).toEqual({ kind: 'bigint', value: 30n });
  });

  it('evaluates bigint subtraction', () => {
    const method = makeMethod('sub', [
      { name: 'a', type: 'bigint' },
      { name: 'b', type: 'bigint' },
    ], [
      returnStmt(binaryExpr('-', ident('a'), ident('b'))),
    ]);

    const contract = makeContract([method]);
    const interp = new RunarInterpreter({});
    const result = interp.executeMethod(contract, 'sub', {
      a: { kind: 'bigint', value: 50n },
      b: { kind: 'bigint', value: 20n },
    });

    expect(result.success).toBe(true);
    expect(result.returnValue).toEqual({ kind: 'bigint', value: 30n });
  });

  it('evaluates bigint multiplication', () => {
    const method = makeMethod('mul', [
      { name: 'a', type: 'bigint' },
      { name: 'b', type: 'bigint' },
    ], [
      returnStmt(binaryExpr('*', ident('a'), ident('b'))),
    ]);

    const contract = makeContract([method]);
    const interp = new RunarInterpreter({});
    const result = interp.executeMethod(contract, 'mul', {
      a: { kind: 'bigint', value: 7n },
      b: { kind: 'bigint', value: 6n },
    });

    expect(result.success).toBe(true);
    expect(result.returnValue).toEqual({ kind: 'bigint', value: 42n });
  });

  it('evaluates variable declarations and references', () => {
    // public compute(x: bigint) { const y = x + 1n; return y * 2n; }
    const method = makeMethod('compute', [
      { name: 'x', type: 'bigint' },
    ], [
      varDecl('y', binaryExpr('+', ident('x'), bigintLit(1n))),
      returnStmt(binaryExpr('*', ident('y'), bigintLit(2n))),
    ]);

    const contract = makeContract([method]);
    const interp = new RunarInterpreter({});
    const result = interp.executeMethod(contract, 'compute', {
      x: { kind: 'bigint', value: 10n },
    });

    expect(result.success).toBe(true);
    expect(result.returnValue).toEqual({ kind: 'bigint', value: 22n });
  });
});

// ---------------------------------------------------------------------------
// assert(true) / assert(false)
// ---------------------------------------------------------------------------

describe('RunarInterpreter: assert', () => {
  it('assert(true) succeeds', () => {
    const method = makeMethod('check', [], [
      exprStmt(callExpr('assert', [boolLit(true)])),
    ]);

    const contract = makeContract([method]);
    const interp = new RunarInterpreter({});
    const result = interp.executeMethod(contract, 'check', {});

    expect(result.success).toBe(true);
  });

  it('assert(false) fails', () => {
    const method = makeMethod('check', [], [
      exprStmt(callExpr('assert', [boolLit(false)])),
    ]);

    const contract = makeContract([method]);
    const interp = new RunarInterpreter({});
    const result = interp.executeMethod(contract, 'check', {});

    expect(result.success).toBe(false);
    expect(result.error).toContain('assert failed');
  });

  it('assert with condition expression', () => {
    // assert(a === b)
    const method = makeMethod('check', [
      { name: 'a', type: 'bigint' },
      { name: 'b', type: 'bigint' },
    ], [
      exprStmt(callExpr('assert', [binaryExpr('===', ident('a'), ident('b'))])),
    ]);

    const contract = makeContract([method]);
    const interp = new RunarInterpreter({});

    // Equal values: should succeed
    const result1 = interp.executeMethod(contract, 'check', {
      a: { kind: 'bigint', value: 42n },
      b: { kind: 'bigint', value: 42n },
    });
    expect(result1.success).toBe(true);

    // Different values: should fail
    const result2 = interp.executeMethod(contract, 'check', {
      a: { kind: 'bigint', value: 42n },
      b: { kind: 'bigint', value: 43n },
    });
    expect(result2.success).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Method not found
// ---------------------------------------------------------------------------

describe('RunarInterpreter: error handling', () => {
  it('returns error for unknown method', () => {
    const contract = makeContract([]);
    const interp = new RunarInterpreter({});
    const result = interp.executeMethod(contract, 'nonexistent', {});

    expect(result.success).toBe(false);
    expect(result.error).toContain('Method not found');
  });

  it('returns error for missing argument', () => {
    const method = makeMethod('add', [
      { name: 'a', type: 'bigint' },
      { name: 'b', type: 'bigint' },
    ], [
      returnStmt(binaryExpr('+', ident('a'), ident('b'))),
    ]);

    const contract = makeContract([method]);
    const interp = new RunarInterpreter({});
    const result = interp.executeMethod(contract, 'add', {
      a: { kind: 'bigint', value: 1n },
      // missing 'b'
    });

    expect(result.success).toBe(false);
    expect(result.error).toContain('Missing argument');
  });
});

// ---------------------------------------------------------------------------
// Property access
// ---------------------------------------------------------------------------

describe('RunarInterpreter: property access', () => {
  it('reads constructor properties via this.x', () => {
    // public getValue() { return this.x + 1n; }
    const method = makeMethod('getValue', [], [
      returnStmt(binaryExpr('+', { kind: 'property_access', property: 'x' }, bigintLit(1n))),
    ]);

    const contract = makeContract([method]);
    const interp = new RunarInterpreter({
      x: { kind: 'bigint', value: 99n },
    });
    const result = interp.executeMethod(contract, 'getValue', {});

    expect(result.success).toBe(true);
    expect(result.returnValue).toEqual({ kind: 'bigint', value: 100n });
  });
});

// ---------------------------------------------------------------------------
// Built-in hash functions
// ---------------------------------------------------------------------------

describe('RunarInterpreter: built-in functions', () => {
  it('sha256 produces 32-byte result', () => {
    const method = makeMethod('hashIt', [
      { name: 'data', type: 'bigint' },
    ], [
      returnStmt(callExpr('sha256', [ident('data')])),
    ]);

    const contract = makeContract([method]);
    const interp = new RunarInterpreter({});
    const result = interp.executeMethod(contract, 'hashIt', {
      data: { kind: 'bytes', value: new Uint8Array([0xab]) },
    });

    expect(result.success).toBe(true);
    expect(result.returnValue?.kind).toBe('bytes');
    if (result.returnValue?.kind === 'bytes') {
      expect(result.returnValue.value.length).toBe(32);
    }
  });

  it('hash160 produces 20-byte result', () => {
    const method = makeMethod('hashIt', [
      { name: 'data', type: 'bigint' },
    ], [
      returnStmt(callExpr('hash160', [ident('data')])),
    ]);

    const contract = makeContract([method]);
    const interp = new RunarInterpreter({});
    const result = interp.executeMethod(contract, 'hashIt', {
      data: { kind: 'bytes', value: new Uint8Array([0xab]) },
    });

    expect(result.success).toBe(true);
    expect(result.returnValue?.kind).toBe('bytes');
    if (result.returnValue?.kind === 'bytes') {
      expect(result.returnValue.value.length).toBe(20);
    }
  });
});
