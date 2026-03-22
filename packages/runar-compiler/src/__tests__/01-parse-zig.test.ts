import { describe, expect, it } from 'vitest';
import type {
  ForStatement,
  MethodNode,
  Statement,
  VariableDeclStatement,
} from '../ir/runar-ast.js';
import { parse } from '../passes/01-parse.js';
import { parseZigSource } from '../passes/01-parse-zig.js';

function parseContract(source: string) {
  const directResult = parseZigSource(source, 'Contract.runar.zig');
  const dispatchResult = parse(source, 'Contract.runar.zig');

  expect(directResult.errors.filter(error => error.severity === 'error')).toEqual([]);
  expect(dispatchResult.errors.filter(error => error.severity === 'error')).toEqual([]);

  return {
    direct: directResult.contract!,
    dispatch: dispatchResult.contract!,
  };
}

function requireMethod(method: MethodNode | undefined): MethodNode {
  expect(method).toBeDefined();
  return method!;
}

function requireVariableDecl(statement: Statement | undefined): VariableDeclStatement {
  expect(statement).toBeDefined();
  expect(statement?.kind).toBe('variable_decl');
  return statement as VariableDeclStatement;
}

function requireForStatement(statement: Statement | undefined): ForStatement {
  expect(statement).toBeDefined();
  expect(statement?.kind).toBe('for_statement');
  return statement as ForStatement;
}

describe('parseZigSource readonly stateful fields', () => {
  it('parses runar.Readonly(T) without a default as readonly in StatefulSmartContract', () => {
    const source = `
      const runar = @import("runar");

      pub const Counter = struct {
        pub const Contract = runar.StatefulSmartContract;

        owner: runar.Readonly(runar.PubKey),
        count: i64 = 0,
      };
    `;

    const { direct, dispatch } = parseContract(source);

    for (const contract of [direct, dispatch]) {
      const owner = contract.properties.find(property => property.name === 'owner');
      const count = contract.properties.find(property => property.name === 'count');

      expect(owner?.readonly).toBe(true);
      expect(owner?.initializer).toBeUndefined();
      expect(count?.readonly).toBe(false);
    }
  });

  it('parses runar.Readonly(T) with a default as readonly in StatefulSmartContract', () => {
    const source = `
      const runar = @import("runar");

      pub const Counter = struct {
        pub const Contract = runar.StatefulSmartContract;

        prefix: runar.Readonly(runar.ByteString) = "abc",
        count: i64 = 0,
      };
    `;

    const { direct, dispatch } = parseContract(source);

    for (const contract of [direct, dispatch]) {
      const prefix = contract.properties.find(property => property.name === 'prefix');
      const count = contract.properties.find(property => property.name === 'count');

      expect(prefix?.readonly).toBe(true);
      expect(prefix?.initializer).toMatchObject({ kind: 'bytestring_literal', value: 'abc' });
      expect(count?.readonly).toBe(false);
    }
  });

  it('keeps unwrapped uninitialized stateful fields readonly', () => {
    const source = `
      const runar = @import("runar");

      pub const Counter = struct {
        pub const Contract = runar.StatefulSmartContract;

        count: i64,
      };
    `;

    const { direct, dispatch } = parseContract(source);

    for (const contract of [direct, dispatch]) {
      expect(contract.properties[0]?.readonly).toBe(true);
    }
  });
});

describe('parseZigSource bytes equality lowering', () => {
  it('parses runar.bytesEq(a, b) as byte equality instead of a builtin call', () => {
    const source = `
      const runar = @import("runar");

      pub const EqContract = struct {
        pub const Contract = runar.SmartContract;

        pub fn unlock(self: EqContract, a: runar.ByteString, b: runar.ByteString) {
          _ = self;
          return runar.bytesEq(a, b);
        }
      };
    `;

    const { direct, dispatch } = parseContract(source);

    for (const contract of [direct, dispatch]) {
      const unlock = contract.methods.find(method => method.name === 'unlock');
      expect(unlock?.body).toHaveLength(1);

      const ret = unlock?.body[0];
      expect(ret?.kind).toBe('return_statement');

      if (ret?.kind === 'return_statement') {
        expect(ret.value).toEqual({
          kind: 'binary_expr',
          op: '===',
          left: { kind: 'identifier', name: 'a' },
          right: { kind: 'identifier', name: 'b' },
        });
      }
    }
  });
});

describe('parseZigSource bigint surface', () => {
  it('parses runar.Bigint as the normal bigint contract type', () => {
    const source = `
      const runar = @import("runar");

      pub const SchnorrZKP = struct {
        pub const Contract = runar.SmartContract;

        pubKey: runar.Point,

        pub fn verify(self: *const SchnorrZKP, rPoint: runar.Point, s: runar.Bigint) void {
          _ = self;
          _ = rPoint;
          _ = s;
        }
      };
    `;

    const { direct, dispatch } = parseContract(source);

    for (const contract of [direct, dispatch]) {
      const verify = requireMethod(contract.methods.find(method => method.name === 'verify'));
      expect(verify.params.map(param => [param.name, param.type])).toEqual([
        ['rPoint', { kind: 'primitive_type', name: 'Point' }],
        ['s', { kind: 'primitive_type', name: 'bigint' }],
      ]);
    }
  });
});

describe('parseZigSource @builtin expressions', () => {
  it('parses @divTrunc as binary division', () => {
    const source = `
      const runar = @import("runar");

      pub const Arithmetic = struct {
        pub const Contract = runar.SmartContract;

        target: i64,

        pub fn init(target: i64) Arithmetic {
          return .{ .target = target };
        }

        pub fn verify(self: *const Arithmetic, a: i64, b: i64) void {
          const quot = @divTrunc(a, b);
          runar.assert(quot == self.target);
        }
      };
    `;

    const { direct, dispatch } = parseContract(source);

    for (const contract of [direct, dispatch]) {
      const verify = requireMethod(contract.methods.find(method => method.name === 'verify'));
      // First statement should be variable_decl with a binary_expr (division)
      const quotDecl = requireVariableDecl(
        verify.body.find(s => s.kind === 'variable_decl' && s.name === 'quot'),
      );
      expect(quotDecl.init).toMatchObject({ kind: 'binary_expr', op: '/' });
    }
  });

  it('parses @mod as binary modulo', () => {
    const source = `
      const runar = @import("runar");

      pub const Modulo = struct {
        pub const Contract = runar.SmartContract;

        target: i64,

        pub fn init(target: i64) Modulo {
          return .{ .target = target };
        }

        pub fn verify(self: *const Modulo, a: i64, b: i64) void {
          const rem = @mod(a, b);
          runar.assert(rem == self.target);
        }
      };
    `;

    const { direct, dispatch } = parseContract(source);

    for (const contract of [direct, dispatch]) {
      const verify = requireMethod(contract.methods.find(method => method.name === 'verify'));
      const remDecl = requireVariableDecl(
        verify.body.find(s => s.kind === 'variable_decl' && s.name === 'rem'),
      );
      expect(remDecl.init).toMatchObject({ kind: 'binary_expr', op: '%' });
    }
  });

  it('parses @shlExact as binary left shift', () => {
    const source = `
      const runar = @import("runar");

      pub const Shift = struct {
        pub const Contract = runar.SmartContract;

        pub fn verify(self: *const Shift, a: i64, b: i64) void {
          _ = self;
          const shifted = @shlExact(a, b);
          _ = shifted;
        }
      };
    `;

    const { direct, dispatch } = parseContract(source);

    for (const contract of [direct, dispatch]) {
      const verify = requireMethod(contract.methods.find(method => method.name === 'verify'));
      const shiftedDecl = requireVariableDecl(
        verify.body.find(s => s.kind === 'variable_decl' && s.name === 'shifted'),
      );
      expect(shiftedDecl.init).toMatchObject({ kind: 'binary_expr', op: '<<' });
    }
  });

  it('reports unsupported @builtins instead of silently rewriting them', () => {
    const source = `
      const runar = @import("runar");

      pub const Shift = struct {
        pub const Contract = runar.SmartContract;

        pub fn verify(self: *const Shift, a: i64, b: i64) void {
          _ = self;
          const shifted = @foo(a, b);
          _ = shifted;
        }
      };
    `;

    const direct = parseZigSource(source, 'Contract.runar.zig');
    const dispatch = parse(source, 'Contract.runar.zig');

    for (const result of [direct, dispatch]) {
      const errors = result.errors.filter(error => error.severity === 'error');
      expect(errors.some(error => error.message.includes("Unsupported Zig builtin '@foo'"))).toBe(true);

      const verify = requireMethod(result.contract!.methods.find(method => method.name === 'verify'));
      const shiftedDecl = requireVariableDecl(
        verify.body.find(s => s.kind === 'variable_decl' && s.name === 'shifted'),
      );
      expect(shiftedDecl.init).toMatchObject({
        kind: 'call_expr',
        callee: { kind: 'identifier', name: 'foo' },
      });
    }
  });
});

describe('parseZigSource while loop lowering', () => {
  it('only merges the preceding variable decl when it matches the loop update target', () => {
    const source = `
      const runar = @import("runar");

      pub const Counter = struct {
        pub const Contract = runar.SmartContract;

        pub fn verify(self: *const Counter, n: i64) void {
          _ = self;
          const total = n + 1;
          while (n < 3) : (n += 1) {
            runar.assert(total > 0);
          }
        }
      };
    `;

    const { direct, dispatch } = parseContract(source);

    for (const contract of [direct, dispatch]) {
      const verify = requireMethod(contract.methods.find(method => method.name === 'verify'));
      expect(verify.body).toHaveLength(2);
      expect(verify.body[0]).toMatchObject({ kind: 'variable_decl', name: 'total' });
      expect(verify.body[1]).toMatchObject({ kind: 'for_statement' });

      const totalDecl = requireVariableDecl(verify.body[0]);
      expect(totalDecl.name).toBe('total');

      const loop = requireForStatement(verify.body[1]);
      expect(loop.init).toMatchObject({ kind: 'variable_decl', name: '__while_no_init' });
    }
  });
});

describe('parseZigSource StatefulContext desugaring', () => {
  it('desugars StatefulContext builtins to canonical contract intrinsics', () => {
    const source = `
      const runar = @import("runar");

      pub const Counter = struct {
        pub const Contract = runar.StatefulSmartContract;

        count: i64 = 0,

        pub fn increment(self: *Counter, ctx: runar.StatefulContext, outputSatoshis: i64) void {
          runar.assert(ctx.txPreimage == ctx.txPreimage);
          ctx.addOutput(outputSatoshis, .{ self.count + 1 });
        }
      };
    `;

    const { direct, dispatch } = parseContract(source);

    for (const contract of [direct, dispatch]) {
      const increment = requireMethod(contract.methods.find(method => method.name === 'increment'));
      expect(increment.body).toHaveLength(2);

      const assertion = increment.body[0];
      expect(assertion).toMatchObject({ kind: 'expression_statement' });
      if (assertion?.kind === 'expression_statement') {
        expect(assertion.expression).toMatchObject({
          kind: 'call_expr',
          callee: { kind: 'identifier', name: 'assert' },
          args: [{
            kind: 'binary_expr',
            op: '===',
            left: { kind: 'property_access', property: 'txPreimage' },
            right: { kind: 'property_access', property: 'txPreimage' },
          }],
        });
      }

      const addOutput = increment.body[1];
      expect(addOutput).toMatchObject({ kind: 'expression_statement' });
      if (addOutput?.kind === 'expression_statement') {
        expect(addOutput.expression).toMatchObject({
          kind: 'call_expr',
          callee: { kind: 'property_access', property: 'addOutput' },
        });
      }
    }
  });
});

describe('parseZigSource helper method calls', () => {
  it('rewrites bare helper calls to canonical contract method calls', () => {
    const source = `
      const runar = @import("runar");

      pub const MultiMethod = struct {
        pub const Contract = runar.SmartContract;

        owner: runar.PubKey,

        pub fn init(owner: runar.PubKey) MultiMethod {
          return .{ .owner = owner };
        }

        fn computeThreshold(a: i64, b: i64) i64 {
          return a * b + 1;
        }

        pub fn spend(self: *const MultiMethod, amount: i64) void {
          _ = self;
          const threshold = computeThreshold(amount, 2);
          runar.assert(threshold > 10);
        }
      };
    `;

    const { direct, dispatch } = parseContract(source);

    for (const contract of [direct, dispatch]) {
      const spend = requireMethod(contract.methods.find(method => method.name === 'spend'));
      const thresholdDecl = requireVariableDecl(
        spend.body.find(statement => statement.kind === 'variable_decl' && statement.name === 'threshold'),
      );
      expect(thresholdDecl.init).toMatchObject({
        kind: 'call_expr',
        callee: { kind: 'property_access', property: 'computeThreshold' },
      });
    }
  });
});
