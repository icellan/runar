import { describe, expect, it } from 'vitest';
import type {
  ForStatement,
  MethodNode,
  Statement,
  VariableDeclStatement,
} from '../ir/runar-ast.js';
import { parse } from '../passes/01-parse.js';
import { parseZigSource } from '../passes/01-parse-zig.js';
import { compile } from '../index.js';

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

        prefix: runar.Readonly(runar.ByteString) = runar.hexToBytes("abc"),
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

  // N-182 / R93: runar.BigintBig is the 256-bit native spelling (u256 in
  // packages/runar-zig) for EC coordinates. Proves: it lowers to the same AST
  // bigint as runar.Bigint, for a property and a parameter. Does NOT prove the
  // native u256 runtime (packages/runar-zig tests) or any codegen.
  it('parses runar.BigintBig as the bigint contract type (N-182)', () => {
    const source = `
      const runar = @import("runar");

      pub const BigCoord = struct {
        pub const Contract = runar.SmartContract;

        x: runar.BigintBig,

        pub fn init(x: runar.BigintBig) BigCoord {
          return .{ .x = x };
        }

        pub fn check(self: *const BigCoord, y: runar.BigintBig) void {
          runar.assert(self.x == y);
        }
      };
    `;

    const { direct, dispatch } = parseContract(source);

    for (const contract of [direct, dispatch]) {
      expect(contract.properties.map(p => [p.name, p.type])).toEqual([
        ['x', { kind: 'primitive_type', name: 'bigint' }],
      ]);
      const check = requireMethod(contract.methods.find(method => method.name === 'check'));
      expect(check.params.map(param => [param.name, param.type])).toEqual([
        ['y', { kind: 'primitive_type', name: 'bigint' }],
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
      expect(loop.init).toMatchObject({ kind: 'variable_decl', name: ' __while_no_init' });
    }
  });

  it('N-009: a user local spelled exactly like the merge placeholder does not fool the ' +
    'condition-iterator check into unrolling from 0', () => {
    // Non-adjacent declaration (an unrelated `var sum` sits between the real
    // loop variable and the `while`), same shape `conformance/negatives/N162-
    // zig-while-non-adjacent-init.runar.zig` already refuses for a variable
    // named `i` -- except here the developer's OWN variable is spelled
    // `__while_no_init`, identically to the parser's merge placeholder. Before
    // the fix this collided: the unmerged placeholder's synthesized name and
    // the user's real declaration were both the literal string
    // `__while_no_init`, so `04-anf-lower.ts`'s condition-iterator check
    // (`condition.left.name !== stmt.init.name`) compared equal and let the
    // loop compile unrolled from the placeholder's start of 0 instead of the
    // declared start of 3 -- a silent miscompile (@bsv/sdk Spend.validate()
    // then accepts sum=10 and rejects the correct sum=7, measured directly
    // via ScriptExecutionContract at HEAD before this fix). This test proves
    // only that the contract is REFUSED; the on-chain acceptance/rejection
    // pair is recorded in prose on the N-253 conformance negative fixture,
    // not re-measured here.
    const source = `
      const runar = @import("runar");

      pub const Collide = struct {
        pub const Contract = runar.SmartContract;

        target: i64,

        pub fn init(target: i64) Collide {
          return .{ .target = target };
        }

        pub fn check(self: *const Collide, expected: i64) void {
          var __while_no_init: i64 = 3;
          var sum: i64 = 0;
          while (__while_no_init < 5) : (__while_no_init += 1) {
            sum = sum + __while_no_init;
          }
          runar.assert(sum == expected);
          runar.assert(self.target == self.target);
        }
      };
    `;

    const result = compile(source, { fileName: 'Collide.runar.zig', disableConstantFolding: true });

    expect(result.success).toBe(false);
    const messages = result.diagnostics.filter(d => d.severity === 'error').map(d => d.message);
    expect(messages.some(m => m.includes('must compare the loop variable'))).toBe(true);
  });

  it('N-009 control: a user local literally named __while_no_init still compiles ' +
    'correctly when it IS the adjacent loop declaration', () => {
    // The fix must not turn `__while_no_init` into a name developers cannot
    // use at all -- only the UNMERGED placeholder is unspellable now (a
    // leading space). When the user's `__while_no_init` declaration is
    // adjacent to the `while` (the normal merge case), the merge gate
    // compares the declaration's name against the UPDATE target's name
    // (both spelled `__while_no_init`, no space), not against the
    // placeholder, so it still folds and the real start of 3 is honoured.
    // Same bytes as N-008's adjacent control (`577c9d00009c`): OP_7 OP_SWAP
    // OP_NUMEQUALVERIFY OP_0 OP_0 OP_NUMEQUAL -- sum = 3 + 4 = 7.
    const source = `
      const runar = @import("runar");

      pub const Collide = struct {
        pub const Contract = runar.SmartContract;

        target: i64,

        pub fn init(target: i64) Collide {
          return .{ .target = target };
        }

        pub fn check(self: *const Collide, expected: i64) void {
          var sum: i64 = 0;
          var __while_no_init: i64 = 3;
          while (__while_no_init < 5) : (__while_no_init += 1) {
            sum = sum + __while_no_init;
          }
          runar.assert(sum == expected);
          runar.assert(self.target == self.target);
        }
      };
    `;

    const result = compile(source, { fileName: 'Collide.runar.zig', disableConstantFolding: true });

    expect(result.diagnostics.filter(d => d.severity === 'error')).toEqual([]);
    expect(result.success).toBe(true);
    expect(result.artifact?.script).toBe('577c9d00009c');
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
