/**
 * R-285 (CL-GAP-075) — every branch in generated Script must leave both arms
 * at the same stack depth.
 *
 * `ECTracker` tracks the stack as a list of names and updates it from
 * hand-declared arities: `rawBlock(consume, produce, …)` is TOLD what it moves,
 * and `emitIf(…, resultName)` is TOLD whether the branch yields a value.
 * Nothing checked either declaration against the opcodes actually emitted. The
 * 257-step secp256k1 ladder is built out of those two primitives and the
 * P-256/P-384 and BN254 codegens reuse them, so one miscounted arm would put
 * every later `findDepth` off by a constant — and PICK/ROLL would address the
 * wrong stack item. The result is a different locking script, produced
 * silently.
 *
 * Measured before the check existed: 77,437 branch nodes across the 78
 * checked-in IR goldens, none of them actually imbalanced. So this is a
 * regression net over a currently-correct corpus, not a bug report — the
 * finding's claim was about the MISSING cross-check, and that part was true.
 *
 * `stackDelta` refuses to model an opcode it does not know rather than
 * returning 0 for it. A table that silently scored unknown opcodes as
 * stack-neutral would make this whole file vacuously green, which is exactly
 * the shape of the hole it is meant to close.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadANFFromJSON } from '../packages/runar-compiler/src/index.js';
import { lowerToStack } from '../packages/runar-compiler/src/passes/05-stack-lower.js';
import {
  stackDelta,
  modelledOpcodes,
  UnmodelledStackOpError,
} from '../packages/runar-compiler/src/passes/stack-op-effects.js';
import type { StackOp } from '../packages/runar-compiler/src/ir/stack-ir.js';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const fixturesDir = join(repoRoot, 'conformance', 'tests');

const opcode = (code: string): StackOp => ({ op: 'opcode', code }) as StackOp;
const push = (value: bigint): StackOp => ({ op: 'push', value }) as StackOp;

describe('stackDelta', () => {
  it('scores a straight-line run from the opcodes', () => {
    // push push OP_ADD: +1 +1 -1 = +1
    expect(stackDelta([push(1n), push(2n), opcode('OP_ADD')])).toBe(1);
  });

  it('scores a balanced structural if as arms-minus-condition', () => {
    const branch = {
      op: 'if',
      then: [push(1n)],
      else: [push(2n)],
    } as unknown as StackOp;
    expect(stackDelta([branch])).toBe(0); // +1 arm, -1 condition
  });

  it('refuses an imbalanced structural if', () => {
    const branch = {
      op: 'if',
      then: [push(1n), push(1n)],
      else: [push(2n)],
    } as unknown as StackOp;
    expect(() => stackDelta([branch])).toThrow(/different depths/);
  });

  it('scores a raw OP_IF / OP_ELSE / OP_ENDIF span', () => {
    const ops = [
      opcode('OP_IF'), push(1n), opcode('OP_ELSE'), push(2n), opcode('OP_ENDIF'),
    ];
    expect(stackDelta(ops)).toBe(0);
  });

  it('refuses an imbalanced raw OP_IF span', () => {
    const ops = [
      opcode('OP_IF'), push(1n), push(1n), opcode('OP_ELSE'), push(2n), opcode('OP_ENDIF'),
    ];
    expect(() => stackDelta(ops)).toThrow(/different depths/);
  });

  it('handles a nested raw span without confusing the inner OP_ELSE/OP_ENDIF for the outer', () => {
    const ops = [
      opcode('OP_IF'),
        opcode('OP_IF'), push(1n), opcode('OP_ELSE'), push(2n), opcode('OP_ENDIF'),
        push(9n),
      opcode('OP_ELSE'),
        push(3n),
      opcode('OP_ENDIF'),
    ];
    // then arm: inner branch is +1/+1 so it nets 1 - 1 = 0, plus push9 = +1.
    // else arm: +1. Balanced, so the outer branch nets 1 - 1 = 0.
    //
    // A parser that ignored nesting would take the INNER OP_ELSE as the outer
    // one and the inner OP_ENDIF as the outer close, leaving the then arm as
    // an unterminated `OP_IF push1` — which throws. So the assertion below
    // fails if nesting tracking is removed, rather than coincidentally passing.
    expect(stackDelta(ops)).toBe(0);
  });

  it('refuses an unclosed raw span rather than scoring the tail as the then arm', () => {
    expect(() => stackDelta([opcode('OP_IF'), push(1n)])).toThrow(/not closed/);
  });

  it('refuses an opcode it does not model instead of scoring it as neutral', () => {
    expect(() => stackDelta([opcode('OP_NONSENSE')])).toThrow(UnmodelledStackOpError);
  });

  it('refuses an op kind it does not model', () => {
    expect(() => stackDelta([{ op: 'nonsense' } as unknown as StackOp]))
      .toThrow(UnmodelledStackOpError);
  });
});

describe('the effects table tracks the analyzer it was copied from', () => {
  // `packages/runar-testing` depends on `runar-compiler`, so the compiler-side
  // table cannot import the analyzer's. Diff them as source instead, or they
  // drift the way seven copies of `methodUsesCodePart` did (R-287).
  const analyzerSource = readFileSync(
    join(repoRoot, 'packages', 'runar-testing', 'src', 'analyzer', 'stack-analyzer.ts'),
    'utf8',
  );
  const tableBody = analyzerSource.slice(
    analyzerSource.indexOf('const STACK_EFFECTS'),
    analyzerSource.indexOf('export function getStackEffect'),
  );
  const analyzerOpcodes = new Set(
    [...tableBody.matchAll(/\[Opcode\.(OP_[A-Z0-9_]+)\]/g)].map(m => m[1]!),
  );
  // Branch opcodes are handled structurally by `stackDelta`, not by arity.
  const structural = new Set(['OP_IF', 'OP_NOTIF', 'OP_ELSE', 'OP_ENDIF']);
  const ours = new Set(modelledOpcodes());

  it('extracted a real table from the analyzer (anti-vacuity)', () => {
    expect(analyzerOpcodes.size).toBeGreaterThan(50);
  });

  it('models every opcode the analyzer models, minus the structural ones', () => {
    const missing = [...analyzerOpcodes].filter(o => !structural.has(o) && !ours.has(o));
    expect(missing).toEqual([]);
  });
});

describe('every branch in every golden leaves its arms balanced', () => {
  const goldens = readdirSync(fixturesDir).sort()
    .map(name => ({ name, irPath: join(fixturesDir, name, 'expected-ir.json') }))
    .filter(g => existsSync(g.irPath));

  let branchCount = 0;
  const failures: string[] = [];

  for (const golden of goldens) {
    const program = lowerToStack(loadANFFromJSON(readFileSync(golden.irPath, 'utf8')));
    for (const method of program.methods) {
      const visit = (ops: readonly StackOp[]): void => {
        for (const op of ops) {
          if (op.op !== 'if') continue;
          branchCount++;
          const node = op as unknown as { then?: StackOp[]; else?: StackOp[] };
          try {
            stackDelta([op]);
          } catch (e) {
            failures.push(`${golden.name}/${method.name}: ${(e as Error).message}`);
          }
          visit(node.then ?? []);
          visit(node.else ?? []);
        }
      };
      visit(method.ops as StackOp[]);
    }
  }

  it('examined the whole corpus (anti-vacuity)', () => {
    expect(goldens.length).toBeGreaterThanOrEqual(70);
    expect(branchCount).toBeGreaterThan(1000);
  });

  it('found no imbalanced or unmodelled branch', () => {
    expect(failures.slice(0, 10)).toEqual([]);
  });
});
