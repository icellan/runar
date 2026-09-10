/**
 * R-064 — `assert`, `exit`, `pack` and `toByteString` must reject a
 * zero-argument call at compile time.
 *
 * Each of these four arms in `lowerCall` (05-stack-lower.ts) was shaped
 *
 *     if (func === 'assert') {
 *       if (args.length >= 1) { ...bringToTop, OP_VERIFY, stackMap.push(name) }
 *       return;
 *     }
 *
 * so a zero-argument call fell straight through the `if` and returned having
 * emitted NO opcodes and having never registered the binding's stack slot.
 * For `assert` / `exit` that silently deletes the OP_VERIFY — Rúnar's primary
 * control mechanism ("scripts fail if any assert is false") compiled to
 * nothing. For `pack` / `toByteString` the operand is left stranded on the
 * runtime stack with no stack-map entry, so the method epilogue's cleanup is
 * short by one slot.
 *
 * REACHABILITY: NOT reachable from source — 03-typecheck.ts rejects
 * `assert()` ("assert() expects 1 or 2 arguments, got 0") and rejects zero-arg
 * `exit` / `pack` / `toByteString` via the generic `args.length !==
 * sig.params.length` check. It IS reachable through `compileFromANF` /
 * CLI `--from-ir`, which never runs a typecheck. Both are covered below.
 *
 * The guard lives in the lowerer rather than the typechecker for exactly the
 * reason the neighbouring `lowerCheckMultiSig` guard documents: the `--ir`
 * input path never runs a typecheck. No defensive opcodes are emitted, so the
 * bytes of every correct-arity call are unchanged (see the control block).
 */

import { describe, it, expect } from 'vitest';
import { compile, compileFromANF } from '../index.js';
import type { ANFProgram, ANFBinding } from '../ir/index.js';

const P = (name: string, type: string) => ({ name, type });

function prog(
  properties: { name: string; type: string; readonly?: boolean }[],
  params: { name: string; type: string }[],
  body: ANFBinding[],
): ANFProgram {
  return {
    contractName: 'ArityProbe',
    properties: properties.map(p => ({ ...p, readonly: true })),
    methods: [{ name: 'unlock', params, body, isPublic: true }],
  };
}

/** `unlock(x) { <func>(...args) ; assert(x === target) }` over the --ir path. */
function withLeadingCall(func: string, args: string[]): ANFProgram {
  return prog([P('target', 'bigint')], [P('x', 'bigint')], [
    { name: 't0', value: { kind: 'call', func, args } } as unknown as ANFBinding,
    { name: 't1', value: { kind: 'load_prop', name: 'target' } },
    { name: 't2', value: { kind: 'bin_op', op: '===', left: 'x', right: 't1' } },
    { name: 't3', value: { kind: 'call', func: 'assert', args: ['t2'] } } as unknown as ANFBinding,
  ]);
}

/** Baseline captured before the guard landed; must not move. */
const SOURCE_CONTROL_HEX = '7c00880087';

const ZERO_ARG_BUILTINS = ['assert', 'exit', 'pack', 'toByteString'] as const;

describe('R-064: zero-argument assert / exit / pack / toByteString', () => {
  describe('reachability: the source pipeline already rejects these', () => {
    it('assert() with no arguments is a typecheck error', () => {
      const src = `
import { SmartContract, assert } from 'runar-lang';
export class Probe extends SmartContract {
  constructor() { super(); }
  public unlock(x: bigint): void {
    assert();
  }
}`;
      const messages = compile(src, { fileName: 'Probe.runar.ts' }).diagnostics.map(d => d.message);
      expect(messages.join('\n')).toMatch(/assert\(\) expects 1 or 2 arguments, got 0/);
    });

    it.each(['exit', 'pack', 'toByteString'])(
      '%s() with no arguments is a typecheck error',
      (func) => {
        const src = `
import { SmartContract, assert, ${func} } from 'runar-lang';
export class Probe extends SmartContract {
  constructor() { super(); }
  public unlock(x: bigint): void {
    ${func}();
    assert(x === 1n);
  }
}`;
        const messages = compile(src, { fileName: 'Probe.runar.ts' }).diagnostics.map(d => d.message);
        expect(messages.join('\n')).toMatch(
          new RegExp(`${func}\\(\\) expects 1 argument\\(s\\), got 0`),
        );
      },
    );
  });

  describe('the --ir path (compileFromANF) must reject them too', () => {
    it.each(ZERO_ARG_BUILTINS)('%s with no arguments throws', (func) => {
      expect(() => compileFromANF(withLeadingCall(func, []), {
        constructorArgs: { target: 5n },
        disableConstantFolding: true,
      })).toThrow(new RegExp(`${func} requires 1 argument, got 0`));
    });
  });

  describe('controls: correct-arity calls are byte-unchanged', () => {
    it('assert(cond) still emits the verify', () => {
      const { scriptHex, scriptAsm } = compileFromANF(
        prog([P('target', 'bigint')], [P('x', 'bigint')], [
          { name: 't1', value: { kind: 'load_prop', name: 'target' } },
          { name: 't2', value: { kind: 'bin_op', op: '===', left: 'x', right: 't1' } },
          { name: 't3', value: { kind: 'call', func: 'assert', args: ['t2'] } } as unknown as ANFBinding,
        ]),
        { constructorArgs: { target: 5n }, disableConstantFolding: true },
      );
      // Peephole fuses OP_NUMEQUAL + OP_VERIFY into OP_NUMEQUALVERIFY (0x9d).
      // Before the guard landed, `assert()` compiled this same program to
      // `OP_5 OP_NUMEQUAL` (55 9c) — the verify silently gone.
      expect(scriptAsm).toBe('OP_5 OP_NUMEQUALVERIFY');
      expect(scriptHex).toBe('559d');
    });

    it('exit(cond) still emits the verify', () => {
      const { scriptHex } = compileFromANF(
        prog([P('target', 'bigint')], [P('x', 'bigint')], [
          { name: 't1', value: { kind: 'load_prop', name: 'target' } },
          { name: 't2', value: { kind: 'bin_op', op: '===', left: 'x', right: 't1' } },
          { name: 't3', value: { kind: 'call', func: 'exit', args: ['t2'] } } as unknown as ANFBinding,
        ]),
        { constructorArgs: { target: 5n }, disableConstantFolding: true },
      );
      expect(scriptHex).toBe('559d');
    });

    it('pack(x) is byte-unchanged', () => {
      const { scriptHex } = compileFromANF(
        prog([P('target', 'ByteString')], [P('x', 'bigint')], [
          { name: 't0', value: { kind: 'call', func: 'pack', args: ['x'] } } as unknown as ANFBinding,
          { name: 't1', value: { kind: 'load_prop', name: 'target' } },
          { name: 't2', value: { kind: 'bin_op', op: '===', left: 't0', right: 't1' } },
          { name: 't3', value: { kind: 'call', func: 'assert', args: ['t2'] } } as unknown as ANFBinding,
        ]),
        { constructorArgs: { target: '0102' }, disableConstantFolding: true },
      );
      expect(scriptHex).toBe('0201029d');
    });

    it('toByteString(x) is byte-unchanged', () => {
      const { scriptHex } = compileFromANF(
        prog([P('target', 'ByteString')], [P('x', 'ByteString')], [
          { name: 't0', value: { kind: 'call', func: 'toByteString', args: ['x'] } } as unknown as ANFBinding,
          { name: 't1', value: { kind: 'load_prop', name: 'target' } },
          { name: 't2', value: { kind: 'bin_op', op: '===', left: 't0', right: 't1' } },
          { name: 't3', value: { kind: 'call', func: 'assert', args: ['t2'] } } as unknown as ANFBinding,
        ]),
        { constructorArgs: { target: '0102' }, disableConstantFolding: true },
      );
      expect(scriptHex).toBe('0201029d');
    });

    it('a real source contract using assert / pack / toByteString is byte-unchanged', () => {
      const src = `
import { SmartContract, ByteString, assert, pack, toByteString } from 'runar-lang';
export class Probe extends SmartContract {
  readonly target: ByteString;
  constructor(target: ByteString) { super(target); this.target = target; }
  public unlock(x: bigint, b: ByteString): void {
    assert(pack(x) === this.target);
    assert(toByteString(b) === this.target);
  }
}`;
      const result = compile(src, { fileName: 'Probe.runar.ts', disableConstantFolding: true });
      expect(result.diagnostics.filter(d => d.severity === 'error')).toEqual([]);
      expect(result.scriptHex).toBe(SOURCE_CONTROL_HEX);
    });
  });
});
