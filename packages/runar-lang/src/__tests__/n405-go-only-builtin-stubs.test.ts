import { describe, it, expect } from 'vitest';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import ts from 'typescript';
import * as lang from '../index.js';

// N-405: verifySP1FRI, merkleRootPoseidon2KB, assertGroth16WitnessAssisted,
// assertGroth16WitnessAssistedWithMSM and groth16PublicInput are Go-tier
// builtins listed in runar-compiler's builtin-arity.ts, but runar-lang exported
// none of them, so a .runar.ts contract importing them failed tsc before any
// Go compiler saw it.
//
// Proves: each name is exported as a function that throws the compile-stub
// error, its declared parameter count equals builtin-arity.ts (hard-coded copy) (merkleRootPoseidon2KB
// is variadic, 8*depth + 10 bigints, so it is a rest parameter), and a contract
// source importing and calling all five typechecks under tsc against runar-lang
// while a wrongly-typed call is rejected.
// Does not prove: that any compiler lowers them (Go-only, see CLAUDE.md), or
// on-chain behaviour.
const here = path.dirname(fileURLToPath(import.meta.url));
const indexTs = path.resolve(here, '../index.ts');

// Arities copied from runar-compiler/src/ir/builtin-arity.ts (runar-lang cannot
// import compiler sources: its tsc rootDir is its own src). merkleRootPoseidon2KB
// takes 8*depth + 10 arguments, so it is a rest parameter (length 0).
const ARITY: Record<string, number> = {
  verifySP1FRI: 3,
  assertGroth16WitnessAssisted: 0,
  assertGroth16WitnessAssistedWithMSM: 0,
  groth16PublicInput: 1,
};

const NAMES = [
  'verifySP1FRI',
  'merkleRootPoseidon2KB',
  'assertGroth16WitnessAssisted',
  'assertGroth16WitnessAssistedWithMSM',
  'groth16PublicInput',
] as const;

function diagnose(source: string): string[] {
  const file = path.resolve(here, '__n405_virtual__.ts');
  const options: ts.CompilerOptions = {
    noEmit: true,
    strict: true,
    skipLibCheck: true,
    target: ts.ScriptTarget.ES2022,
    module: ts.ModuleKind.ESNext,
    moduleResolution: ts.ModuleResolutionKind.Bundler,
    allowImportingTsExtensions: true,
    types: [],
  };
  const host = ts.createCompilerHost(options);
  const origRead = host.readFile.bind(host);
  const origExists = host.fileExists.bind(host);
  const origSource = host.getSourceFile.bind(host);
  host.fileExists = (f) => f === file || origExists(f);
  host.readFile = (f) => (f === file ? source : origRead(f));
  host.getSourceFile = (f, l, ...rest) =>
    f === file ? ts.createSourceFile(f, source, l) : origSource(f, l, ...rest);
  const program = ts.createProgram([file], options, host);
  return ts
    .getPreEmitDiagnostics(program, program.getSourceFile(file))
    .filter((d) => d.file?.fileName === file)
    .map((d) => ts.flattenDiagnosticMessageText(d.messageText, '\n'));
}

describe('N-405 Go-only builtins are exported by runar-lang', () => {
  for (const name of NAMES) {
    it(`${name} is exported and is a compiler stub`, () => {
      const fn = (lang as unknown as Record<string, unknown>)[name];
      expect(typeof fn).toBe('function');
      expect(() => (fn as () => unknown)()).toThrow(`${name}()`);
    });
    if (name !== 'merkleRootPoseidon2KB') {
      it(`${name} declared arity equals builtin-arity.ts`, () => {
        const fn = (lang as unknown as Record<string, unknown>)[name] as (...a: unknown[]) => unknown;
        expect(typeof fn).toBe('function');
        expect(fn.length).toBe(ARITY[name]);
      });
    }
  }

  it('merkleRootPoseidon2KB is variadic (rest parameter)', () => {
    const fn = (lang as unknown as Record<string, unknown>).merkleRootPoseidon2KB as (...a: unknown[]) => unknown;
    expect(typeof fn).toBe('function');
    expect(fn.length).toBe(0);
  });

  const importPath = indexTs.replace(/\.ts$/, '.js');
  const good = `
import {
  verifySP1FRI, merkleRootPoseidon2KB, assertGroth16WitnessAssisted,
  assertGroth16WitnessAssistedWithMSM, groth16PublicInput,
} from ${JSON.stringify(importPath)};
import type { ByteString } from ${JSON.stringify(importPath)};
export function f(a: ByteString, b: ByteString, c: ByteString, i: bigint): boolean {
  const ok: boolean = verifySP1FRI(a, b, c);
  const x: bigint = groth16PublicInput(i);
  const r: bigint = merkleRootPoseidon2KB(1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n, 0n, 0n);
  assertGroth16WitnessAssisted();
  assertGroth16WitnessAssistedWithMSM();
  return ok && x === r;
}
`;
  it('a contract source importing and calling all five typechecks', () => {
    expect(diagnose(good)).toEqual([]);
  });

  it('wrongly-typed calls are rejected', () => {
    const bad = `
import { verifySP1FRI, groth16PublicInput, assertGroth16WitnessAssisted } from ${JSON.stringify(importPath)};
export const a: boolean = verifySP1FRI(1n, 2n, 3n);
export const b: bigint = groth16PublicInput('x');
export const c = assertGroth16WitnessAssisted(1n);
`;
    expect(diagnose(bad).length).toBeGreaterThanOrEqual(3);
  });
});
