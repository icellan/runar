import { describe, it, expect } from 'vitest';
import { existsSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { computeNewStateAndDataOutputs } from 'runar-sdk';
import type { ANFProgram } from 'runar-ir-schema';

const __dirname = dirname(fileURLToPath(import.meta.url));
const CONFORMANCE_TESTS_DIR = join(__dirname, '../tests');
const INPUTS_DIR = join(__dirname, 'inputs');
const EXPECTED_DIR = join(__dirname, 'expected');

interface CaseInput {
  case: string;
  methodName: string;
  currentState: Record<string, unknown>;
  args: Record<string, unknown>;
  constructorArgs: unknown[];
}

interface CaseOutput {
  state: Record<string, unknown>;
  dataOutputs: Array<{ satoshis: string; script: string }>;
}

/**
 * Decode `"42n"` → `42n` recursively. Inputs use the trailing-`n` convention
 * for bigints to keep them representable in JSON.
 */
function decodeBigints(v: unknown): unknown {
  if (typeof v === 'string' && /^-?\d+n$/.test(v)) {
    return BigInt(v.slice(0, -1));
  }
  if (Array.isArray(v)) return v.map(decodeBigints);
  if (v && typeof v === 'object') {
    const r: Record<string, unknown> = {};
    for (const [k, val] of Object.entries(v)) r[k] = decodeBigints(val);
    return r;
  }
  return v;
}

/** Normalize the interpreter result so `bigint`s are stringly-comparable. */
function normalizeResult(result: { state: Record<string, unknown>; dataOutputs: Array<{ satoshis: bigint | number; script: string }> }): CaseOutput {
  function encode(v: unknown): unknown {
    if (typeof v === 'bigint') return v.toString() + 'n';
    if (Array.isArray(v)) return v.map(encode);
    if (v && typeof v === 'object') {
      const r: Record<string, unknown> = {};
      for (const [k, val] of Object.entries(v)) r[k] = encode(val);
      return r;
    }
    return v;
  }
  return {
    state: encode(result.state) as Record<string, unknown>,
    dataOutputs: result.dataOutputs.map(d => ({
      satoshis: typeof d.satoshis === 'bigint' ? d.satoshis.toString() + 'n' : String(d.satoshis) + 'n',
      script: d.script,
    })),
  };
}

function loadAnf(caseName: string): ANFProgram {
  const path = join(CONFORMANCE_TESTS_DIR, caseName, 'expected-ir.json');
  return JSON.parse(readFileSync(path, 'utf8')) as ANFProgram;
}

const inputFiles = readdirSync(INPUTS_DIR).filter(f => f.endsWith('.json')).sort();

describe('ANF interpreter parity (TS SDK)', () => {
  for (const inputFile of inputFiles) {
    const baseName = inputFile.replace(/\.json$/, '');
    it(`${baseName} matches pinned golden`, () => {
      const inputRaw = JSON.parse(readFileSync(join(INPUTS_DIR, inputFile), 'utf8')) as CaseInput;
      const input = decodeBigints(inputRaw) as CaseInput;
      const anf = loadAnf(input.case);
      const result = computeNewStateAndDataOutputs(
        anf,
        input.methodName,
        input.currentState,
        input.args,
        input.constructorArgs,
      );
      const actual = normalizeResult(result);

      const expectedPath = join(EXPECTED_DIR, inputFile);
      if (!existsSync(expectedPath)) {
        // Bootstrap mode: first run pins the golden. Subsequent runs assert.
        writeFileSync(expectedPath, JSON.stringify(actual, null, 2) + '\n');
        // Re-read so the assertion below still runs against the freshly written
        // file — this both creates the golden and proves it can round-trip.
      }
      const expected = JSON.parse(readFileSync(expectedPath, 'utf8')) as CaseOutput;
      expect(actual).toEqual(expected);
    });
  }
});
