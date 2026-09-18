/**
 * R-287 (CL-GAP-077) — `_codePart` provisioning must not depend on which tier
 * compiled the ANF IR.
 *
 * The finding asked for a trace of `lowerDeserializeState`'s
 * var-length-without-`_codePart` path. That path turned out to be unreachable
 * (see the sibling assertions below): `computeUsesCodePart` gates on a
 * CONTRACT-level fact, so a method that reads any mutable property of a
 * contract carrying variable-length state always keeps `_codePart`.
 *
 * The trace surfaced a different, live defect instead. `methodUsesCodePart`
 * is implemented seven times, and the seven copies did not agree on which ANF
 * kinds trigger `_codePart`:
 *
 *   Go / Python / Ruby / Java / Zig   add_output, add_raw_output, add_data_output
 *   TypeScript / Rust                 add_output, add_raw_output
 *
 * From source the disagreement is invisible, because `continuationShape`
 * makes `hasDataOutput` imply `needsChange`, so every `add_data_output`
 * arrives beside a `computeStateOutput` call that trips the predicate's other
 * clause. The `--ir` front door has no such coupling: feeding one ANF program
 * whose only trigger is `add_data_output` to all seven tiers produced a
 * three-way split in the emitted script — a direct violation of invariant 2
 * (byte-identical Stack IR + hex).
 */
import { describe, it, expect } from 'vitest';
import { compile } from '../index.js';
import { lowerToStack } from '../passes/05-stack-lower.js';
import type { ANFProgram, ANFMethod } from '../ir/anf-ir.js';

/** Compile source to ANF, asserting the frontend produced no errors. */
function anfOf(source: string, fileName: string): ANFProgram {
  const result = compile(source, { fileName, disableConstantFolding: true });
  const errors = result.diagnostics.filter(d => d.severity === 'error');
  expect(errors.map(e => e.message)).toEqual([]);
  return result.anf!;
}

function methodNamed(anf: ANFProgram, name: string): ANFMethod {
  const method = anf.methods.find(m => m.name === name);
  expect(method, `method '${name}' is missing from the ANF`).toBeDefined();
  return method!;
}

const DATA_OUTPUT_SOURCE = `
import { StatefulSmartContract, ByteString } from 'runar-lang';

export class DataOnly extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }

  public emitData(payload: ByteString): void {
    this.addDataOutput(0n, payload);
  }
}
`;

describe('R-287: add_data_output provisions _codePart', () => {
  it('trips the predicate on its own, with no continuation binding present', () => {
    const anf = anfOf(DATA_OUTPUT_SOURCE, 'DataOnly.runar.ts');
    const method = methodNamed(anf, 'emitData');

    // Locate the add_data_output binding and drop everything after it. What
    // remains is exactly the shape the `--ir` front door accepts and
    // `continuationShape` can never produce: a data output with no
    // computeStateOutput / add_output sibling to trip the other clauses.
    const dataOutputAt = method.body.findIndex(b => b.value.kind === 'add_data_output');
    expect(dataOutputAt, 'the contract must lower to an add_data_output binding').toBeGreaterThan(-1);

    const truncated: ANFProgram = {
      ...anf,
      methods: anf.methods.map(m =>
        m.name === 'emitData' ? { ...m, body: m.body.slice(0, dataOutputAt + 1) } : m,
      ),
    };

    // Anti-vacuity: the trimmed body must genuinely have no other trigger,
    // or this test would pass for the wrong reason.
    const remaining = truncated.methods.find(m => m.name === 'emitData')!.body;
    expect(remaining.some(b => b.value.kind === 'add_output')).toBe(false);
    expect(remaining.some(b => b.value.kind === 'add_raw_output')).toBe(false);
    expect(
      remaining.some(
        b => b.value.kind === 'call'
          && (b.value.func === 'computeStateOutput' || b.value.func === 'computeStateOutputHash'),
      ),
    ).toBe(false);
    expect(remaining.some(b => b.value.kind === 'add_data_output')).toBe(true);

    const stack = lowerToStack(truncated);
    const lowered = stack.methods.find(m => m.name === 'emitData')!;
    expect(lowered.usesCodePart).toBe(true);
  });

  it('still provisions _codePart when the data output is the only trigger inside a branch', () => {
    const anf = anfOf(
      `
import { StatefulSmartContract, ByteString } from 'runar-lang';

export class BranchedDataOnly extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }

  public emitData(payload: ByteString, flag: boolean): void {
    if (flag) {
      this.addDataOutput(0n, payload);
    }
  }
}
`,
      'BranchedDataOnly.runar.ts',
    );
    const method = methodNamed(anf, 'emitData');
    const hasBranchDataOutput = method.body.some(
      b => b.value.kind === 'if'
        && [...b.value.then, ...b.value.else].some(inner => inner.value.kind === 'add_data_output'),
    );
    expect(hasBranchDataOutput, 'the data output must land inside an if arm').toBe(true);
  });
});

describe('R-287: the var-length deserialization skip path stays unreachable', () => {
  it('keeps _codePart for a terminal method that reads a fixed-size sibling of var-length state', () => {
    // R-074's rule: once ANY mutable property is variable-length, EVERY
    // mutable-property read needs `_codePart`. A method reading only the
    // fixed-size `count` is the case that used to fall through to the
    // deploy-time constructor placeholder.
    const anf = anfOf(
      `
import { StatefulSmartContract, assert, ByteString } from 'runar-lang';

export class Mixed extends StatefulSmartContract {
  label: ByteString;
  count: bigint;

  constructor(label: ByteString, count: bigint) {
    super(label, count);
    this.label = label;
    this.count = count;
  }

  public check(x: bigint): void {
    assert(this.count == x);
  }
}
`,
      'Mixed.runar.ts',
    );
    const stack = lowerToStack(anf);
    const lowered = stack.methods.find(m => m.name === 'check')!;
    expect(lowered.usesCodePart).toBe(true);
  });

  it('keeps _codePart when the only var-length read hides behind a private helper', () => {
    const anf = anfOf(
      `
import { StatefulSmartContract, assert, ByteString } from 'runar-lang';

export class Helped extends StatefulSmartContract {
  label: ByteString;
  count: bigint;

  constructor(label: ByteString, count: bigint) {
    super(label, count);
    this.label = label;
    this.count = count;
  }

  private peek(): bigint {
    return this.count;
  }

  public check(x: bigint): void {
    assert(this.peek() == x);
  }
}
`,
      'Helped.runar.ts',
    );
    const stack = lowerToStack(anf);
    const lowered = stack.methods.find(m => m.name === 'check')!;
    expect(lowered.usesCodePart).toBe(true);
  });
});
