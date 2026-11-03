import { describe, it, expect } from 'vitest';
import { RunarContract } from '../contract.js';
import type { RunarArtifact } from 'runar-ir-schema';

// N-067 — `new RunarContract` must fail closed, with a clear diagnostic, when
// an artifact's `abi.constructor.params` is not an array.
//
// The Go compiler used to serialize a zero-parameter constructor's ABI as
// `"params": null` (a nil Go slice marshals as JSON `null`, not `[]`) —
// fixed at the source in compilers/go/compiler/compiler.go. That fix means a
// freshly-compiled Go artifact can no longer produce this shape, but the SDK
// still has to deal with artifacts compiled by an older Go binary, or by any
// other non-conforming producer, since `RunarArtifact.abi.constructor.params`
// is a wire-format field the SDK does not otherwise validate on load.
//
// Before this test, `new RunarContract` read
// `artifact.abi.constructor.params.length` unconditionally (contract.ts) and
// crashed with the generic, unactionable `TypeError: Cannot read properties
// of null (reading 'length')`. The SDK already fails closed elsewhere on
// malformed wire input (e.g. state.ts's push-opcode check, contract.ts's own
// constructor-arg-count mismatch a few lines below the crash site) rather
// than silently coercing bad data into a default — so a null `params` gets
// the same treatment: a clear, named `RunarContract` error instead of either
// a crash or a silent `null -> []` normalization that would mask a
// genuinely malformed artifact (e.g. one where params should have had
// entries but a producer bug dropped them to null instead).
//
// What this test proves: `new RunarContract` throws a clear, named error
// (not a raw TypeError) that names the artifact field, for a malformed
// artifact whose constructor.params is null.
// What it does NOT prove: anything about a fresh Go-compiled artifact — the
// Go compiler fix means that path emits `[]` now, so this scenario is only
// reachable via an old/foreign artifact or a hand-crafted one, both covered
// by this synthetic malformed-artifact construction.

function makeArtifact(
  overrides: Partial<RunarArtifact> & Pick<RunarArtifact, 'script' | 'abi'>,
): RunarArtifact {
  return {
    version: 'runar-v0.1.0',
    compilerVersion: '0.1.0',
    contractName: 'Test',
    asm: '',
    buildTimestamp: '2026-03-02T00:00:00.000Z',
    ...overrides,
  };
}

describe('RunarContract — malformed abi.constructor.params', () => {
  it('fails closed with a clear error when params is null, instead of crashing', () => {
    const artifact = makeArtifact({
      script: '51',
      abi: {
        // Simulates a non-conforming producer (e.g. a pre-fix Go artifact).
        constructor: { params: null as unknown as [] },
        methods: [{ name: 'unlock', params: [], isPublic: true }],
      },
    });

    expect(() => new RunarContract(artifact, [])).toThrowError(
      /abi\.constructor\.params/,
    );
  });
});
