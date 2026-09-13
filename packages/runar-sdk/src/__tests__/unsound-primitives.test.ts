import { describe, it, expect } from 'vitest';
import { assertUnsoundPrimitivesAcknowledged } from '../unsound-primitives.js';
import type { RunarArtifact } from 'runar-ir-schema';

/**
 * R-062 / CL-BUG-105 — the acknowledged SP1 FRI path reaches a value-bearing
 * deployment with no friction.
 *
 * R-012 made the COMPILER refuse `verifySP1FRI` unless the author wrote
 * `@acknowledgeUnsoundSP1FriVerifier` or the invoker passed
 * `--acknowledge-unsound-sp1-fri`. The acknowledgement stopped there. The
 * reviewer enumerated the artifact's keys and found nothing recording the gap,
 * and `grep -rln "acknowledgeUnsound|unsoundSP1|UnsoundSP1" packages/` matched
 * in none of the seven SDKs — so whoever was handed the artifact afterwards saw
 * an ordinary contract and every SDK funded it silently.
 *
 * The compiler now stamps `unsoundPrimitives` into the artifact, and this guard
 * is what every deploy path calls before any signing or broadcast.
 */

const artifact = (unsound?: string[]): RunarArtifact =>
  ({
    version: 'runar-v1.0.0-rc.1',
    compilerVersion: '1.0.0-rc.1-go',
    contractName: 'Sp1Rollup',
    abi: { constructor: { params: [] }, methods: [] },
    script: '51',
    asm: 'OP_1',
    buildTimestamp: '2026-09-13T00:00:00Z',
    ...(unsound ? { unsoundPrimitives: unsound } : {}),
  }) as RunarArtifact;

describe('R-062 unsound-primitive deploy guard', () => {
  it('does nothing for an ordinary artifact, acknowledged or not', () => {
    expect(() => assertUnsoundPrimitivesAcknowledged(artifact(), undefined, 'deploy')).not.toThrow();
    expect(() => assertUnsoundPrimitivesAcknowledged(artifact(), [], 'deploy')).not.toThrow();
    expect(() =>
      assertUnsoundPrimitivesAcknowledged(artifact(), ['verifySP1FRI'], 'deploy'),
    ).not.toThrow();
    // An empty list is the same as none — a marker that says "nothing unsound".
    expect(() => assertUnsoundPrimitivesAcknowledged(artifact([]), undefined, 'deploy')).not.toThrow();
  });

  it('refuses an unsound artifact when the caller acknowledged nothing', () => {
    expect(() => assertUnsoundPrimitivesAcknowledged(artifact(['verifySP1FRI']), undefined, 'Sp1Rollup.deploy'))
      .toThrow(/verifySP1FRI/);
    expect(() => assertUnsoundPrimitivesAcknowledged(artifact(['verifySP1FRI']), [], 'Sp1Rollup.deploy'))
      .toThrow(/acknowledgeUnsound/);
  });

  it('names the contract and the call site in the error', () => {
    let message = '';
    try {
      assertUnsoundPrimitivesAcknowledged(artifact(['verifySP1FRI']), undefined, 'Sp1Rollup.deploy');
    } catch (e) {
      message = (e as Error).message;
    }
    expect(message).toContain('Sp1Rollup.deploy');
    expect(message).toContain('verifySP1FRI');
  });

  it('accepts when every listed primitive is acknowledged', () => {
    expect(() =>
      assertUnsoundPrimitivesAcknowledged(artifact(['verifySP1FRI']), ['verifySP1FRI'], 'deploy'),
    ).not.toThrow();
  });

  it('refuses a PARTIAL acknowledgement — every primitive must be named', () => {
    expect(() =>
      assertUnsoundPrimitivesAcknowledged(
        artifact(['verifySP1FRI', 'someFutureStub']),
        ['verifySP1FRI'],
        'deploy',
      ),
    ).toThrow(/someFutureStub/);
  });

  it('does not accept a blanket acknowledgement of something else', () => {
    expect(() =>
      assertUnsoundPrimitivesAcknowledged(artifact(['verifySP1FRI']), ['somethingElse'], 'deploy'),
    ).toThrow(/verifySP1FRI/);
  });
});
