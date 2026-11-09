/**
 * OP_PUSHDATA4 lengths are unsigned 32-bit values. Two readers still built the
 * length with a signed `b3 << 24` (the class fe213bd4 (from #125) and N-317
 * (68197d977) fixed elsewhere), so any length >= 0x80000000 came out negative:
 *
 *  - ordinals/envelope.ts — `opcodeSize` made `findInscriptionEnvelope` step by
 *    zero or backwards and never return; `readPushData` stepped back inside a
 *    candidate envelope and could report bounds for bytes that are not one;
 *  - state.ts `decodePushData` — the cursor moved backwards, so
 *    `deserializeState` could return field values for a state section that the
 *    contract's own on-chain reader rejects.
 *
 * The envelope cases run one per child process
 * (pushdata4-unsigned-length-replay.mts): before the fix the walk never
 * returned, and a synchronous loop cannot be timed out in-process.
 *
 * Proves: a high-bit OP_PUSHDATA4 length reads as a push past the end of the
 * script at all three sites — the envelope walk terminates with no envelope
 * (also through `stripInscriptionEnvelope` and `RunarContract.fromUtxo`), and
 * `deserializeState` rejects the state section; a well-formed OP_PUSHDATA4
 * still decodes.
 * Does NOT prove: anything about OP_PUSHDATA1/2 (they cannot overflow); the
 * other SDK tiers; scripts of 2 GiB or more (a genuine push that large is
 * never built here).
 */
import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { StateField } from 'runar-ir-schema';
import { deserializeState, serializeState } from '../state.js';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, '../../../..');
const WALL_CAP_MS = 15_000;

function replay(name: string): { error?: Error; status: number | null; stderr: string; out?: Record<string, unknown> } {
  const child = spawnSync(
    process.execPath,
    [resolve(repoRoot, 'node_modules/tsx/dist/cli.mjs'), resolve(here, 'pushdata4-unsigned-length-replay.mts'), name],
    { encoding: 'utf8', timeout: WALL_CAP_MS },
  );
  return {
    error: child.error,
    status: child.status,
    stderr: child.stderr,
    out: child.status === 0 ? JSON.parse(child.stdout) as Record<string, unknown> : undefined,
  };
}

function expectTerminated(r: ReturnType<typeof replay>): void {
  expect(r.error, `killed after ${WALL_CAP_MS} ms (hang)`).toBeUndefined();
  expect(r.status, r.stderr).toBe(0);
}

describe('findInscriptionEnvelope: OP_PUSHDATA4 length is unsigned', () => {
  // Each name is a script in pushdata4-unsigned-length-replay.mts.
  it.each([
    ['zero step', '4efbffffff'],
    ['backward step', '51514ef8ffffff'],
    ['content-type push', '0001aa68' + '0063036f726451' + '4ef0ffffff'],
    ['content push', '0063036f7264' + '51' + '0168' + '00' + '4ef9ffffff'],
  ])('%s: a high-bit length reads as a push past the end, so no envelope is found', (name, hex) => {
    const r = replay(name);
    expectTerminated(r);
    expect(r.out?.found).toBeNull();
    expect(r.out?.stripped).toBe(hex);
  }, WALL_CAP_MS + 5_000);

  it('control: a well-formed OP_PUSHDATA4 before an envelope is still skipped', () => {
    const r = replay('valid pushdata4 then envelope');
    expectTerminated(r);
    // 6-byte push, then the 26-byte "text/plain" / "hello" envelope
    expect(r.out?.found).toEqual({ startHex: 12, endHex: 64 });
    expect(r.out?.stripped).toBe('4e01000000aa');
  }, WALL_CAP_MS + 5_000);

  it('RunarContract.fromUtxo returns, with no inscription, for a script ending in a high-bit length', () => {
    const r = replay('fromUtxo');
    expectTerminated(r);
    expect(r.out).toEqual({ inscription: null });
  }, WALL_CAP_MS + 5_000);
});

describe('deserializeState: OP_PUSHDATA4 length is unsigned', () => {
  const fields: StateField[] = [
    { name: 'a', type: 'ByteString', index: 0 },
    { name: 'b', type: 'ByteString', index: 1 },
  ];

  it('control: the honest encoding round-trips', () => {
    expect(serializeState(fields, { a: '', b: 'aabb' })).toBe('0002aabb');
    expect(deserializeState(fields, '0002aabb')).toEqual({ a: '', b: 'aabb' });
  });

  it('rejects a high-bit length instead of moving the cursor backwards', () => {
    // length 0xfffffff8; the signed read decoded this as { a: '', b: 'aabb' }
    expect(() => deserializeState(fields, '4ef8ffffff0aaabb')).toThrow(/truncated.*OP_PUSHDATA4 payload/);
  });

  it('rejects a lone 0x80000000 length as truncated', () => {
    expect(() => deserializeState(fields.slice(0, 1), '4e00000080')).toThrow(/truncated.*OP_PUSHDATA4 payload/);
  });
});
