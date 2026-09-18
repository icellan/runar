// INTERPRETER-ONLY: spendability covered by conformance/witnesses/real-crypto/state-covenant-mechanics.json
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { TestContract } from 'runar-testing';

/**
 * R-192 — the covenant mechanics, split out from the Go-only allowlist.
 *
 * `state-covenant` is exempt from cross-tier parity because of two Go-only
 * builtins, and the exemption is fixture-wide — it covered the state
 * continuation, the OP_CODESEPARATOR handling and the output construction as
 * well. This contract is the same covenant with those two calls removed, so
 * those mechanics get checked in all seven tiers.
 *
 * The byte parity lives in the conformance fixture and the post-spend state in
 * the real-crypto witness. What this adds is the source-semantics reading of
 * the three guards, including the two that must REJECT.
 */
const __dirname = dirname(fileURLToPath(import.meta.url));
const FILE = 'StateCovenantMechanics.runar.ts';
const source = readFileSync(join(__dirname, FILE), 'utf8');

const hash256 = (b: Uint8Array) =>
  new Uint8Array(createHash('sha256').update(createHash('sha256').update(b).digest()).digest());
const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');
/** `c.state` hands a ByteString back as a hex STRING, not bytes. */
const stateHex = (v: unknown) =>
  v instanceof Uint8Array ? Buffer.from(v).toString('hex') : String(v);
const bytes = (h: string) => Uint8Array.from(Buffer.from(h, 'hex'));

const PRE = '00'.repeat(32);
const NEXT = '22'.repeat(32);
const VKH = '11'.repeat(32);
const BATCH = hex(hash256(bytes(PRE + NEXT)));

function contract() {
  return TestContract.fromSource(
    source,
    { stateRoot: PRE, blockNumber: 5n, verifyingKeyHash: VKH },
    FILE,
  );
}

describe('StateCovenantMechanics (the covenant, minus the Go-only builtins)', () => {
  it('advances the state when every guard holds', () => {
    const c = contract();
    const r = c.call('advanceState', {
      newStateRoot: bytes(NEXT),
      newBlockNumber: 6n,
      batchDataHash: bytes(BATCH),
      preStateRoot: bytes(PRE),
    });
    expect(r.success, r.error).toBe(true);
    expect(stateHex(c.state.stateRoot)).toBe(NEXT);
    expect(c.state.blockNumber).toBe(6n);
  });

  it('REJECTS a block number that does not strictly increase', () => {
    const c = contract();
    expect(
      c.call('advanceState', {
        newStateRoot: bytes(NEXT),
        newBlockNumber: 5n,
        batchDataHash: bytes(BATCH),
        preStateRoot: bytes(PRE),
      }).success,
      'a covenant that lets the block number stand still can be replayed',
    ).toBe(false);
  });

  it('REJECTS a pre-state root that does not match the current state', () => {
    const c = contract();
    const wrongPre = '99'.repeat(32);
    expect(
      c.call('advanceState', {
        newStateRoot: bytes(NEXT),
        newBlockNumber: 6n,
        batchDataHash: bytes(hex(hash256(bytes(wrongPre + NEXT)))),
        preStateRoot: bytes(wrongPre),
      }).success,
      'the chain link is the pre-state check; without it any state can follow any other',
    ).toBe(false);
  });

  it('REJECTS a batch hash that does not bind hash256(pre || new)', () => {
    const c = contract();
    expect(
      c.call('advanceState', {
        newStateRoot: bytes(NEXT),
        newBlockNumber: 6n,
        batchDataHash: bytes('33'.repeat(32)),
        preStateRoot: bytes(PRE),
      }).success,
    ).toBe(false);
  });

  it('a rejected advance leaves the state untouched', () => {
    const c = contract();
    c.call('advanceState', {
      newStateRoot: bytes(NEXT),
      newBlockNumber: 5n,
      batchDataHash: bytes(BATCH),
      preStateRoot: bytes(PRE),
    });
    expect(stateHex(c.state.stateRoot)).toBe(PRE);
    expect(c.state.blockNumber).toBe(5n);
  });
});
