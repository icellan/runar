import { describe, it, expect, beforeAll } from 'vitest';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildSourceTiers, compileHex, judge } from './tier-harness.js';
import { isCiEnv } from '../env.js';

/**
 * N-469 — the Zig Rabin public-key provenance check on the `self` receiver.
 *
 * The .runar.zig parser keeps a method call's receiver as `self`
 * (`self.check(self.pk, n, ...)`), but the Zig provenance collector only
 * matched `this`, so it never saw the call site of a private helper and could
 * not trust the helper's parameter bound to `self.pk`: Zig refused a contract
 * the other six tiers accept (an over-refusal).
 *
 * Making the collector see `self` calls exposes a second hazard. A helper may
 * declare a StatefulContext handle that the call site omits (every tier elides
 * the handle, N-304/N-453), so pairing helper parameters with call arguments by
 * position must skip the handle on both sides; otherwise a literal passed in the
 * pubkey position lands on the wrong parameter (fail-open).
 *
 * What this proves:
 *   - a private helper whose verifyRabinSig key parameter is bound to `self.pk`
 *     at its only call site compiles in all seven tiers to identical bytes,
 *     with the handle declared-and-omitted, declared-and-passed, and absent;
 *   - the same shapes with a LITERAL in the other (unused) key slot still
 *     compile, and one with a spender-supplied parameter bound to the key
 *     parameter is refused by every tier with the F-286 diagnostic, including
 *     when the call omits a handle the helper declares (the shifted pairing).
 * What it does NOT prove: surfaces other than .runar.zig, calls that reach the
 *   helper through a bare (non-`self`) callee, or on-chain behaviour.
 */

const TIERS = buildSourceTiers().filter((t) => t.cmd !== null);

const HEAD = (name: string) => `const runar = @import("runar");

pub const ${name} = struct {
    pub const Contract = runar.StatefulSmartContract;

    pk: runar.RabinPubKey,
    count: i64 = 0,

    pub fn init(pk: runar.RabinPubKey) ${name} {
        return .{ .pk = pk };
    }
`;

/** helperCtx: whether `check` declares a ctx; callArgs: the call's first args. */
function contract(name: string, helperCtx: boolean, settleCtx: boolean, callArgs: string): string {
  const hc = helperCtx ? 'ctx: runar.StatefulContext, ' : '';
  const sc = settleCtx ? 'ctx: runar.StatefulContext, ' : '';
  return `${HEAD(name)}
    fn check(self: *${name}, ${hc}a: runar.RabinPubKey, b: runar.RabinPubKey, msg: runar.ByteString, sig: runar.RabinSig, padding: runar.ByteString) void {
        _ = b;
        runar.assert(runar.verifyRabinSig(msg, sig, padding, a));
    }

    pub fn settle(self: *${name}, ${sc}n: runar.RabinPubKey, msg: runar.ByteString, sig: runar.RabinSig, padding: runar.ByteString) void {
        self.check(${callArgs}, msg, sig, padding);
        self.count = self.count + 1;
    }
};
`;
}

const ACCEPTED: Array<[string, string]> = [
  ['plain helper bound to self.pk', contract('RabinPosPlain', false, false, 'self.pk, n')],
  ['ctx declared and omitted at the call', contract('RabinPosNoCtx', true, true, 'self.pk, n')],
  ['ctx declared and passed at the call', contract('RabinPosCtx', true, true, 'ctx, self.pk, n')],
];

const REFUSED: Array<[string, string]> = [
  // `a` (the verified key) is the spender's `n`; the literal sits in the unused slot.
  ['ctx declared, omitted, spender key in the key slot, literal in the other', contract('RabinNegLit', true, true, 'n, 7')],
  ['plain helper with the spender key in the key slot', contract('RabinNeg', false, false, 'n, self.pk')],
];

let dir = '';
beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), 'n469-zig-rabin-self-'));
});
let seq = 0;
function write(name: string, src: string): string {
  const sub = join(dir, String(seq++));
  mkdirSync(sub, { recursive: true });
  const p = join(sub, `${name}.runar.zig`);
  writeFileSync(p, src);
  return p;
}

describe('N-469 Rabin key provenance through self.helper() calls (.runar.zig) — seven-tier parity', () => {
  it('at least two tiers are available (all seven in CI)', () => {
    expect(TIERS.length).toBeGreaterThanOrEqual(2);
    if (isCiEnv(process.env)) expect(TIERS.length).toBe(7);
  });

  for (const [name, src] of ACCEPTED) {
    it(`every tier compiles ${name} to identical bytes`, () => {
      const cname = /pub const (\w+) =/.exec(src)![1];
      const p = write(cname, src);
      const hexes = TIERS.map((t) => [t.id, compileHex(t, p)] as const);
      const ref = hexes[0][1];
      expect(ref.length).toBeGreaterThan(0);
      for (const [id, hex] of hexes) expect([id, hex]).toEqual([id, ref]);
    });
  }

  for (const [name, src] of REFUSED) {
    for (const tier of TIERS) {
      it(`${tier.id} refuses ${name}`, () => {
        const cname = /pub const (\w+) =/.exec(src)![1];
        const { verdict, diag } = judge(tier, write(cname, src));
        expect(verdict).toBe('rejected');
        expect(diag).toContain('verifyRabinSig public key (4th argument)');
      });
    }
  }
});
