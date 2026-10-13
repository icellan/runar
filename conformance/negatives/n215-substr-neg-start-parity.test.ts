import { describe, it, expect } from 'vitest';
import { join } from 'node:path';
import { buildSourceTiers, judge, ALL_TIER_IDS } from './tier-harness.js';
import { isCiEnv } from '../anf-interpreter/driver-gate.js';

/**
 * N-215 -- substr() literal negative start, seven-tier SHARED-DIAGNOSTIC
 * parity (F-265).
 *
 * `rejection-parity.test.ts` already proves every tier REFUSES
 * `N215-substr-negative-start.runar.ts` (accept/reject only). That is not
 * the whole claim F-265 closes: before the fix, TS, Go, Python, Zig, Ruby
 * and Java all COMPILED `substr(a, -5n, 3n)` to the identical byte-for-byte
 * hex `0055018553537a7b7f777c7f75008777` -- a script that aborts at runtime
 * (`-5n` minimal-encodes to `<85>`, which OP_SPLIT rejects) -- and only Rust
 * refused it, with its own wording. The fix ported ONE shared compile-time
 * diagnostic to all seven typecheckers. A bare accept/reject gate cannot
 * see wording drift back apart later; this test pins the shared substring.
 *
 * What this proves: every available tier's verdict is 'rejected' for this
 * fixture AND its diagnostic contains the exact shared message
 * "substr() argument 2 (start) must be >= 0; got -5" -- i.e. the rejection
 * comes from the SAME typecheck-time bound, not seven different runtime
 * crashes that happen to also exit non-zero.
 * What it does NOT prove: anything about a non-literal negative start (out
 * of scope -- no static value to check), or the companion F-265 defect
 * (ByteString property-initializer hex validation, N-216), which Go,
 * Python, Zig, Ruby and Java still catch late in stack lowering with
 * tier-specific wording -- deliberately not asserted here; see
 * `02-validate.test.ts` / `validator.rs` for the TS+Rust-only fix there.
 */

const FIXTURE = join(__dirname, 'N215-substr-negative-start.runar.ts');
const WANT = 'substr() argument 2 (start) must be >= 0; got -5';

const TIERS = buildSourceTiers();
const AVAILABLE = TIERS.filter((t) => t.cmd !== null);

describe('N-215 substr() negative-start -- seven-tier shared-diagnostic parity', () => {
  it('the matrix names all seven tiers (a silently dropped tier fails here)', () => {
    expect([...TIERS.map((t) => t.id)].sort()).toEqual([...ALL_TIER_IDS]);
  });

  it('at least two tiers are available (all seven in CI)', () => {
    expect(AVAILABLE.length).toBeGreaterThanOrEqual(2);
    if (isCiEnv(process.env)) expect(AVAILABLE.length).toBe(7);
  });

  for (const tier of AVAILABLE) {
    it(`${tier.id} rejects with the shared "argument 2 (start) must be >= 0" diagnostic`, () => {
      const { verdict, diag } = judge(tier, FIXTURE);
      expect(verdict).toBe('rejected');
      expect(diag).toContain(WANT);
    });
  }
});
