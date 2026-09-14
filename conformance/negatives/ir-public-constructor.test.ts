import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { ScriptVM } from '../../packages/runar-testing/src/vm/script-vm.js';
import { BrokenTier, IR_TIER_IDS, REPO, Tier, buildIrTiers, verdict } from './tier-harness.js';

/**
 * N-113 — the `--ir` no-public-methods guard counted the CONSTRUCTOR.
 *
 * ---------------------------------------------------------------------------
 * Why this file is separate from `ir-rejection-parity.test.ts`
 * ---------------------------------------------------------------------------
 *
 * That file grades a VERDICT: non-zero exit, real diagnostic, not a usage or
 * launcher error. It is the right gate for the corpus at large, and
 * `I15-public-constructor-only.ir.json` is driven over it like every other
 * fixture there.
 *
 * It is not a sufficient gate for THIS defect, for the reason R-100 exists:
 * `rc != 0` passes for whatever reason happens to fire. While reproducing this
 * bug the first measurement run scored all six tiers "rejects" — from a
 * mistyped input path. Six clean non-zero exits, six real diagnostics, and not
 * one of them had read the fixture. A test that could be satisfied that way is
 * not a test of an anyone-can-spend hole.
 *
 * So this file asserts the CONSEQUENCE instead, and asserts it by execution:
 * whatever a tier prints for this IR must not be a locking script that spends
 * with no key. The refusal is checked too, second, because a rejection is the
 * only acceptable way to satisfy the first assertion — but the first one is
 * what the defect was about, and it is the one that reddens first.
 *
 * ---------------------------------------------------------------------------
 * The defect
 * ---------------------------------------------------------------------------
 *
 * Every tier's IR loader guarded "this contract has at least one public
 * method" by scanning the ANF `methods` array. The source-path validator that
 * guard was written to mirror scans the AST's method list — where the
 * constructor lives in a SEPARATE field (`ContractNode.Constructor` in Go, and
 * the same shape in the other five) and is therefore NOT in the list being
 * scanned. ANF lowering flattens the constructor INTO `methods`. Same loop,
 * differently-shaped collection: one `isPublic: true` on the constructor
 * satisfied the loader while leaving the contract with no spending entry point
 * at all.
 *
 * Downstream nothing catches it, because everything downstream filters by NAME
 * rather than by `isPublic` (`emit.go` skips `m.Name != "constructor"`, stack
 * lowering skips the constructor and every private method). So zero methods
 * reached the emitter and it returned a locking script of `""`. Measured
 * before the fix, on this exact fixture:
 *
 *     go, rust, python, ruby, java   exit 0, script ""
 *     zig                            exit 0, script "51"
 *
 * Go additionally wrote a well-formed artifact — `{"contractName":"Anyone",
 * ..., "script":""}` — which an SDK would deploy without complaint.
 *
 * Both of those scripts are spendable by anybody: see the oracle self-test
 * below, which executes them on the real `@bsv/sdk` engine rather than
 * asserting it in prose.
 *
 * ---------------------------------------------------------------------------
 * The fixture
 * ---------------------------------------------------------------------------
 *
 * `I15-public-constructor-only.ir.json` is the checked-in `asm-raw-script`
 * golden with the `isPublic` flag MOVED from `unlock` to `constructor`. The
 * contract still declares exactly one public method by the old guard's
 * arithmetic; it just isn't one that can ever be spent through. Keeping it
 * derived from a golden every tier is separately observed ACCEPTING (the
 * control below) is what stops a tier that refuses everything from scoring
 * here.
 */

const FIXTURE = join(__dirname, 'ir/I15-public-constructor-only.ir.json');

/** The golden `FIXTURE` is one flag-move away from. Every tier must accept it. */
const CONTROL = join(REPO, 'conformance/tests/asm-raw-script/expected-ir.json');

const TIERS: Tier[] = buildIrTiers();
const available = TIERS.filter((t) => t.cmd !== null);

const hexToBytes = (hex: string): Uint8Array =>
  new Uint8Array((hex.match(/../g) ?? []).map((b) => parseInt(b, 16)));

/**
 * Keyless, push-only unlocking scripts. An attacker spending a contract they
 * hold no key for gets to choose the witness, so "is this anyone-can-spend"
 * means "does ANY witness a stranger could write satisfy it".
 *
 * These four are the whole search space needed for the shapes at issue: an
 * empty locking script needs the witness to leave something truthy behind
 * (`OP_1`), and a locking script that is itself `OP_1` needs no witness at
 * all. They are all push-only, so they survive the consensus rule that
 * unlocking scripts may not contain operations.
 */
const KEYLESS_WITNESSES = ['', '51', '0051', '5151'];

/**
 * Does `scriptHex` spend without a key? Answered by EXECUTION on the same
 * `@bsv/sdk` engine the rest of the repo verifies against — not by pattern
 * matching, which would have to be kept in sync with every shape a broken
 * emitter might produce.
 */
function anyoneCanSpend(scriptHex: string): boolean {
  const vm = new ScriptVM();
  const locking = hexToBytes(scriptHex);
  for (const witness of KEYLESS_WITNESSES) {
    try {
      if (vm.execute(hexToBytes(witness), locking).success) return true;
    } catch {
      // An engine error is a failed spend, not a successful one.
    }
  }
  return false;
}

/** Run a tier's `--ir` CLI and report what it did, with no interpretation. */
function runIr(tier: Tier, input: string): { status: number | null; stdout: string } {
  if (tier.cmd === null) throw new BrokenTier(`${tier.id}: no toolchain`);
  const argv = [...tier.prefix, ...tier.argsFor(input)];
  const res = spawnSync(tier.cmd, argv, {
    cwd: tier.cwd,
    encoding: 'utf-8',
    timeout: tier.timeoutMs,
    maxBuffer: 64 * 1024 * 1024,
  });
  const where = `${tier.id} (${tier.cmd} ${argv.join(' ')})`;
  if (res.error) throw new BrokenTier(`${where} could not run: ${res.error.message}`);
  if (res.signal !== null) throw new BrokenTier(`${where} killed by ${res.signal}`);
  return { status: res.status, stdout: (res.stdout ?? '').trim() };
}

describe('N-113: a public constructor is not a spending entry point (--ir path)', () => {
  // -- the oracle's own contract -------------------------------------------
  //
  // `anyoneCanSpend` is the assertion every tier row below rests on. An oracle
  // that answered `false` for everything would turn this whole file green, so
  // it is pinned in both directions first: it must SEE the two scripts the
  // broken tiers actually emitted, and it must NOT flag a script that needs a
  // signature.

  it('the oracle sees an EMPTY locking script as anyone-can-spend', () => {
    // What go/rust/python/ruby/java emitted, exit 0, before the fix.
    expect(anyoneCanSpend('')).toBe(true);
  });

  it('the oracle sees a bare OP_1 locking script as anyone-can-spend', () => {
    // What zig emitted, exit 0, before the fix.
    expect(anyoneCanSpend('51')).toBe(true);
  });

  it('the oracle does NOT flag a script that requires a signature', () => {
    // P2PKH. If this were `true` the oracle would be a rubber stamp.
    expect(anyoneCanSpend(`76a914${'00'.repeat(20)}88ac`)).toBe(false);
  });

  // -- vacuity guards -------------------------------------------------------

  it('the fixture and its control are both on disk', () => {
    expect(existsSync(FIXTURE), 'the N-113 fixture is missing').toBe(true);
    expect(existsSync(CONTROL), 'the asm-raw-script control golden is missing').toBe(true);
  });

  it('the matrix names all six IR-capable tiers', () => {
    expect([...TIERS.map((t) => t.id)].sort()).toEqual([...IR_TIER_IDS].sort());
  });

  it('every IR-capable tier is built (strict in CI, ">=2" locally)', () => {
    const missing = TIERS.filter((t) => t.cmd === null).map((t) => t.id);
    if (process.env.CI === 'true') {
      expect(missing, `CI=true but these tiers have no toolchain: ${missing.join(', ')}`).toEqual(
        [],
      );
    }
    expect(available.length).toBeGreaterThanOrEqual(2);
  });

  // -- the gate -------------------------------------------------------------

  for (const tier of available) {
    it(`${tier.id} ACCEPTS the asm-raw-script control (else its refusal is vacuous)`, () => {
      expect(
        verdict(tier, CONTROL),
        `${tier.id} did not accept valid IR its own peers emit, so its refusal ` +
          `of the fixture proves nothing about the guard.`,
      ).toBe('accepted');
    });

    it(`${tier.id} emits no anyone-can-spend script for a public-constructor-only contract`, () => {
      const { status, stdout } = runIr(tier, FIXTURE);

      // THE assertion. `--hex` mode prints the locking script and nothing
      // else, so any hex on stdout is a script this tier was willing to hand
      // an SDK to deploy. A tier that refused printed nothing, and the empty
      // string is not a script it emitted — which is why this is guarded on
      // `status === 0` rather than run unconditionally.
      if (status === 0) {
        expect(
          anyoneCanSpend(stdout),
          `${tier.id} exited 0 for a contract whose ONLY public method is the ` +
            `constructor, and emitted the locking script "${stdout}" — which ` +
            `validates against a keyless push-only witness. Anyone can spend a ` +
            `UTXO locked with it. The constructor is never a spending entry ` +
            `point: it is filtered out by NAME downstream (emit, stack ` +
            `lowering), so this contract has no entry point at all.`,
        ).toBe(false);
      }

      // And the only acceptable way to satisfy the above is a real refusal —
      // a verdict, so a tier that could not start fails loudly instead of
      // scoring a free pass for printing nothing.
      expect(
        verdict(tier, FIXTURE),
        `${tier.id} did not refuse IR whose only public method is the constructor.`,
      ).toBe('rejected');
    });
  }
});
