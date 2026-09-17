import { describe, it, expect } from 'vitest';
import { parse } from '../passes/01-parse.js';
import { validate } from '../passes/02-validate.js';
import type { ValidationResult } from '../passes/02-validate.js';
import type { ContractNode } from '../ir/index.js';

// ---------------------------------------------------------------------------
// H2 (#131): locktime soundness warning.
//
// A method that reads extractLocktime(preimage) only enforces a timelock if
// the covenant ALSO asserts the spending tx is non-final. Without that, a
// hand-built all-final-sequence transaction bypasses the locktime gate,
// because consensus ignores nLockTime when every input is final.
//
// W1 / FinalCountdown rewrote what counts as "that assertion". The original
// diagnostic recommended, in its own message text,
//
//     assert(extractSequence(this.txPreimage) < 0xffffffffn)
//
// and accepted `<=` on the same bound. Both halves were wrong, for two
// different reasons:
//
//   * the RECOMMENDATION was the exploit. Stack lowering decoded nSequence
//     with a bare OP_BIN2NUM, so the sentinel `ffffffff` read as the SCRIPT
//     NUMBER -2147483647, and `< 0xffffffff` was true for exactly the value
//     the guard exists to exclude. The compiler was teaching authors to write
//     a check that admits a final spend. That half is fixed in the lowering
//     (`emitUnsignedBin2Num`), not here.
//
//   * `<= 0xffffffff` is TAUTOLOGICAL, and stays tautological under the fixed
//     unsigned decode: nSequence cannot exceed 0xffffffff, so the comparison
//     is true for every transaction, sentinel included. Accepting it as a
//     finality guard silenced the warning on a contract with no guard at all.
//     That half is fixed here.
//
// What a guard has to do now is exclude 0xffffffff under the UNSIGNED reading:
// `!== 0xffffffffn` (the recommended spelling), or a strict `<` bound, or a
// non-strict bound strictly below the sentinel.
// ---------------------------------------------------------------------------

const WARNING_NEEDLE = 'does not assert extractSequence';

function parseContract(source: string): ContractNode {
  const result = parse(source);
  if (!result.contract) {
    throw new Error(`Parse failed: ${result.errors.map(e => e.message).join(', ')}`);
  }
  return result.contract;
}

function validateSource(source: string): ValidationResult {
  return validate(parseContract(source));
}

function hasLocktimeWarning(result: ValidationResult): boolean {
  return result.warnings.some(w => w.message.includes(WARNING_NEEDLE));
}

/** A stateful timelock whose `unlock` body is `guard` followed by the gate. */
function timelock(guard: string): string {
  return `
      class TimeLock extends StatefulSmartContract {
        count: bigint;
        readonly deadline: bigint;
        constructor(count: bigint, deadline: bigint) {
          super(count, deadline);
          this.count = count;
          this.deadline = deadline;
        }
        public unlock() {
          ${guard}
          assert(extractLocktime(this.txPreimage) >= this.deadline);
          this.count++;
        }
      }
    `;
}

describe('H2 (#131): extractLocktime without extractSequence guard', () => {
  it('warns when a method reads extractLocktime but has no sequence guard', () => {
    const result = validateSource(timelock(''));
    expect(hasLocktimeWarning(result)).toBe(true);
    // The warning names the method and points at the fix.
    const w = result.warnings.find(x => x.message.includes(WARNING_NEEDLE))!;
    expect(w.severity).toBe('warning');
    expect(w.message).toContain('unlock');
    expect(w.message).toContain('0xffffffff');
  });

  it('recommends `!== 0xffffffffn`, never the `< 0xffffffffn` of the old text', () => {
    const result = validateSource(timelock(''));
    const w = result.warnings.find(x => x.message.includes(WARNING_NEEDLE))!;
    // The exact string the compiler used to hand authors, and which the
    // pre-W1 lowering made true for the finality sentinel.
    expect(w.message).not.toContain('< 0xffffffffn');
    expect(w.message).toContain('!== 0xffffffffn');
  });

  // -------------------------------------------------------------------------
  // Guards that genuinely exclude the sentinel
  // -------------------------------------------------------------------------

  it.each([
    ['!==', 'assert(extractSequence(this.txPreimage) !== 0xffffffffn);'],
    ['reversed !==', 'assert(0xffffffffn !== extractSequence(this.txPreimage));'],
    ['strict <', 'assert(extractSequence(this.txPreimage) < 0xffffffffn);'],
    ['non-strict <= below the sentinel', 'assert(extractSequence(this.txPreimage) <= 0xfffffffen);'],
    ['reversed strict >', 'assert(0xffffffffn > extractSequence(this.txPreimage));'],
    ['reversed non-strict >= below the sentinel', 'assert(0xfffffffen >= extractSequence(this.txPreimage));'],
  ])('does NOT warn for a real guard: %s', (_label, guard) => {
    expect(hasLocktimeWarning(validateSource(timelock(guard)))).toBe(false);
  });

  // -------------------------------------------------------------------------
  // Comparisons that are true for EVERY transaction, sentinel included
  // -------------------------------------------------------------------------

  it.each([
    ['<= the sentinel', 'assert(extractSequence(this.txPreimage) <= 0xffffffffn);'],
    ['reversed >= the sentinel', 'assert(0xffffffffn >= extractSequence(this.txPreimage));'],
  ])('STILL warns for a tautology: %s', (_label, guard) => {
    expect(hasLocktimeWarning(validateSource(timelock(guard)))).toBe(true);
  });

  it('STILL warns for a `!==` against something other than the sentinel', () => {
    // `!== 0n` excludes a value no consensus rule cares about and leaves the
    // final spend wide open.
    const guard = 'assert(extractSequence(this.txPreimage) !== 0n);';
    expect(hasLocktimeWarning(validateSource(timelock(guard)))).toBe(true);
  });

  // -------------------------------------------------------------------------
  // Comparisons that do not enforce anything
  // -------------------------------------------------------------------------

  it('STILL warns when the comparison is assigned, not asserted', () => {
    // A comparison that is never asserted does not enforce anything.
    // `let ok = extractSequence !== 0xffffffffn` used to silence the warning.
    const guard = 'const ok: boolean = extractSequence(this.txPreimage) !== 0xffffffffn;';
    expect(hasLocktimeWarning(validateSource(timelock(guard)))).toBe(true);
  });

  it('STILL warns for a vacuous strict bound (extractSequence < 0n)', () => {
    // Unsigned nSequence is never negative, so `< 0n` is not a finality guard.
    // strictBoundOk used to admit any literal <= 2^32-1.
    const guard = 'assert(extractSequence(this.txPreimage) < 0n);';
    expect(hasLocktimeWarning(validateSource(timelock(guard)))).toBe(true);
  });

  it('does NOT warn for a method that never reads extractLocktime', () => {
    const source = `
      class Counter extends StatefulSmartContract {
        count: bigint;
        constructor(count: bigint) {
          super(count);
          this.count = count;
        }
        public increment() {
          this.count++;
        }
      }
    `;
    const result = validateSource(source);
    expect(hasLocktimeWarning(result)).toBe(false);
  });

  it('sees a sequence guard supplied transitively through a private helper', () => {
    const source = `
      class TimeLock extends StatefulSmartContract {
        count: bigint;
        readonly deadline: bigint;
        constructor(count: bigint, deadline: bigint) {
          super(count, deadline);
          this.count = count;
          this.deadline = deadline;
        }
        private requireNonFinal() {
          assert(extractSequence(this.txPreimage) !== 0xffffffffn);
        }
        public unlock() {
          this.requireNonFinal();
          assert(extractLocktime(this.txPreimage) >= this.deadline);
          this.count++;
        }
      }
    `;
    const result = validateSource(source);
    expect(hasLocktimeWarning(result)).toBe(false);
  });

  it('warns when a private helper supplies only the TAUTOLOGY', () => {
    const source = `
      class TimeLock extends StatefulSmartContract {
        count: bigint;
        readonly deadline: bigint;
        constructor(count: bigint, deadline: bigint) {
          super(count, deadline);
          this.count = count;
          this.deadline = deadline;
        }
        private requireNonFinal() {
          assert(extractSequence(this.txPreimage) <= 0xffffffffn);
        }
        public unlock() {
          this.requireNonFinal();
          assert(extractLocktime(this.txPreimage) >= this.deadline);
          this.count++;
        }
      }
    `;
    const result = validateSource(source);
    expect(hasLocktimeWarning(result)).toBe(true);
  });

  it('warns when the locktime read is in a private helper but no sequence guard exists', () => {
    const source = `
      class TimeLock extends StatefulSmartContract {
        count: bigint;
        readonly deadline: bigint;
        constructor(count: bigint, deadline: bigint) {
          super(count, deadline);
          this.count = count;
          this.deadline = deadline;
        }
        private checkDeadline() {
          assert(extractLocktime(this.txPreimage) >= this.deadline);
        }
        public unlock() {
          this.checkDeadline();
          this.count++;
        }
      }
    `;
    const result = validateSource(source);
    expect(hasLocktimeWarning(result)).toBe(true);
  });
});
