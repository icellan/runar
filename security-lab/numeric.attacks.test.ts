import { describe, it, expect } from 'vitest';
import { deployAndCall, validateInput, stateOf, build, asm, firstLine } from './harness.js';

/**
 * Attack surface: the numeric domain of preimage-introspection values and of
 * bigint arithmetic. Bitcoin's nLockTime / nSequence are UNSIGNED uint32; the
 * Script number stack is signed sign-magnitude. A contract that compares a
 * timestamp read out of the preimage against a baked deadline is comparing a
 * SIGNED reading of an unsigned field.
 */

/**
 * D26 refuses to compile a lower-bound compare on `extractLocktime` unless the
 * same path pins the domain, so each gate below states which of the two ranges
 * it lives in. Before that rule existed the same source compiled for both, and a
 * developer who mixed a block height with a Unix timestamp got a gate that
 * consensus simply ignored.
 */
const VAULT_SOURCE = (pin: string) => `
class Vault extends StatefulSmartContract {
  amount: bigint;
  readonly deadline: bigint;
  constructor(amount: bigint, deadline: bigint) {
    super(amount, deadline);
    this.amount = amount;
    this.deadline = deadline;
  }
  public withdraw() {
    assert(extractLocktime(this.txPreimage) >= this.deadline);
    ${pin}
    this.amount = this.amount;
  }
}
`;

/** Timestamp gate — used by the post-2038 cases. */
const VAULT = VAULT_SOURCE('assert(extractLocktime(this.txPreimage) >= 500000000n);');
/** Height gate — used by the pre-2038 control, where a timestamp-domain pin
 *  would wrongly reject an honest block height. */
const HEIGHT_VAULT = VAULT_SOURCE('assert(extractLocktime(this.txPreimage) < 500000000n);');

const VAULT2 = `
class Window extends StatefulSmartContract {
  amount: bigint;
  readonly lo: bigint;
  readonly hi: bigint;
  constructor(amount: bigint, lo: bigint, hi: bigint) {
    super(amount, lo, hi);
    this.amount = amount;
    this.lo = lo;
    this.hi = hi;
  }
  public poke() {
    assert(within(extractLocktime(this.txPreimage), this.lo, this.hi));
    assert(extractLocktime(this.txPreimage) >= 500000000n);
    this.amount = this.amount;
  }
}
`;

const SEQ = `
class Csv extends StatefulSmartContract {
  amount: bigint;
  readonly minSeq: bigint;
  constructor(amount: bigint, minSeq: bigint) {
    super(amount, minSeq);
    this.amount = amount;
    this.minSeq = minSeq;
  }
  public go() {
    assert(extractSequence(this.txPreimage) >= this.minSeq);
    this.amount = this.amount;
  }
}
`;

const BAKE_TS = 2_500_000_000n; // a Unix deadline after 2038-01-19

async function run(source: string, ctor: unknown[], bake: Record<string, unknown>, method: string, locktime: number) {
  const r = await deployAndCall(source, 'Vault.runar.ts', ctor, method, [], {
    bake,
    signerKey: 'alice',
    fundingSatoshis: 200_000,
    deployOptions: { satoshis: 100_000 },
    callOptions: { satoshis: 100_000, locktime },
  });
  return { ...r, verdict: validateInput(r.callTx, 0, r.deployTx, 0) };
}

describe('signed-number attacks on preimage introspection', () => {
  it('shows how the deadline is baked and read', () => {
    const c = build(VAULT, 'Vault.runar.ts', { amount: 50_000n, deadline: BAKE_TS });
    const s = asm(c.scriptHex);
    console.log('withdraw ASM:', s.replace(/ (OP_1 OP_SPLIT OP_ROT OP_ROT OP_SWAP OP_CAT)+/, ' [preimage-splice] '));
  });

  it('post-2038 deadline: honest spend vs locktime=0 bypass', async () => {
    const ctor = [50_000n, BAKE_TS];
    const cases: Array<[string, number, string]> = [
      ['honest: lockTime = deadline', 2_500_000_000, 'should ACCEPT'],
      ['honest+1: lockTime = deadline+1', 2_500_000_001, 'should ACCEPT'],
      ['too early: lockTime = 0', 0, 'should REJECT (years early)'],
      ['too early: lockTime = 1', 1, 'should REJECT'],
      ['too early: block height 700000', 700_000, 'should REJECT (a height cannot satisfy a timestamp gate)'],
      ['too early: deadline-1', 2_499_999_999, 'should REJECT'],
      ['unsigned-max: 0xFFFFFFFF', 0xffffffff, 'should ACCEPT (unsigned read: 4294967295 >= 2.5e9)'],
    ];
    for (const [name, locktime, expectation] of cases) {
      const expected = expectation.includes('ACCEPT');
      let ok = false;
      let detail = '';
      try {
        const r = await run(VAULT, ctor, { amount: 50_000n, deadline: BAKE_TS }, 'withdraw', locktime);
        ok = r.verdict.ok;
        detail = `tx.lockTime=${r.callTx.lockTime} ${ok ? '' : '— ' + firstLine(r.verdict.error ?? '')}`;
      } catch (e: any) {
        ok = false;
        detail = 'threw: ' + firstLine(String(e.message), 70);
      }
      console.log(`${ok ? 'ACCEPT ' : 'reject '}: ${name}  (${expectation}) ${detail}`);
      expect(ok).toBe(expected);
    }
  });

  it('pre-2038 deadline behaves correctly (control)', async () => {
    const ctor = [50_000n, 700_000n];
    for (const [name, locktime, expected] of [
      ['height 700000 (== deadline)', 700_000, true],
      ['height 699999 (too early)', 699_999, false],
      ['height 800000', 800_000, true],
      ['zero', 0, false],
      ['timestamp 500000000', 500_000_000, false],
    ] as Array<[string, number, boolean]>) {
      let ok = false;
      try {
        const r = await run(HEIGHT_VAULT, ctor, { amount: 50_000n, deadline: 700_000n }, 'withdraw', locktime);
        ok = r.verdict.ok;
      } catch {
        ok = false;
      }
      console.log(`${ok ? 'ACCEPT ' : 'reject '}: ${name}${ok !== expected ? '   <<< expected ' + (expected ? 'ACCEPT' : 'reject') : ''}`);
      expect(ok).toBe(expected);
    }
  });

  it('range check within(locktime, lo, hi) with a post-2038 window', async () => {
    const lo = 2_500_000_000n;
    const hi = 2_600_000_000n;
    for (const locktime of [0, 1, 2_499_999_999, 2_500_000_000, 2_550_000_000, 2_600_000_001, 0xffffffff]) {
      let ok = false;
      try {
        const r = await run(VAULT2, [50_000n, lo, hi], { amount: 50_000n, lo, hi }, 'poke', locktime);
        ok = r.verdict.ok;
      } catch {
        ok = false;
      }
      const expected = locktime >= Number(lo) && locktime <= Number(hi);
      console.log(`${ok ? 'ACCEPT ' : 'reject '}: within(locktime,2.5e9,2.6e9) lockTime=${locktime}${ok !== expected ? '   <<< expected ' + (expected ? 'ACCEPT' : 'reject') : ''}`);
      expect(ok).toBe(expected);
    }
  });

  it('extractSequence compared numerically (bit31 = CSV disable flag)', async () => {
    for (const seq of [0xffffffff, 0xfffffffe, 0x80000000, 0x7fffffff, 0x00200000, 1]) {
      try {
        const r = await deployAndCall(SEQ, 'Csv.runar.ts', [50_000n, 1n], 'go', [], {
          bake: { amount: 50_000n, minSeq: 1n },
          signerKey: 'alice',
          fundingSatoshis: 200_000,
          deployOptions: { satoshis: 100_000 },
          callOptions: { satoshis: 100_000, sequence: seq },
        });
        const v = validateInput(r.callTx, 0, r.deployTx, 0);
        console.log(`${v.ok ? 'ACCEPT ' : 'reject '}: extractSequence >= 1 with nSequence=0x${seq.toString(16)}`);
      } catch (e: any) {
        console.log(`reject(threw): nSequence=0x${seq.toString(16)}  ${firstLine(String(e.message), 70)}`);
      }
    }
  });

  it('stateful state word vs script rebuild: huge / negative bigints', async () => {
    // `amount` is mutated from a witness value, so the app (JS BigInt) and the
    // script (sign-magnitude 8-byte word) must agree byte for byte.
    const BUMP = `
class Bumper extends StatefulSmartContract {
  amount: bigint;
  constructor(amount: bigint) {
    super(amount);
    this.amount = amount;
  }
  public setTo(v: bigint) {
    this.amount = v;
  }
}
`;
    for (const v of [1n, -1n, 127n, 128n, 255n, 32767n, 2147483647n, 2147483648n, 4294967295n, 9223372036854775807n, -9223372036854775808n]) {
      try {
        const r = await deployAndCall(BUMP, 'Bumper.runar.ts', [1000n], 'setTo', [v], {
          bake: { amount: 1000n },
          signerKey: 'alice',
          fundingSatoshis: 200_000,
          deployOptions: { satoshis: 100_000 },
          callOptions: { satoshis: 100_000 },
        });
        const v2 = validateInput(r.callTx, 0, r.deployTx, 0);
        const st = stateOf(r.artifact, r.callTx) as any;
        console.log(`${v2.ok ? 'ACCEPT ' : 'reject '}: setTo(${v}) -> state.amount=${st?.amount}`);
      } catch (e: any) {
        console.log(`threw: setTo(${v})  ${firstLine(String(e.message), 100)}`);
      }
    }
  });
});
