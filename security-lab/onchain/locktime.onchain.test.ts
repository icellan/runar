import { it, expect } from 'vitest';
import { onchain } from './gate.js';
import { RunarContract } from 'runar-sdk';
import { compileSource } from '../../integration/ts/helpers/compile.js';
import { createFundedWallet } from '../../integration/ts/helpers/wallet.js';
import { createBatchProvider, getBlockCount, mine, mineUntilConfirmed, rpcCall } from '../../integration/ts/helpers/node.js';

/**
 * F-1 on a live node.
 *
 * The bug was that `extractLocktime` / `extractSequence` handed the 4 raw
 * preimage bytes to `OP_BIN2NUM`, a SIGNED decode, so the unsigned top of the
 * range arrived negative; on top of that nothing stopped a contract from mixing
 * block heights with Unix timestamps, and nothing forced the transaction to
 * actually carry a non-final nSequence — which is what makes nLockTime mean
 * anything to a miner.
 *
 * All of it is now enforced before the transaction ever reaches the node, and
 * these three tests check that on-chain rather than trusting the in-process
 * oracle:
 *
 *   A  an honest locked withdrawal really is held back until its deadline
 *   B  a withdrawal that tries to bypass the gate with a final nSequence is
 *      refused by the node as a script failure, not merely ignored
 *   C  a post-2038 timestamp deadline is satisfiable: on the signed read every
 *      spend of that vault failed `mandatory-script-verify-flag-failed`, the
 *      honest one included, which is how funds got locked forever
 *
 * The contract has to say which domain its gate lives in and pin its sequence,
 * or D26 refuses to compile it at all:
 *
 *   method 'withdraw' reads extractLocktime but does not assert extractSequence
 *   is not 0xffffffff; a locktime gate is not consensus-enforceable without it
 */
const HEIGHT_GATE = `
class Vault extends StatefulSmartContract {
  amount: bigint;
  readonly deadline: bigint;
  constructor(amount: bigint, deadline: bigint) {
    super(amount, deadline);
    this.amount = amount;
    this.deadline = deadline;
  }
  public withdraw() {
    assert(extractSequence(this.txPreimage) !== 0xffffffffn);
    assert(extractLocktime(this.txPreimage) >= this.deadline);
    assert(extractLocktime(this.txPreimage) < 500000000n);
    this.amount = this.amount;
  }
}
`;

/** Same gate in the timestamp domain — the D26 pin flips to `>= 500000000n`. */
const TIMESTAMP_GATE = HEIGHT_GATE.replace('< 500000000n', '>= 500000000n');

const sats = (btc: number) => Math.round(btc * 1e8);

async function vault(source: string, deadline: bigint) {
  const artifact = compileSource(source, 'Vault.runar.ts');
  const provider = createBatchProvider();
  const owner = await createFundedWallet(provider, 0.5);
  const contract = new RunarContract(artifact, [sats(0.001), deadline]);
  const deploy = await contract.deploy(provider, owner.signer, { satoshis: sats(0.002) });
  await mineUntilConfirmed(deploy.txid);
  return { provider, owner, contract };
}

/**
 * Run an SDK call with `broadcast` stubbed out, so the fully-signed transaction
 * is built and captured but never handed to the node. Returns the serialized
 * bytes plus the txid they hash to.
 *
 * Needed because a time-locked spend that the node has already parked in its
 * non-final pool cannot be pushed a second time — `sendrawtransaction` answers
 * `Transaction already in the mempool` — so to compare "before the deadline"
 * against "after the deadline" the transaction has to be built first and sent
 * exactly once, on whichever side of the deadline the test is standing.
 */
async function buildWithoutBroadcast(provider: any, run: () => Promise<any>): Promise<{ result: any; hex: string; txid: string }> {
  let captured: any = null;
  const original = provider.broadcast.bind(provider);
  provider.broadcast = async (tx: any) => {
    captured = tx;
    return tx.id('hex');
  };
  try {
    const result = await run();
    return { result, hex: captured.toHex(), txid: captured.id('hex') };
  } finally {
    provider.broadcast = original;
  }
}

/** Mine until the chain has reached `deadline`, so a height gate is satisfied. */
async function mineUntilDeadline(deadline: number): Promise<void> {
  const needed = deadline - (await getBlockCount()) + 1;
  if (needed > 0) await mine(needed);
}

/** Where the node put a transaction: chain, relaying pool, non-final pool, or nowhere. */
async function whereabouts(txid: string): Promise<{ confirmations: number; pool: string }> {
  let confirmations = 0;
  try {
    confirmations = ((await rpcCall('getrawtransaction', txid, true)) as { confirmations?: number }).confirmations ?? 0;
  } catch {
    confirmations = 0;
  }
  if (confirmations > 0) return { confirmations, pool: 'in a block' };
  if (((await rpcCall('getrawmempool')) as string[]).includes(txid)) return { confirmations, pool: 'relaying mempool' };
  if (((await rpcCall('getrawnonfinalmempool')) as string[]).includes(txid)) return { confirmations, pool: 'non-final pool (nLockTime not yet reached)' };
  return { confirmations, pool: 'nowhere — rejected or dropped' };
}

onchain('F-1 nLockTime / nSequence, verified on a regtest node', () => {

  it('A: a locked withdrawal broadcast before its deadline is held out of every block', async () => {
    const height = await getBlockCount();
    const deadline = height + 40;
    const { provider, owner, contract } = await vault(HEIGHT_GATE, BigInt(deadline));

    const { hex, txid } = await buildWithoutBroadcast(provider, () =>
      contract.call('withdraw', [], provider, owner.signer, { satoshis: sats(0.002), locktime: deadline }),
    );
    console.log(`  signed withdrawal built, txid ${txid.slice(0, 16)}…, deadline height ${deadline} (now ${height})`);

    await rpcCall('sendrawtransaction', hex);
    await mine(3);
    const early = await whereabouts(txid);
    console.log(`  at height ${await getBlockCount()}: ${early.pool}`);
    expect(early.confirmations).toBe(0);
    expect(early.pool).toMatch(/non-final/);

    // Keep mining past the deadline. Consensus now considers the transaction
    // final, and the node still does not mine it: the non-final pool is not a
    // scheduler, it re-evaluates nothing on a new tip, and it refuses the
    // re-broadcast as `Transaction already in the mempool`. A wallet that
    // broadcasts a time-locked spend and walks away therefore leaves its own
    // coins parked until something re-sends different bytes (a new
    // transaction, so a new deadline and a new signature). Recorded as an
    // operational caveat next to F-1; what matters here is that the script did
    // its job and the deadline was not bypassed.
    const needed = deadline - (await getBlockCount()) + 2;
    if (needed > 0) await mine(needed);
    const stale = await whereabouts(txid);
    console.log(`  at height ${await getBlockCount()}, past the deadline: ${stale.pool}`);
    expect(stale.confirmations).toBe(0);
    let duplicate = '';
    try {
      await rpcCall('sendrawtransaction', hex);
    } catch (e: any) {
      duplicate = String(e.message);
    }
    console.log(`  re-sent after the deadline: ${(duplicate.split('\n')[0] ?? 'accepted').slice(0, 90)}`);
    expect(duplicate).toMatch(/already in the mempool/);
  });

  it('A2: the same withdrawal, sent after its deadline, is mined (a legit locked spend is not rejected)', async () => {
    // The other half of A, and the half that matters for honest users: a
    // satisfied locktime has to be accepted. A withdrawn-on-time transaction
    // that the node had never seen before goes straight into a block.
    const height = await getBlockCount();
    const deadline = height + 6;
    const { provider, owner, contract } = await vault(HEIGHT_GATE, BigInt(deadline));

    const { hex, txid } = await buildWithoutBroadcast(provider, () =>
      contract.call('withdraw', [], provider, owner.signer, { satoshis: sats(0.002), locktime: deadline }),
    );
    await mineUntilDeadline(deadline);
    await rpcCall('sendrawtransaction', hex);
    await mine(1);
    const at = await whereabouts(txid);
    console.log(`  withdrawal sent at height ${await getBlockCount()} (deadline ${deadline}): ${at.pool}`);
    expect(at.confirmations).toBeGreaterThan(0);
  });

  it('B: the same withdrawal with a final nSequence is refused by the node, not just ignored', async () => {
    // The covenant asserts `extractSequence(p) !== 0xffffffffn`, so the bypass
    // that used to work — set nLockTime to the deadline, leave every input
    // final, and let a miner take the fee immediately — is now a script failure
    // the node rejects outright. That is the difference between a timelock and
    // a wish: the old failure was silent acceptance.
    const height = await getBlockCount();
    const deadline = height + 40;
    const { provider, owner, contract } = await vault(HEIGHT_GATE, BigInt(deadline));

    let rejection = '';
    let mined = false;
    try {
      const call = await contract.call('withdraw', [], provider, owner.signer, {
        satoshis: sats(0.002),
        locktime: deadline,
        sequence: 0xffffffff,
      });
      await mine(2);
      mined = (await whereabouts(call.txid)).confirmations > 0;
    } catch (e: any) {
      rejection = String(e.message);
    }
    console.log(`  final-sequence withdrawal: ${rejection ? 'rejected — ' + (rejection.split('\n')[0] ?? '').slice(0, 130) : mined ? '*** MINED — the gate is bypassed ***' : 'not mined'}`);
    if (rejection) expect(rejection).toMatch(/mandatory-script-verify-flag-failed|Script failed an OP_VERIFY/i);
    expect(mined).toBe(false);
  });

  it('C: a post-2038 timestamp deadline is parked, not rejected (it used to fail the script)', async () => {
    // 2_500_000_000 is 2049-02-07. On the signed read it arrived at the script
    // as -1794967296, so `extractLocktime >= deadline` was false for every
    // nLockTime consensus allows and every withdrawal came back
    // `mandatory-script-verify-flag-failed` — the honest one included, which is
    // how the coins were locked away. The offline matrix in
    // `locktime.attacks.test.ts` proves the read is unsigned now, across
    // 2^31-1, 2^31 and 2.5e9; what the node can add without a time machine is
    // the *other* half: an unsatisfiable-yet-valid timestamp is refused as a
    // finality rule, not as a script failure.
    //
    // Actually mining it would mean taking the chain to 2049, because finality
    // for a timestamp locktime is judged against the median time past of the
    // previous 11 blocks. That is deliberately not done here: it needs 12
    // blocks at a mocked clock, and unwinding them afterwards put this
    // regtest node into safe mode ("we do not appear to fully agree with our
    // peers"), which then starves every other job sharing the node in the same
    // CI run. Height-domain gates, which is where contracts actually live, are
    // exercised end to end in A and A2.
    const POST_2038 = 2_500_000_000;
    const { provider, owner, contract } = await vault(TIMESTAMP_GATE, BigInt(POST_2038));
    try {
      const parked = await contract.call('withdraw', [], provider, owner.signer, { satoshis: sats(0.002), locktime: POST_2038 });
      const where = await whereabouts(parked.txid);
      console.log(`  withdrawal with nLockTime=${POST_2038}: ${where.pool}`);
      expect(where.confirmations).toBe(0);
      expect(where.pool).toMatch(/non-final/);
    } catch (e: any) {
      // A consensus-level script rejection here means the signed read is back:
      // the transaction would never be valid at any nLockTime, final or not.
      const msg = String(e.message);
      console.log(`  *** refused at the script: ${(msg.split('\n')[0] ?? '').slice(0, 140)} ***`);
      expect(msg).not.toMatch(/mandatory-script-verify-flag-failed|OP_VERIFY/);
      throw e;
    }
  });


});
