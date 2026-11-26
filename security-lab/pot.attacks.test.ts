import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { callChain, validateInput, stateOf, key, outSats, firstLine } from './harness.js';

/**
 * "State is a number, not coins."
 *
 * Every stateful Rúnar method gets `_newAmount` / `_changePKH` / `_changeAmount`
 * injected: the CALLER picks how many satoshis stay in the contract UTXO and
 * where the rest goes. The covenant binds those numbers to the transaction
 * outputs, but NOTHING binds them to the numbers the contract keeps in state
 * (`betAmount`, `balance`, `highestBid`) or to the value of the input being
 * spent. Two consequences shown here on shipped examples:
 *
 *   1. any caller can shrink the pot and pocket the difference mid-lifecycle;
 *   2. a negative amount argument moves the ledger the wrong way while real
 *      satoshis leave the contract.
 */

const TTT = 'examples/ts/tic-tac-toe/TicTacToe.runar.ts';
const tttSource = readFileSync(TTT, 'utf8');
const FP = 'examples/ts/function-patterns/FunctionPatterns.runar.ts';
const fpSource = readFileSync(FP, 'utf8');

const X = 'alice';
const O = 'bob';
const BET = 50_000;

describe('pot drain on TicTacToe', () => {
  it('T1 draining the prize pool on an ordinary move is refused', async () => {
    // The theft this lab opened with: X plays a move, leaves 546 satoshis in
    // the contract and takes the rest of the 2x pot as change, while the state
    // goes on claiming a full pot — so the eventual winner has to fund the
    // payout out of their own pocket. Main refuses it: a stateful continuation
    // must carry at least its input value, so there is no way to skim the pot
    // on a move. Assert both halves, because a guard that also refused honest
    // play would be worthless.
    const drain = async (leave: number) => {
      try {
        const r = await callChain(tttSource, TTT, [key(X).pubKey, BigInt(BET)], { playerX: key(X).pubKey, betAmount: BigInt(BET) }, [
          { method: 'join', args: [key(O).pubKey, null], signerKey: O, callOptions: { satoshis: BET * 2 } },
          { method: 'move', args: [4n, key(X).pubKey, null], signerKey: X, callOptions: { satoshis: leave } },
        ], { satoshis: BET });
        const v = validateInput(r.txs[2]!, 0, r.txs[1]!, 0);
        return { ok: v.ok, why: v.error ?? '', tx: r.txs[2]! };
      } catch (e: any) {
        return { ok: false, why: String(e.message), tx: undefined as undefined | (typeof e)['tx'] };
      }
    };

    const skimmed = await drain(546);
    console.log(`T1 move leaving 546 of a ${BET * 2} pot: ${skimmed.ok ? '*** ACCEPTED — the drain is back ***' : 'REFUSED — ' + firstLine(skimmed.why, 90)}`);
    expect(skimmed.ok).toBe(false);

    const carried = await drain(BET * 2);
    console.log(`T1 control, same move with the pot carried: ${carried.ok ? 'accepted' : '*** REFUSED — honest play is broken: ' + firstLine(carried.why, 90) + ' ***'}`);
    expect(carried.ok).toBe(true);
  });

  // X opens 0, O answers 3, X 1, O 4, X 2 -> X takes the top row.
  const winningMoves = (drain: boolean, changeAmount = 0n, changePKH = key(X).pubKeyHash) =>
    [
      { method: 'join', args: [key(O).pubKey, null], signerKey: O, callOptions: { satoshis: BET * 2 } },
      { method: 'move', args: [0n, key(X).pubKey, null], signerKey: X, callOptions: { satoshis: drain ? 546 : BET * 2 } },
      { method: 'move', args: [3n, key(O).pubKey, null], signerKey: O, callOptions: { satoshis: drain ? 546 : BET * 2 } },
      { method: 'move', args: [1n, key(X).pubKey, null], signerKey: X, callOptions: { satoshis: drain ? 546 : BET * 2 } },
      { method: 'move', args: [4n, key(O).pubKey, null], signerKey: O, callOptions: { satoshis: drain ? 546 : BET * 2 } },
      { method: 'moveAndWin', args: [2n, key(X).pubKey, null, changePKH, changeAmount], signerKey: X, callOptions: {} },
    ] as any[];

  async function playToEnd(drain: boolean, changeAmount?: bigint) {
    const steps = winningMoves(drain, changeAmount ?? 0n);
    try {
      const r = await callChain(tttSource, TTT, [key(X).pubKey, BigInt(BET)], { playerX: key(X).pubKey, betAmount: BigInt(BET) }, steps, { satoshis: BET });
      const last = r.txs[r.txs.length - 1]!;
      const parent = r.txs[r.txs.length - 2]!;
      return { last, verdict: validateInput(last, 0, parent, 0) };
    } catch (e: any) {
      const msg = String(e.message);
      return { last: undefined, verdict: { ok: false, error: (msg.match(/Script evaluation error: [^\n]*/)?.[0] ?? msg.split('\n')[0]) as string } };
    }
  }

  it('T2 honest game: the terminal payout needs the change amount declared up front', async () => {
    const exactCover = await playToEnd(false);
    console.log('T2 exact-cover claim (changeAmount = 0):', exactCover.verdict.ok ? 'accepted' : 'rejected — ' + String(exactCover.verdict.error).slice(0, 80));
    if (exactCover.last) {
      const last = exactCover.last.outputs.length - 1;
          const measured = BigInt(outSats(exactCover.last, last));
      const again = await playToEnd(false, measured);
      console.log('T2 retry declaring changeAmount=' + measured + ':', again.verdict.ok ? 'accepted' : 'rejected — ' + String(again.verdict.error).slice(0, 80));
    } else {
      console.log('T2 the SDK cannot even build the exact-cover claim: the pot is 2*bet exactly, so the fee needs a second input, which forces a change output the contract was told is zero.');
    }
  });

  it('T3 drained game: the winner has to buy back their own prize', async () => {
    let outcome;
    try {
      outcome = await playToEnd(true);
    } catch (e: any) {
      console.log('T3 drained game, exact-cover attempt threw:', String(e.message).split('\n').slice(0, 2).join(' ').slice(0, 140));
    }
    if (outcome) {
      console.log('T3 drained verdict:', outcome.verdict.ok, String(outcome.verdict.error).split('\n')[0] ?? '');
      console.log('T3 drained outputs:', outcome.last?.outputs.map((o) => o.satoshis) ?? '(tx never built)', 'inputs:', outcome.last?.inputs.length ?? '-');
    }
    // With the pot drained to 546 the winner must contribute 2*bet - 546 from
    // their own wallet just to close the game.
    console.log(`T3 prize owed to the winner: ${BET * 2}; pot left after the drain: 546; winner must add ${BET * 2 - 546} satoshis`);
  });

});

describe('negative amounts on FunctionPatterns (deposit/withdraw ledger)', () => {
  async function withdraw(amount: bigint, feeBps: bigint, satoshis: number) {
    try {
      const r = await callChain(fpSource, FP, [key(X).pubKey, 100_000n], { owner: key(X).pubKey, balance: 100_000n }, [
        { method: 'withdraw', args: [null, amount, feeBps], signerKey: X, callOptions: { satoshis } },
      ], { satoshis: 100_000 });
      const v = validateInput(r.txs[1]!, 0, r.txs[0]!, 0);
      const st = stateOf(r.artifact, r.txs[1]!) as any;
      return { v, st, tx: r.txs[1]! };
    } catch (e: any) {
      return { v: { ok: false, error: String(e.message).split('\n').slice(-2).join(' ') }, st: undefined, tx: undefined };
    }
  }

  it('W1 honest withdraw and its ledger', async () => {
    const r = await withdraw(10_000n, 250n, 89_750);
    console.log('W1 withdraw 10 000 @2.5%:', r.v.ok ? 'ACCEPT' : 'reject', '| state.balance =', r.st?.balance, '| contract holds', r.tx?.outputs[0]?.satoshis, '| change out', r.tx?.outputs.slice(1).map((o) => o.satoshis));
  });

  it('W2 NEGATIVE withdraw: ledger goes up, coins go out', async () => {
    const r = await withdraw(-10_000n, 250n, 1_000);
    console.log('W2 withdraw(-10 000):', r.v.ok ? 'ACCEPT' : 'reject', r.v.error?.slice(0, 90) ?? '');
    console.log('W2 state.balance =', r.st?.balance, '(started 100 000) | contract now holds', r.tx?.outputs[0]?.satoshis, '| paid out', r.tx?.outputs.slice(1).map((o) => o.satoshis));
  });

  it('W3 negative feeBps', async () => {
    const r = await withdraw(10_000n, -250n, 89_000);
    console.log('W3 withdraw(10 000, feeBps=-250):', r.v.ok ? 'ACCEPT' : 'reject', '| state.balance =', r.st?.balance);
  });

  it('W4 feeBps far above 10 000 (basis-point overflow)', async () => {
    const r = await withdraw(10_000n, 25_000n, 1_000);
    console.log('W4 withdraw(10 000, feeBps=25 000):', r.v.ok ? 'ACCEPT' : 'reject', '| state.balance =', r.st?.balance);
  });

  it('W5 deposit more than was funded', async () => {
    try {
      const r = await callChain(fpSource, FP, [key(X).pubKey, 100_000n], { owner: key(X).pubKey, balance: 100_000n }, [
        { method: 'deposit', args: [null, 1_000_000n], signerKey: X, callOptions: { satoshis: 100_000 } },
      ], { satoshis: 100_000 });
      const v = validateInput(r.txs[1]!, 0, r.txs[0]!, 0);
      const st = stateOf(r.artifact, r.txs[1]!) as any;
      console.log('W5 deposit(1 000 000) with no extra funding:', v.ok ? 'ACCEPT' : 'reject', '| state.balance =', st?.balance, '| contract holds', r.txs[1]!.outputs[0]!.satoshis);
    } catch (e: any) {
      console.log('W5 threw:', firstLine(String(e.message), 120));
    }
  });

  it('W6 scale by a huge ratio / divide by a witness denominator', async () => {
    for (const [num, den] of [[2n, 1n], [10n ** 18n, 3n], [1n, 3n], [1n, 0n], [-1n, 1n]] as Array<[bigint, bigint]>) {
      try {
        const r = await callChain(fpSource, FP, [key(X).pubKey, 100_000n], { owner: key(X).pubKey, balance: 100_000n }, [
          { method: 'scale', args: [null, num, den], signerKey: X, callOptions: { satoshis: 100_000 } },
        ], { satoshis: 100_000 });
        const v = validateInput(r.txs[1]!, 0, r.txs[0]!, 0);
        const st = stateOf(r.artifact, r.txs[1]!) as any;
        console.log(`W6 scale(${num}, ${den}): ${v.ok ? 'ACCEPT' : 'reject'} state.balance=${st?.balance} ${v.ok ? '' : '| ' + firstLine(v.error, 70)}`);
      } catch (e: any) {
        console.log(`W6 scale(${num}, ${den}): threw ${firstLine(String(e.message), 90)}`);
      }
    }
  });
});
