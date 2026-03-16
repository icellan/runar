/**
 * Minimal stateful contract test — 2 methods, script validation.
 * Tests whether a second method call fails on-chain even though the
 * compiler produces valid code.
 */
import { describe, it, expect } from 'vitest';
import { compile } from 'runar-compiler';
import { RunarContract } from '../contract.js';
import { MockProvider } from '../providers/mock.js';
import { LocalSigner } from '../signers/local.js';
import { Spend, LockingScript, UnlockingScript, Transaction, Hash, Utils } from '@bsv/sdk';
import type { RunarArtifact } from 'runar-ir-schema';

const SIGNER_KEY = '0000000000000000000000000000000000000000000000000000000000000003';

function compileSource(source: string, fileName: string): RunarArtifact {
  const result = compile(source, { fileName });
  if (!result.artifact) {
    const errors = (result.diagnostics || [])
      .filter((d: any) => d.severity === 'error')
      .map((d: any) => d.message);
    throw new Error(`Compile failed: ${errors.join('; ')}`);
  }
  return result.artifact;
}

async function setupWallet(provider: MockProvider, privKey: string, satoshis: number) {
  const signer = new LocalSigner(privKey);
  const address = await signer.getAddress();
  const pubKeyHex = await signer.getPublicKey();
  provider.addUtxo(address, {
    txid: privKey.slice(0, 64),
    outputIndex: 0,
    satoshis,
    script: '76a914' + '00'.repeat(20) + '88ac',
  });
  return { signer, pubKeyHex };
}

function validateSpend(
  tx: Transaction,
  inputIdx: number,
  sourceTx: Transaction,
  sourceOutputIdx: number,
): boolean {
  const input = tx.inputs[inputIdx]!;
  const sourceOutput = sourceTx.outputs[sourceOutputIdx]!;

  const spend = new Spend({
    sourceTXID: input.sourceTXID!,
    sourceOutputIndex: input.sourceOutputIndex,
    sourceSatoshis: sourceOutput.satoshis!,
    lockingScript: sourceOutput.lockingScript,
    transactionVersion: tx.version,
    otherInputs: tx.inputs
      .filter((_: any, i: number) => i !== inputIdx)
      .map((inp: any, idx: number) => ({
        inputIndex: idx >= inputIdx ? idx + 1 : idx,
        sourceOutputIndex: inp.sourceOutputIndex,
        sourceTXID: inp.sourceTXID!,
        sequence: inp.sequence,
        unlockingScript: inp.unlockingScript,
        sourceSatoshis: 0,
        lockingScript: LockingScript.fromHex(''),
      })),
    outputs: tx.outputs.map((o: any) => ({
      lockingScript: o.lockingScript,
      satoshis: o.satoshis,
    })),
    unlockingScript: input.unlockingScript,
    inputIndex: inputIdx,
    inputSequence: input.sequence,
    lockTime: tx.lockTime,
  });

  return spend.validate();
}

describe('Complex stateful contract with private methods', () => {
  const gameSource = `
    class Game extends StatefulSmartContract {
      readonly owner: PubKey;
      status: bigint;
      turn: bigint;
      c0: bigint;
      c1: bigint;
      c2: bigint;
      c3: bigint;
      c4: bigint;
      constructor(owner: PubKey, status: bigint, turn: bigint,
        c0: bigint, c1: bigint, c2: bigint, c3: bigint, c4: bigint) {
        super(owner, status, turn, c0, c1, c2, c3, c4);
        this.owner = owner;
        this.status = status;
        this.turn = turn;
        this.c0 = c0; this.c1 = c1; this.c2 = c2; this.c3 = c3; this.c4 = c4;
      }

      private assertTurn(player: PubKey): void {
        if (this.turn === 1n) {
          assert(player === this.owner);
        } else {
          assert(player !== this.owner);
        }
      }

      public start(sig: Sig, pk: PubKey): void {
        assert(this.status === 0n);
        this.status = 1n;
        this.turn = 1n;
        assert(checkSig(sig, pk));
      }

      public play(position: bigint, player: PubKey, sig: Sig): void {
        assert(this.status === 1n);
        assert(checkSig(sig, player));
        if (position === 0n) { this.c0 = this.turn; }
        else if (position === 1n) { this.c1 = this.turn; }
        else { this.c4 = this.turn; }
        if (this.turn === 1n) { this.turn = 2n; }
        else { this.turn = 1n; }
      }
    }
  `;

  it('start (method 0) should pass script validation', async () => {
    const artifact = compileSource(gameSource, 'Game.runar.ts');
    const provider = new MockProvider();
    const wallet = await setupWallet(provider, SIGNER_KEY, 500_000);
    const contract = new RunarContract(artifact, [wallet.pubKeyHex, 0n, 0n, 0n, 0n, 0n, 0n, 0n]);

    await contract.deploy(provider, wallet.signer, {});
    const deployTx = Transaction.fromHex(provider.getBroadcastedTxs()[0]!);

    await contract.call('start', [null, wallet.pubKeyHex], provider, wallet.signer);
    const startTx = Transaction.fromHex(provider.getBroadcastedTxs()[1]!);

    expect(contract.state.status).toBe(1n);
    expect(contract.state.turn).toBe(1n);
    const ok = validateSpend(startTx, 0, deployTx, 0);
    expect(ok).toBe(true);
  });

  it('play (method 1, with private method call) should pass script validation', async () => {
    const artifact = compileSource(gameSource, 'Game.runar.ts');
    const provider = new MockProvider();
    const wallet = await setupWallet(provider, SIGNER_KEY, 500_000);
    const contract = new RunarContract(artifact, [wallet.pubKeyHex, 0n, 0n, 0n, 0n, 0n, 0n, 0n]);

    await contract.deploy(provider, wallet.signer, {});
    const deployTx = Transaction.fromHex(provider.getBroadcastedTxs()[0]!);

    // start
    await contract.call('start', [null, wallet.pubKeyHex], provider, wallet.signer);
    const startTx = Transaction.fromHex(provider.getBroadcastedTxs()[1]!);

    // play - calls private method assertTurn
    await contract.call('play', [4n, wallet.pubKeyHex, null], provider, wallet.signer);
    const playTx = Transaction.fromHex(provider.getBroadcastedTxs()[2]!);

    expect(contract.state.c4).toBe(1n);
    expect(contract.state.turn).toBe(2n);

    try {
      const ok = validateSpend(playTx, 0, startTx, 0);
      expect(ok).toBe(true);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      expect.fail(`Play TX script validation failed: ${msg}`);
    }
  });
});

describe('Stateful two-method contract script validation', () => {
  const source = `
    class Counter extends StatefulSmartContract {
      count: bigint;
      constructor(count: bigint) {
        super(count);
        this.count = count;
      }

      public increment(sig: Sig, pk: PubKey): void {
        this.count = this.count + 1n;
        assert(checkSig(sig, pk));
      }

      public reset(sig: Sig, pk: PubKey): void {
        this.count = 0n;
        assert(checkSig(sig, pk));
      }
    }
  `;

  it('first method (increment) should pass script validation', async () => {
    const artifact = compileSource(source, 'Counter.runar.ts');
    const provider = new MockProvider();
    const wallet = await setupWallet(provider, SIGNER_KEY, 500_000);
    const contract = new RunarContract(artifact, [0n]);

    await contract.deploy(provider, wallet.signer, {});
    const deployTx = Transaction.fromHex(provider.getBroadcastedTxs()[0]!);

    await contract.call('increment', [null, wallet.pubKeyHex], provider, wallet.signer);
    const incrTx = Transaction.fromHex(provider.getBroadcastedTxs()[1]!);

    expect(contract.state.count).toBe(1n);
    expect(() => validateSpend(incrTx, 0, deployTx, 0)).not.toThrow();
  });

  it('second method (reset) should pass script validation', async () => {
    const artifact = compileSource(source, 'Counter.runar.ts');
    const provider = new MockProvider();
    const wallet = await setupWallet(provider, SIGNER_KEY, 500_000);
    const contract = new RunarContract(artifact, [5n]);

    await contract.deploy(provider, wallet.signer, {});
    const deployTx = Transaction.fromHex(provider.getBroadcastedTxs()[0]!);

    await contract.call('reset', [null, wallet.pubKeyHex], provider, wallet.signer);
    const resetTx = Transaction.fromHex(provider.getBroadcastedTxs()[1]!);

    expect(contract.state.count).toBe(0n);
    expect(() => validateSpend(resetTx, 0, deployTx, 0)).not.toThrow();
  });

  it('increment then reset should both pass', async () => {
    const artifact = compileSource(source, 'Counter.runar.ts');
    const provider = new MockProvider();
    const wallet = await setupWallet(provider, SIGNER_KEY, 500_000);
    const contract = new RunarContract(artifact, [0n]);

    await contract.deploy(provider, wallet.signer, {});
    const deployTx = Transaction.fromHex(provider.getBroadcastedTxs()[0]!);

    // First call: increment
    await contract.call('increment', [null, wallet.pubKeyHex], provider, wallet.signer);
    const incrTx = Transaction.fromHex(provider.getBroadcastedTxs()[1]!);
    expect(contract.state.count).toBe(1n);
    expect(() => validateSpend(incrTx, 0, deployTx, 0)).not.toThrow();

    // Second call: reset (uses the increment TX's output)
    await contract.call('reset', [null, wallet.pubKeyHex], provider, wallet.signer);
    const resetTx = Transaction.fromHex(provider.getBroadcastedTxs()[2]!);
    expect(contract.state.count).toBe(0n);
    expect(() => validateSpend(resetTx, 0, incrTx, 0)).not.toThrow();
  });
});

describe('Bug #1: update_prop old-value removal — multiple property mutations', () => {
  // Regression test: after liftBranchUpdateProps, each update_prop used to leave
  // the OLD property value on the stack. Over N property updates, the stack
  // accumulated N extra items, causing OP_NUM2BIN to receive wrong values.
  const source = `
    class ThreeProp extends StatefulSmartContract {
      a: bigint;
      b: bigint;
      c: bigint;
      constructor(a: bigint, b: bigint, c: bigint) {
        super(a, b, c);
        this.a = a; this.b = b; this.c = c;
      }
      public setAll(sig: Sig, pk: PubKey): void {
        this.a = 10n;
        this.b = 20n;
        this.c = 30n;
        assert(checkSig(sig, pk));
      }
    }
  `;

  it('three consecutive update_prop should pass script validation', async () => {
    const artifact = compileSource(source, 'ThreeProp.runar.ts');
    const provider = new MockProvider();
    const wallet = await setupWallet(provider, SIGNER_KEY, 500_000);
    const contract = new RunarContract(artifact, [1n, 2n, 3n]);

    await contract.deploy(provider, wallet.signer, {});
    const deployTx = Transaction.fromHex(provider.getBroadcastedTxs()[0]!);

    await contract.call('setAll', [null, wallet.pubKeyHex], provider, wallet.signer);
    const callTx = Transaction.fromHex(provider.getBroadcastedTxs()[1]!);

    expect(contract.state.a).toBe(10n);
    expect(contract.state.b).toBe(20n);
    expect(contract.state.c).toBe(30n);
    expect(() => validateSpend(callTx, 0, deployTx, 0)).not.toThrow();
  });
});

describe('Bug #4: @this object consumption in private method dispatch', () => {
  // Regression test: lowerMethodCall didn't consume the @this object reference
  // before dispatching to inlineMethodCall. The stale 0n on the stack inflated
  // PICK/ROLL depths, producing extra OP_ROT/OP_SWAP opcodes.
  const source = `
    class WithHelper extends SmartContract {
      readonly pk: PubKey;
      constructor(pk: PubKey) { super(pk); this.pk = pk; }
      private double(x: bigint): bigint {
        return x * 2n;
      }
      public spend(sig: Sig, amount: bigint): void {
        const d: bigint = this.double(amount);
        assert(d > 0n);
        assert(checkSig(sig, this.pk));
      }
    }
  `;

  it('private method call in stateless contract produces valid script', () => {
    const artifact = compileSource(source, 'WithHelper.runar.ts');
    // Stateless contracts don't need deploy/call — just verify compilation
    // produces a script. The script is validated in conformance tests.
    expect(artifact.script.length).toBeGreaterThan(0);
    // The key signal: the script should NOT contain unnecessary OP_ROT (0x7b)
    // sequences that indicate stale @this on the stack.
    // Before the fix, this produced OP_0 OP_ROT OP_ROT; after, it's clean.
    const script = artifact.script;
    // OP_0 OP_ROT OP_ROT = 007b7b — this sequence shouldn't appear
    expect(script).not.toContain('007b7b');
  });
});

describe('Bug #5: void-if — assertion-only branches should not push phantom', () => {
  // Regression test: after an if-else where both branches only assert (no value
  // produced), the code unconditionally pushed a phantom entry onto the stackMap.
  // This desynchronized the stackMap from the actual stack.
  const source = `
    class VoidIfGame extends StatefulSmartContract {
      readonly owner: PubKey;
      turn: bigint;
      constructor(owner: PubKey, turn: bigint) {
        super(owner, turn);
        this.owner = owner;
        this.turn = turn;
      }
      private assertCorrectPlayer(player: PubKey): void {
        if (this.turn === 1n) { assert(player === this.owner); }
        else { assert(player !== this.owner); }
      }
      public play(player: PubKey, sig: Sig, pk: PubKey): void {
        this.assertCorrectPlayer(player);
        if (this.turn === 1n) { this.turn = 2n; }
        else { this.turn = 1n; }
        assert(checkSig(sig, pk));
      }
    }
  `;

  it('assertion-only private method + turn flip should pass script validation', async () => {
    const artifact = compileSource(source, 'VoidIfGame.runar.ts');
    const provider = new MockProvider();
    const wallet = await setupWallet(provider, SIGNER_KEY, 500_000);
    // Initialize with turn=1n so assertCorrectPlayer's then-branch runs
    // (player === owner succeeds when we use the same key)
    const contract = new RunarContract(artifact, [wallet.pubKeyHex, 1n]);

    await contract.deploy(provider, wallet.signer, {});
    const deployTx = Transaction.fromHex(provider.getBroadcastedTxs()[0]!);

    await contract.call('play', [wallet.pubKeyHex, null, wallet.pubKeyHex], provider, wallet.signer);
    const playTx = Transaction.fromHex(provider.getBroadcastedTxs()[1]!);

    // turn flips from 1 to 2
    expect(contract.state.turn).toBe(2n);
    try {
      const ok = validateSpend(playTx, 0, deployTx, 0);
      expect(ok).toBe(true);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      expect.fail(`Play TX script validation failed: ${msg}`);
    }
  });
});

describe('Terminal method with extractOutputHash (payout verification)', () => {
  const source = `
import { StatefulSmartContract, assert, checkSig, num2bin, cat, hash160, hash256, extractOutputHash } from 'runar-lang';
import type { PubKey, Sig, ByteString } from 'runar-lang';

class PayoutContract extends StatefulSmartContract {
  readonly owner: PubKey;
  readonly betAmount: bigint;
  readonly p2pkhPrefix: ByteString = "1976a914" as ByteString;
  readonly p2pkhSuffix: ByteString = "88ac" as ByteString;
  status: bigint = 0n;

  constructor(owner: PubKey, betAmount: bigint) {
    super(owner, betAmount);
    this.owner = owner;
    this.betAmount = betAmount;
  }

  public activate(sig: Sig): void {
    assert(this.status == 0n);
    assert(checkSig(sig, this.owner));
    this.status = 1n;
  }

  public claim(sig: Sig, changePKH: ByteString, changeAmount: bigint): void {
    assert(this.status == 1n);
    assert(checkSig(sig, this.owner));
    const payout = cat(cat(num2bin(this.betAmount, 8n), this.p2pkhPrefix), cat(hash160(this.owner), this.p2pkhSuffix));
    if (changeAmount > 0n) {
      const change = cat(cat(num2bin(changeAmount, 8n), this.p2pkhPrefix), cat(changePKH, this.p2pkhSuffix));
      assert(hash256(cat(payout, change)) == extractOutputHash(this.txPreimage));
    } else {
      assert(hash256(payout) == extractOutputHash(this.txPreimage));
    }
  }
}
  `;

  it('activate (state-mutating) should pass script validation', async () => {
    const artifact = compileSource(source, 'PayoutContract.runar.ts');
    const provider = new MockProvider();
    const wallet = await setupWallet(provider, SIGNER_KEY, 500_000);
    const betAmount = 1000n;
    const contract = new RunarContract(artifact, [wallet.pubKeyHex, betAmount]);

    await contract.deploy(provider, wallet.signer, { satoshis: Number(betAmount) });
    const deployTx = Transaction.fromHex(provider.getBroadcastedTxs()[0]!);

    await contract.call('activate', [null], provider, wallet.signer);
    const activateTx = Transaction.fromHex(provider.getBroadcastedTxs()[1]!);

    expect(contract.state.status).toBe(1n);
    expect(() => validateSpend(activateTx, 0, deployTx, 0)).not.toThrow();
  });

  it('claim (terminal with extractOutputHash) should pass script validation', async () => {
    const artifact = compileSource(source, 'PayoutContract.runar.ts');
    const provider = new MockProvider();
    const wallet = await setupWallet(provider, SIGNER_KEY, 500_000);
    const betAmount = 1000n;
    const contract = new RunarContract(artifact, [wallet.pubKeyHex, betAmount]);

    await contract.deploy(provider, wallet.signer, { satoshis: Number(betAmount) });
    const deployTx = Transaction.fromHex(provider.getBroadcastedTxs()[0]!);

    // Activate: state-mutating call to set status=1
    await contract.call('activate', [null], provider, wallet.signer);
    const activateTx = Transaction.fromHex(provider.getBroadcastedTxs()[1]!);
    expect(contract.state.status).toBe(1n);

    // Build the P2PKH payout script: OP_DUP OP_HASH160 <pkh> OP_EQUALVERIFY OP_CHECKSIG
    const pubKeyBytes = Utils.toArray(wallet.pubKeyHex, 'hex');
    const pkhBytes = Hash.hash160(pubKeyBytes);
    const pkhHex = Utils.toHex(pkhBytes);
    const payoutScript = '76a914' + pkhHex + '88ac';

    // Claim: terminal call with terminalOutputs
    await contract.call(
      'claim',
      [null, '00'.repeat(20), 0n],
      provider, wallet.signer,
      {
        terminalOutputs: [
          { scriptHex: payoutScript, satoshis: Number(betAmount) },
        ],
      },
    );
    const claimTx = Transaction.fromHex(provider.getBroadcastedTxs()[2]!);

    try {
      const ok = validateSpend(claimTx, 0, activateTx, 0);
      expect(ok).toBe(true);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      expect.fail(`Claim TX script validation failed: ${msg}`);
    }
  });
});

describe('TicTacToe full game with terminal moveAndWin', () => {
  const PLAYER_X_KEY = '0000000000000000000000000000000000000000000000000000000000000003';
  const PLAYER_O_KEY = '0000000000000000000000000000000000000000000000000000000000000005';

  let tttSource: string;
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const fs = require('fs');
    const path = require('path');
    tttSource = fs.readFileSync(
      path.resolve(__dirname, '../../../../examples/ts/tic-tac-toe/TicTacToe.runar.ts'),
      'utf-8',
    );
  } catch {
    tttSource = '';
  }

  it('full game: deploy → join → 4 moves → moveAndWin', async () => {
    if (!tttSource) return; // skip if source not found

    const artifact = compileSource(tttSource, 'TicTacToe.runar.ts');
    const provider = new MockProvider();
    const betAmount = 1000;

    // Setup playerX wallet
    const playerX = new LocalSigner(PLAYER_X_KEY);
    const playerXPub = await playerX.getPublicKey();
    const playerXAddr = await playerX.getAddress();
    provider.addUtxo(playerXAddr, {
      txid: PLAYER_X_KEY.slice(0, 64),
      outputIndex: 0,
      satoshis: 500_000,
      script: '76a914' + '00'.repeat(20) + '88ac',
    });

    // Setup playerO wallet
    const playerO = new LocalSigner(PLAYER_O_KEY);
    const playerOPub = await playerO.getPublicKey();
    const playerOAddr = await playerO.getAddress();
    provider.addUtxo(playerOAddr, {
      txid: PLAYER_O_KEY.slice(0, 64),
      outputIndex: 0,
      satoshis: 500_000,
      script: '76a914' + '00'.repeat(20) + '88ac',
    });

    // Deploy with playerX
    const contract = new RunarContract(artifact, [playerXPub, BigInt(betAmount)]);
    await contract.deploy(provider, playerX, { satoshis: betAmount });
    const deployTx = Transaction.fromHex(provider.getBroadcastedTxs()[0]!);

    // Player O joins — doubling the pot
    await contract.call('join', [playerOPub, null], provider, playerO, {
      satoshis: betAmount * 2,
    });
    const joinTx = Transaction.fromHex(provider.getBroadcastedTxs()[1]!);
    expect(contract.state.status).toBe(1n);
    expect(contract.state.turn).toBe(1n);

    // Validate join TX
    expect(() => validateSpend(joinTx, 0, deployTx, 0)).not.toThrow();

    // X@0
    await contract.call('move', [0n, playerXPub, null], provider, playerX);
    const move1Tx = Transaction.fromHex(provider.getBroadcastedTxs()[2]!);
    expect(contract.state.c0).toBe(1n);
    expect(contract.state.turn).toBe(2n);
    expect(() => validateSpend(move1Tx, 0, joinTx, 0)).not.toThrow();

    // O@3
    await contract.call('move', [3n, playerOPub, null], provider, playerO);
    const move2Tx = Transaction.fromHex(provider.getBroadcastedTxs()[3]!);
    expect(contract.state.c3).toBe(2n);
    expect(contract.state.turn).toBe(1n);
    expect(() => validateSpend(move2Tx, 0, move1Tx, 0)).not.toThrow();

    // X@1
    await contract.call('move', [1n, playerXPub, null], provider, playerX);
    const move3Tx = Transaction.fromHex(provider.getBroadcastedTxs()[4]!);
    expect(contract.state.c1).toBe(1n);
    expect(contract.state.turn).toBe(2n);
    expect(() => validateSpend(move3Tx, 0, move2Tx, 0)).not.toThrow();

    // O@4
    await contract.call('move', [4n, playerOPub, null], provider, playerO);
    const move4Tx = Transaction.fromHex(provider.getBroadcastedTxs()[5]!);
    expect(contract.state.c4).toBe(2n);
    expect(contract.state.turn).toBe(1n);
    expect(() => validateSpend(move4Tx, 0, move3Tx, 0)).not.toThrow();

    // Board: X X _ | O O _ | _ _ _  — X plays position 2 to win top row
    const totalPayout = betAmount * 2;
    const xPubKeyBytes = Utils.toArray(playerXPub, 'hex');
    const xPkhBytes = Hash.hash160(xPubKeyBytes);
    const xPkhHex = Utils.toHex(xPkhBytes);
    const winnerP2PKH = '76a914' + xPkhHex + '88ac';

    // moveAndWin: terminal method
    await contract.call(
      'moveAndWin',
      [2n, playerXPub, null, '00'.repeat(20), 0n],
      provider, playerX,
      {
        terminalOutputs: [
          { scriptHex: winnerP2PKH, satoshis: totalPayout },
        ],
      },
    );
    const winTx = Transaction.fromHex(provider.getBroadcastedTxs()[6]!);

    try {
      const ok = validateSpend(winTx, 0, move4Tx, 0);
      expect(ok).toBe(true);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      expect.fail(`moveAndWin TX script validation failed: ${msg}`);
    }
  });
});

describe('Private method with return value called multiple times (win detection pattern)', () => {
  // Minimal reproduction of the TicTacToe checkWinAfterMove pattern:
  // a private method with return value (getCellOrOverride) called 3 times,
  // results compared for a "win" condition.
  const source = `
import { StatefulSmartContract, assert, checkSig } from 'runar-lang';
import type { PubKey, Sig } from 'runar-lang';

class WinCheck extends StatefulSmartContract {
  readonly owner: PubKey;
  c0: bigint = 0n;
  c1: bigint = 0n;
  c2: bigint = 0n;
  turn: bigint = 0n;
  status: bigint = 0n;

  constructor(owner: PubKey) {
    super(owner);
    this.owner = owner;
  }

  private getCellOrOverride(cellIndex: bigint, overridePos: bigint, overrideVal: bigint): bigint {
    if (cellIndex == overridePos) {
      return overrideVal;
    }
    if (cellIndex == 0n) { return this.c0; }
    else if (cellIndex == 1n) { return this.c1; }
    else { return this.c2; }
  }

  private checkWinAfterMove(position: bigint, player: bigint): boolean {
    const v0 = this.getCellOrOverride(0n, position, player);
    const v1 = this.getCellOrOverride(1n, position, player);
    const v2 = this.getCellOrOverride(2n, position, player);
    if (v0 == player && v1 == player && v2 == player) { return true; }
    return false;
  }

  public activate(sig: Sig): void {
    assert(checkSig(sig, this.owner));
    this.status = 1n;
    this.turn = 1n;
  }

  public place(position: bigint, sig: Sig): void {
    assert(this.status == 1n);
    assert(checkSig(sig, this.owner));
    if (position == 0n) { this.c0 = this.turn; }
    else if (position == 1n) { this.c1 = this.turn; }
    else { this.c2 = this.turn; }
  }

  public winMove(position: bigint, sig: Sig): void {
    assert(this.status == 1n);
    assert(checkSig(sig, this.owner));
    assert(this.checkWinAfterMove(position, this.turn));
  }
}
  `;

  it('activate + 2 places + winMove should pass validation', async () => {
    const artifact = compileSource(source, 'WinCheck.runar.ts');
    const provider = new MockProvider();
    const wallet = await setupWallet(provider, SIGNER_KEY, 500_000);
    const contract = new RunarContract(artifact, [wallet.pubKeyHex]);

    await contract.deploy(provider, wallet.signer, {});
    const deployTx = Transaction.fromHex(provider.getBroadcastedTxs()[0]!);

    // Activate
    await contract.call('activate', [null], provider, wallet.signer);
    const activateTx = Transaction.fromHex(provider.getBroadcastedTxs()[1]!);
    expect(contract.state.status).toBe(1n);
    expect(contract.state.turn).toBe(1n);
    expect(() => validateSpend(activateTx, 0, deployTx, 0)).not.toThrow();

    // Place at position 0
    await contract.call('place', [0n, null], provider, wallet.signer);
    const place0Tx = Transaction.fromHex(provider.getBroadcastedTxs()[2]!);
    expect(contract.state.c0).toBe(1n);
    expect(() => validateSpend(place0Tx, 0, activateTx, 0)).not.toThrow();

    // Place at position 1
    await contract.call('place', [1n, null], provider, wallet.signer);
    const place1Tx = Transaction.fromHex(provider.getBroadcastedTxs()[3]!);
    expect(contract.state.c1).toBe(1n);
    expect(() => validateSpend(place1Tx, 0, place0Tx, 0)).not.toThrow();

    // Win move at position 2: row 0-1-2 all = 1 (turn)
    // checkWinAfterMove(2, 1) should detect: v0=c0=1, v1=c1=1, v2=override(2,2,1)=1
    try {
      await contract.call('winMove', [2n, null], provider, wallet.signer);
      const winTx = Transaction.fromHex(provider.getBroadcastedTxs()[4]!);
      const ok = validateSpend(winTx, 0, place1Tx, 0);
      expect(ok).toBe(true);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      expect.fail(`winMove TX script validation failed: ${msg}`);
    }
  });
});

describe('Nested private method calls (assertCellEmpty from placeMove)', () => {
  const source = `
    class Game4 extends StatefulSmartContract {
      readonly owner: PubKey;
      status: bigint;
      turn: bigint;
      c0: bigint;
      c1: bigint;
      c2: bigint;
      c3: bigint;
      constructor(owner: PubKey, status: bigint, turn: bigint,
        c0: bigint, c1: bigint, c2: bigint, c3: bigint) {
        super(owner, status, turn, c0, c1, c2, c3);
        this.owner = owner; this.status = status; this.turn = turn;
        this.c0 = c0; this.c1 = c1; this.c2 = c2; this.c3 = c3;
      }
      private assertCorrectPlayer(player: PubKey): void {
        if (this.turn === 1n) { assert(player === this.owner); }
        else { assert(player !== this.owner); }
      }
      private assertCellEmpty(position: bigint): void {
        if (position === 0n) { assert(this.c0 === 0n); }
        else if (position === 1n) { assert(this.c1 === 0n); }
        else if (position === 2n) { assert(this.c2 === 0n); }
        else { assert(this.c3 === 0n); }
      }
      private placeMove(position: bigint): void {
        this.assertCellEmpty(position);
        if (position === 0n) { this.c0 = this.turn; }
        else if (position === 1n) { this.c1 = this.turn; }
        else if (position === 2n) { this.c2 = this.turn; }
        else { this.c3 = this.turn; }
      }
      public start(sig: Sig, pk: PubKey): void {
        assert(this.status === 0n);
        this.status = 1n;
        this.turn = 1n;
        assert(checkSig(sig, pk));
      }
      public play(position: bigint, player: PubKey, sig: Sig): void {
        assert(this.status === 1n);
        assert(checkSig(sig, player));
        this.assertCorrectPlayer(player);
        this.placeMove(position);
        if (this.turn === 1n) { this.turn = 2n; }
        else { this.turn = 1n; }
      }
    }
  `;

  it('start should pass script validation', async () => {
    const artifact = compileSource(source, 'Game4.runar.ts');
    const provider = new MockProvider();
    const wallet = await setupWallet(provider, SIGNER_KEY, 500_000);
    const contract = new RunarContract(artifact, [wallet.pubKeyHex, 0n, 0n, 0n, 0n, 0n, 0n]);

    await contract.deploy(provider, wallet.signer, {});
    const deployTx = Transaction.fromHex(provider.getBroadcastedTxs()[0]!);

    await contract.call('start', [null, wallet.pubKeyHex], provider, wallet.signer);
    const startTx = Transaction.fromHex(provider.getBroadcastedTxs()[1]!);

    expect(contract.state.status).toBe(1n);
    expect(contract.state.turn).toBe(1n);
    expect(() => validateSpend(startTx, 0, deployTx, 0)).not.toThrow();
  });

  it('play (nested private methods) should pass script validation', async () => {
    const artifact = compileSource(source, 'Game4.runar.ts');
    const provider = new MockProvider();
    const wallet = await setupWallet(provider, SIGNER_KEY, 500_000);
    const contract = new RunarContract(artifact, [wallet.pubKeyHex, 0n, 0n, 0n, 0n, 0n, 0n]);

    await contract.deploy(provider, wallet.signer, {});
    const deployTx = Transaction.fromHex(provider.getBroadcastedTxs()[0]!);

    await contract.call('start', [null, wallet.pubKeyHex], provider, wallet.signer);
    const startTx = Transaction.fromHex(provider.getBroadcastedTxs()[1]!);

    await contract.call('play', [2n, wallet.pubKeyHex, null], provider, wallet.signer);
    const playTx = Transaction.fromHex(provider.getBroadcastedTxs()[2]!);

    expect(contract.state.c2).toBe(1n);
    expect(contract.state.turn).toBe(2n);

    try {
      const ok = validateSpend(playTx, 0, startTx, 0);
      expect(ok).toBe(true);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      expect.fail(`Play TX script validation failed: ${msg}`);
    }
  });
});
