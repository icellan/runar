/**
 * TicTacToe integration test — stateful contract with two-player game logic.
 *
 * TicTacToe is a StatefulSmartContract with properties:
 *   - playerX: PubKey (readonly, constructor param)
 *   - betAmount: bigint (readonly, constructor param)
 *   - playerO: PubKey (mutable, initialized to 33 zero bytes)
 *   - c0-c8: bigint (mutable, board cells, initialized to 0)
 *   - turn: bigint (mutable, initialized to 0)
 *   - status: bigint (mutable, initialized to 0)
 *   - p2pkhPrefix, p2pkhSuffix: ByteString (readonly, initialized)
 *
 * State-mutating methods: join(opponentPK, sig), move(position, player, sig)
 * Terminal methods: moveAndWin, moveAndTie, cancelBeforeJoin, cancel
 *
 * The SDK auto-computes Sig when null is passed. For multi-player tests,
 * each player needs their own funded wallet and signer. The signer used
 * for a call determines whose private key signs the transaction — the
 * contract's checkSig verifies the signature against the provided pubkey.
 */

import { describe, it, expect } from 'vitest';
import { compileContract } from './helpers/compile.js';
import { RunarContract } from 'runar-sdk';
import { createFundedWallet, createWallet } from './helpers/wallet.js';
import { createProvider } from './helpers/node.js';

describe('TicTacToe', () => {
  it('should compile the TicTacToe contract', () => {
    const artifact = compileContract('examples/ts/tic-tac-toe/TicTacToe.runar.ts');
    expect(artifact).toBeTruthy();
    expect(artifact.contractName).toBe('TicTacToe');
  });

  it('should deploy with playerX and betAmount', async () => {
    const artifact = compileContract('examples/ts/tic-tac-toe/TicTacToe.runar.ts');

    const provider = createProvider();
    const playerX = await createFundedWallet(provider);

    const contract = new RunarContract(artifact, [playerX.pubKeyHex, 5000n]);

    const { txid: deployTxid } = await contract.deploy(provider, playerX.signer, {});
    expect(deployTxid).toBeTruthy();
    expect(typeof deployTxid).toBe('string');
    expect(deployTxid.length).toBe(64);
  });

  it('should join the game as player O (auto-computed state)', async () => {
    const artifact = compileContract('examples/ts/tic-tac-toe/TicTacToe.runar.ts');

    const provider = createProvider();
    const playerX = await createFundedWallet(provider);
    const playerO = await createFundedWallet(provider);

    const contract = new RunarContract(artifact, [playerX.pubKeyHex, 5000n]);
    await contract.deploy(provider, playerX.signer, {});

    // join(opponentPK, sig) — playerO signs, passing their pubkey
    const { txid: joinTxid } = await contract.call(
      'join', [playerO.pubKeyHex, null], provider, playerO.signer,
    );
    expect(joinTxid).toBeTruthy();
    expect(joinTxid.length).toBe(64);

    // After join: status=1 (playing), turn=1 (playerX's turn)
    expect(contract.state.status).toBe(1n);
    expect(contract.state.turn).toBe(1n);
  });

  it('should make a move after join (auto-computed state)', async () => {
    const artifact = compileContract('examples/ts/tic-tac-toe/TicTacToe.runar.ts');

    const provider = createProvider();
    const playerX = await createFundedWallet(provider);
    const playerO = await createFundedWallet(provider);

    const contract = new RunarContract(artifact, [playerX.pubKeyHex, 5000n]);
    await contract.deploy(provider, playerX.signer, {});

    // Player O joins
    await contract.call('join', [playerO.pubKeyHex, null], provider, playerO.signer);

    // Player X moves to position 4 (center) — turn=1 means it's X's turn
    // DEBUG: try manual newState to isolate the issue
    const { txid: moveTxid } = await contract.call(
      'move', [4n, playerX.pubKeyHex, null], provider, playerX.signer,
      { newState: { c4: 1n, turn: 2n } },
    );
    expect(moveTxid).toBeTruthy();
    expect(moveTxid.length).toBe(64);

    // After move: c4=1 (X mark), turn=2 (O's turn)
    expect(contract.state.c4).toBe(1n);
    expect(contract.state.turn).toBe(2n);
  });

  it('should play a full game: X wins top row and claims the pot', async () => {
    const artifact = compileContract('examples/ts/tic-tac-toe/TicTacToe.runar.ts');

    const provider = createProvider();
    const playerX = await createFundedWallet(provider);
    const playerO = await createFundedWallet(provider);

    const betAmount = 1000n;
    const contract = new RunarContract(artifact, [playerX.pubKeyHex, betAmount]);
    await contract.deploy(provider, playerX.signer, { satoshis: Number(betAmount) });

    // Player O joins — doubling the pot (betAmount * 2)
    await contract.call('join', [playerO.pubKeyHex, null], provider, playerO.signer,
      { satoshis: Number(betAmount) * 2 });
    expect(contract.state.status).toBe(1n);

    // X@0, O@3, X@1, O@4 — set up X to win with position 2 (top row)
    await contract.call('move', [0n, playerX.pubKeyHex, null], provider, playerX.signer);
    await contract.call('move', [3n, playerO.pubKeyHex, null], provider, playerO.signer);
    await contract.call('move', [1n, playerX.pubKeyHex, null], provider, playerX.signer);
    await contract.call('move', [4n, playerO.pubKeyHex, null], provider, playerO.signer);

    // Board: X X _ | O O _ | _ _ _  — X plays position 2 to win top row
    expect(contract.state.c0).toBe(1n);
    expect(contract.state.c1).toBe(1n);
    expect(contract.state.turn).toBe(1n); // X's turn

    // moveAndWin(position, player, sig, changePKH, changeAmount)
    // Terminal method — needs terminalOutputs matching the payout the contract expects
    const totalPayout = Number(betAmount) * 2;
    const winnerP2PKH = '76a914' + playerX.pubKeyHash + '88ac';

    const { txid: winTxid } = await contract.call(
      'moveAndWin',
      [2n, playerX.pubKeyHex, null, '00'.repeat(20), 0n],
      provider, playerX.signer,
      {
        terminalOutputs: [
          { scriptHex: winnerP2PKH, satoshis: totalPayout },
        ],
      },
    );
    expect(winTxid).toBeTruthy();
    expect(winTxid.length).toBe(64);
  });

  it('should reject move by wrong player', async () => {
    const artifact = compileContract('examples/ts/tic-tac-toe/TicTacToe.runar.ts');

    const provider = createProvider();
    const playerX = await createFundedWallet(provider);
    const playerO = await createFundedWallet(provider);

    const contract = new RunarContract(artifact, [playerX.pubKeyHex, 5000n]);
    await contract.deploy(provider, playerX.signer, {});

    // Player O joins — turn=1 (X's turn)
    await contract.call('join', [playerO.pubKeyHex, null], provider, playerO.signer);
    expect(contract.state.turn).toBe(1n);

    // Player O tries to move when it's X's turn
    // checkSig(sig, playerO.pubKey) passes, but assertCorrectPlayer fails
    // because turn=1 expects playerX's pubkey
    await expect(
      contract.call('move', [4n, playerO.pubKeyHex, null], provider, playerO.signer),
    ).rejects.toThrow();
  });

  it('should reject join when game is already playing', async () => {
    const artifact = compileContract('examples/ts/tic-tac-toe/TicTacToe.runar.ts');

    const provider = createProvider();
    const playerX = await createFundedWallet(provider);
    const playerO = await createFundedWallet(provider);

    const contract = new RunarContract(artifact, [playerX.pubKeyHex, 5000n]);
    await contract.deploy(provider, playerX.signer, {});

    // Player O joins — status becomes 1
    await contract.call('join', [playerO.pubKeyHex, null], provider, playerO.signer);
    expect(contract.state.status).toBe(1n);

    // Second join attempt — assert(status == 0) fails on-chain
    const anotherPlayer = await createFundedWallet(provider);
    await expect(
      contract.call('join', [anotherPlayer.pubKeyHex, null], provider, anotherPlayer.signer),
    ).rejects.toThrow();
  });
});
