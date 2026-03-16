import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { TestContract, ALICE, BOB, signTestMessage } from 'runar-testing';

// ---------------------------------------------------------------------------
// Byte-level helpers for pre-computing terminal method output hashes.
// Used to configure setMockPreimageBytes so hash256(payout) == extractOutputHash.
// ---------------------------------------------------------------------------

function hexToU8(hex: string): Uint8Array {
  const buf = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) buf[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  return buf;
}
function catU8(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((s, a) => s + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) { out.set(a, off); off += a.length; }
  return out;
}
function num2binU8(v: bigint, len: bigint): Uint8Array {
  const buf = new Uint8Array(Number(len));
  let abs = v < 0n ? -v : v;
  for (let i = 0; i < Number(len) && abs > 0n; i++) { buf[i] = Number(abs & 0xffn); abs >>= 8n; }
  if (v < 0n) buf[Number(len) - 1] |= 0x80;
  return buf;
}
function hash160U8(data: Uint8Array): Uint8Array {
  const sha = createHash('sha256').update(data).digest();
  return new Uint8Array(createHash('ripemd160').update(sha).digest());
}
function hash256U8(data: Uint8Array): Uint8Array {
  const h1 = createHash('sha256').update(data).digest();
  return new Uint8Array(createHash('sha256').update(h1).digest());
}
function p2pkhOutput(satoshis: bigint, playerHex: string, prefixHex: string, suffixHex: string): Uint8Array {
  return catU8(num2binU8(satoshis, 8n), hexToU8(prefixHex), hash160U8(hexToU8(playerHex)), hexToU8(suffixHex));
}

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'TicTacToe.runar.ts'), 'utf8');

const PLAYER_X = ALICE.pubKey;
const PLAYER_O = BOB.pubKey;
const ZERO_PK = '00'.repeat(33);
const SIG_X = signTestMessage(ALICE.privKey);
const SIG_O = signTestMessage(BOB.privKey);
const BET_AMOUNT = 1000n;
const P2PKH_PREFIX = '1976a914';
const P2PKH_SUFFIX = '88ac';

function makeGame(overrides: Record<string, unknown> = {}) {
  return TestContract.fromSource(source, {
    playerX: PLAYER_X,
    betAmount: BET_AMOUNT,
    p2pkhPrefix: P2PKH_PREFIX,
    p2pkhSuffix: P2PKH_SUFFIX,
    playerO: ZERO_PK,
    c0: 0n, c1: 0n, c2: 0n,
    c3: 0n, c4: 0n, c5: 0n,
    c6: 0n, c7: 0n, c8: 0n,
    turn: 0n,
    status: 0n,
    ...overrides,
  });
}

function makePlayingGame(overrides: Record<string, unknown> = {}) {
  return makeGame({
    playerO: PLAYER_O,
    status: 1n,
    turn: 1n,
    ...overrides,
  });
}

describe('TicTacToe', () => {
  describe('join', () => {
    it('allows player O to join a waiting game', () => {
      const game = makeGame();
      const result = game.call('join', { opponentPK: PLAYER_O, sig: SIG_O });
      expect(result.success).toBe(true);
      expect(game.state.playerO).toBe(PLAYER_O);
      expect(game.state.status).toBe(1n);
      expect(game.state.turn).toBe(1n);
    });

    it('rejects join when game is already playing', () => {
      const game = makePlayingGame();
      const result = game.call('join', { opponentPK: PLAYER_O, sig: SIG_O });
      expect(result.success).toBe(false);
    });
  });

  describe('move', () => {
    it('allows player X to place a mark on an empty cell', () => {
      const game = makePlayingGame();
      const result = game.call('move', { position: 0n, player: PLAYER_X, sig: SIG_X });
      expect(result.success).toBe(true);
      expect(game.state.c0).toBe(1n);
      expect(game.state.turn).toBe(2n);
    });

    it('allows player O to place a mark on their turn', () => {
      const game = makePlayingGame({ turn: 2n });
      const result = game.call('move', { position: 4n, player: PLAYER_O, sig: SIG_O });
      expect(result.success).toBe(true);
      expect(game.state.c4).toBe(2n);
      expect(game.state.turn).toBe(1n);
    });

    it('rejects move on an occupied cell', () => {
      const game = makePlayingGame({ c0: 1n });
      const result = game.call('move', { position: 0n, player: PLAYER_X, sig: SIG_X });
      expect(result.success).toBe(false);
    });

    it('rejects move when game is not playing', () => {
      const game = makeGame();
      const result = game.call('move', { position: 0n, player: PLAYER_X, sig: SIG_X });
      expect(result.success).toBe(false);
    });

    it('tracks state across multiple moves', () => {
      const game = makePlayingGame();
      game.call('move', { position: 0n, player: PLAYER_X, sig: SIG_X });
      expect(game.state.c0).toBe(1n);
      expect(game.state.turn).toBe(2n);

      game.call('move', { position: 4n, player: PLAYER_O, sig: SIG_O });
      expect(game.state.c4).toBe(2n);
      expect(game.state.turn).toBe(1n);

      game.call('move', { position: 8n, player: PLAYER_X, sig: SIG_X });
      expect(game.state.c8).toBe(1n);
      expect(game.state.turn).toBe(2n);
    });
  });

  describe('moveAndWin', () => {
    it('succeeds when the move completes a row win', () => {
      const game = makePlayingGame({
        c0: 1n, c1: 1n,
        c3: 2n, c4: 2n,
        turn: 1n,
      });
      // Pre-compute the payout hash so extractOutputHash returns it.
      const payout = p2pkhOutput(BET_AMOUNT * 2n, PLAYER_X, P2PKH_PREFIX, P2PKH_SUFFIX);
      game.setMockPreimageBytes({ outputHash: hash256U8(payout) });
      const result = game.call('moveAndWin', { position: 2n, player: PLAYER_X, sig: SIG_X, changePKH: '00', changeAmount: 0n });
      if (!result.success) console.error('moveAndWin error:', result.error);
      expect(result.success).toBe(true);
    });
  });

  describe('moveAndTie', () => {
    it('succeeds when the board becomes full with no winner', () => {
      const game = makePlayingGame({
        c0: 1n, c1: 2n, c2: 1n,
        c3: 1n, c4: 1n, c5: 2n,
        c6: 2n, c7: 1n,
        turn: 2n,
      });
      // Pre-compute the tie payout hash (split between both players).
      const out1 = p2pkhOutput(BET_AMOUNT, PLAYER_X, P2PKH_PREFIX, P2PKH_SUFFIX);
      const out2 = p2pkhOutput(BET_AMOUNT, PLAYER_O, P2PKH_PREFIX, P2PKH_SUFFIX);
      game.setMockPreimageBytes({ outputHash: hash256U8(catU8(out1, out2)) });
      const result = game.call('moveAndTie', { position: 8n, player: PLAYER_O, sig: SIG_O, changePKH: '00', changeAmount: 0n });
      expect(result.success).toBe(true);
    });
  });

  describe('full game flow', () => {
    it('plays through join + moves + X wins top row', () => {
      const game = makeGame();
      const joinResult = game.call('join', { opponentPK: PLAYER_O, sig: SIG_O });
      expect(joinResult.success).toBe(true);
      expect(game.state.status).toBe(1n);

      // X@0, O@3, X@1, O@4 — set up X to win with position 2 (top row)
      game.call('move', { position: 0n, player: PLAYER_X, sig: SIG_X });
      expect(game.state.c0).toBe(1n);

      game.call('move', { position: 3n, player: PLAYER_O, sig: SIG_O });
      expect(game.state.c3).toBe(2n);

      game.call('move', { position: 1n, player: PLAYER_X, sig: SIG_X });
      expect(game.state.c1).toBe(1n);

      game.call('move', { position: 4n, player: PLAYER_O, sig: SIG_O });
      expect(game.state.c4).toBe(2n);
      expect(game.state.turn).toBe(1n); // X's turn

      // X plays position 2 to win top row (0,1,2).
      // Pre-compute payout hash so extractOutputHash returns the right value.
      const payout = p2pkhOutput(BET_AMOUNT * 2n, PLAYER_X, P2PKH_PREFIX, P2PKH_SUFFIX);
      game.setMockPreimageBytes({ outputHash: hash256U8(payout) });
      const winResult = game.call('moveAndWin', { position: 2n, player: PLAYER_X, sig: SIG_X, changePKH: '00', changeAmount: 0n });
      expect(winResult.success).toBe(true);
    });
  });
});
