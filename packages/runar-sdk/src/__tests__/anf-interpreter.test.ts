import { describe, it, expect } from 'vitest';
import { computeNewState } from '../anf-interpreter.js';
import type { ANFProgram } from 'runar-ir-schema';

// ---------------------------------------------------------------------------
// Helper: build a minimal ANF program
// ---------------------------------------------------------------------------

function makeANF(overrides: Partial<ANFProgram> = {}): ANFProgram {
  return {
    contractName: 'Test',
    properties: [],
    methods: [],
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Counter contract: increment / decrement
// ---------------------------------------------------------------------------

describe('ANF interpreter: Counter contract', () => {
  // Simulates: this.count = this.count + 1n
  const counterANF = makeANF({
    contractName: 'Counter',
    properties: [
      { name: 'count', type: 'bigint', readonly: false },
    ],
    methods: [
      {
        name: 'increment',
        params: [
          { name: '_changePKH', type: 'Ripemd160' },
          { name: '_changeAmount', type: 'bigint' },
          { name: '_newAmount', type: 'bigint' },
          { name: 'txPreimage', type: 'SigHashPreimage' },
        ],
        body: [
          { name: 't0', value: { kind: 'check_preimage', preimage: 'txPreimage' } },
          { name: 't1', value: { kind: 'deserialize_state', preimage: 'txPreimage' } },
          { name: 't2', value: { kind: 'load_prop', name: 'count' } },
          { name: 't3', value: { kind: 'load_const', value: 1n } },
          { name: 't4', value: { kind: 'bin_op', op: '+', left: 't2', right: 't3' } },
          { name: 't5', value: { kind: 'update_prop', name: 'count', value: 't4' } },
          { name: 't6', value: { kind: 'get_state_script' } },
          { name: 't7', value: { kind: 'add_output', satoshis: '_newAmount', stateValues: ['t4'] } },
        ],
        isPublic: true,
      },
      {
        name: 'decrement',
        params: [
          { name: '_changePKH', type: 'Ripemd160' },
          { name: '_changeAmount', type: 'bigint' },
          { name: '_newAmount', type: 'bigint' },
          { name: 'txPreimage', type: 'SigHashPreimage' },
        ],
        body: [
          { name: 't0', value: { kind: 'check_preimage', preimage: 'txPreimage' } },
          { name: 't1', value: { kind: 'deserialize_state', preimage: 'txPreimage' } },
          { name: 't2', value: { kind: 'load_prop', name: 'count' } },
          { name: 't3', value: { kind: 'load_const', value: 1n } },
          { name: 't4', value: { kind: 'bin_op', op: '-', left: 't2', right: 't3' } },
          { name: 't5', value: { kind: 'update_prop', name: 'count', value: 't4' } },
          { name: 't6', value: { kind: 'get_state_script' } },
          { name: 't7', value: { kind: 'add_output', satoshis: '_newAmount', stateValues: ['t4'] } },
        ],
        isPublic: true,
      },
    ],
  });

  it('increment: { count: 0n } → { count: 1n }', () => {
    const result = computeNewState(counterANF, 'increment', { count: 0n }, {});
    expect(result.count).toBe(1n);
  });

  it('increment: { count: 5n } → { count: 6n }', () => {
    const result = computeNewState(counterANF, 'increment', { count: 5n }, {});
    expect(result.count).toBe(6n);
  });

  it('decrement: { count: 5n } → { count: 4n }', () => {
    const result = computeNewState(counterANF, 'decrement', { count: 5n }, {});
    expect(result.count).toBe(4n);
  });

  it('decrement: { count: 0n } → { count: -1n }', () => {
    const result = computeNewState(counterANF, 'decrement', { count: 0n }, {});
    expect(result.count).toBe(-1n);
  });
});

// ---------------------------------------------------------------------------
// TicTacToe-like contract: join / move
// ---------------------------------------------------------------------------

describe('ANF interpreter: TicTacToe-like state transitions', () => {
  const ticTacToeANF = makeANF({
    contractName: 'TicTacToe',
    properties: [
      { name: 'playerX', type: 'PubKey', readonly: true },
      { name: 'betAmount', type: 'bigint', readonly: true },
      { name: 'playerO', type: 'PubKey', readonly: false },
      { name: 'c0', type: 'bigint', readonly: false },
      { name: 'c4', type: 'bigint', readonly: false },
      { name: 'turn', type: 'bigint', readonly: false },
      { name: 'status', type: 'bigint', readonly: false },
    ],
    methods: [
      {
        name: 'join',
        params: [
          { name: 'opponentPK', type: 'PubKey' },
          { name: 'sig', type: 'Sig' },
          { name: '_changePKH', type: 'Ripemd160' },
          { name: '_changeAmount', type: 'bigint' },
          { name: '_newAmount', type: 'bigint' },
          { name: 'txPreimage', type: 'SigHashPreimage' },
        ],
        body: [
          { name: 't0', value: { kind: 'check_preimage', preimage: 'txPreimage' } },
          { name: 't1', value: { kind: 'deserialize_state', preimage: 'txPreimage' } },
          // assert(this.status == 0n)
          { name: 't2', value: { kind: 'load_prop', name: 'status' } },
          { name: 't3', value: { kind: 'load_const', value: 0n } },
          { name: 't4', value: { kind: 'bin_op', op: '==', left: 't2', right: 't3' } },
          { name: 't5', value: { kind: 'assert', value: 't4' } },
          // assert(checkSig(sig, opponentPK))
          { name: 't6', value: { kind: 'load_param', name: 'sig' } },
          { name: 't7', value: { kind: 'load_param', name: 'opponentPK' } },
          { name: 't8', value: { kind: 'call', func: 'checkSig', args: ['t6', 't7'] } },
          { name: 't9', value: { kind: 'assert', value: 't8' } },
          // this.playerO = opponentPK
          { name: 't10', value: { kind: 'update_prop', name: 'playerO', value: 't7' } },
          // this.status = 1n
          { name: 't11', value: { kind: 'load_const', value: 1n } },
          { name: 't12', value: { kind: 'update_prop', name: 'status', value: 't11' } },
          // this.turn = 1n
          { name: 't13', value: { kind: 'load_const', value: 1n } },
          { name: 't14', value: { kind: 'update_prop', name: 'turn', value: 't13' } },
        ],
        isPublic: true,
      },
      {
        name: 'move',
        params: [
          { name: 'position', type: 'bigint' },
          { name: 'player', type: 'PubKey' },
          { name: 'sig', type: 'Sig' },
          { name: '_changePKH', type: 'Ripemd160' },
          { name: '_changeAmount', type: 'bigint' },
          { name: '_newAmount', type: 'bigint' },
          { name: 'txPreimage', type: 'SigHashPreimage' },
        ],
        body: [
          { name: 't0', value: { kind: 'check_preimage', preimage: 'txPreimage' } },
          { name: 't1', value: { kind: 'deserialize_state', preimage: 'txPreimage' } },
          // assert(this.status == 1n) — skipped (assert is noop)
          // assert(checkSig(sig, player)) — skipped
          // Simplified: update c0 = turn, flip turn
          { name: 't2', value: { kind: 'load_prop', name: 'turn' } },
          { name: 't3', value: { kind: 'update_prop', name: 'c0', value: 't2' } },
          // Flip turn: if turn == 1 → 2 else 1
          { name: 't4', value: { kind: 'load_prop', name: 'turn' } },
          { name: 't5', value: { kind: 'load_const', value: 1n } },
          { name: 't6', value: { kind: 'bin_op', op: '==', left: 't4', right: 't5' } },
          {
            name: 't7',
            value: {
              kind: 'if',
              cond: 't6',
              then: [{ name: 't7', value: { kind: 'load_const', value: 2n } }],
              else: [{ name: 't7', value: { kind: 'load_const', value: 1n } }],
            },
          },
          { name: 't8', value: { kind: 'update_prop', name: 'turn', value: 't7' } },
        ],
        isPublic: true,
      },
    ],
  });

  it('join: sets playerO, status=1, turn=1', () => {
    const PLAYER_O = '02' + 'bb'.repeat(32);
    const result = computeNewState(
      ticTacToeANF,
      'join',
      { playerO: '00'.repeat(33), c0: 0n, c4: 0n, turn: 0n, status: 0n },
      { opponentPK: PLAYER_O, sig: '00'.repeat(36) },
    );
    expect(result.playerO).toBe(PLAYER_O);
    expect(result.status).toBe(1n);
    expect(result.turn).toBe(1n);
  });

  it('move: updates cell and flips turn from 1 to 2', () => {
    const result = computeNewState(
      ticTacToeANF,
      'move',
      { c0: 0n, c4: 0n, turn: 1n, status: 1n },
      { position: 0n, player: '02' + 'aa'.repeat(32), sig: '00'.repeat(36) },
    );
    expect(result.c0).toBe(1n);
    expect(result.turn).toBe(2n);
  });

  it('move: flips turn from 2 to 1', () => {
    const result = computeNewState(
      ticTacToeANF,
      'move',
      { c0: 0n, c4: 0n, turn: 2n, status: 1n },
      { position: 0n, player: '02' + 'bb'.repeat(32), sig: '00'.repeat(36) },
    );
    expect(result.c0).toBe(2n);
    expect(result.turn).toBe(1n);
  });
});

// ---------------------------------------------------------------------------
// Built-in function calls
// ---------------------------------------------------------------------------

describe('ANF interpreter: builtins', () => {
  it('checkSig always returns true', () => {
    const anf = makeANF({
      properties: [{ name: 'result', type: 'bool', readonly: false }],
      methods: [{
        name: 'test',
        params: [
          { name: 'sig', type: 'Sig' },
          { name: 'pk', type: 'PubKey' },
          { name: '_changePKH', type: 'Ripemd160' },
          { name: '_changeAmount', type: 'bigint' },
          { name: 'txPreimage', type: 'SigHashPreimage' },
        ],
        body: [
          { name: 't0', value: { kind: 'load_param', name: 'sig' } },
          { name: 't1', value: { kind: 'load_param', name: 'pk' } },
          { name: 't2', value: { kind: 'call', func: 'checkSig', args: ['t0', 't1'] } },
          { name: 't3', value: { kind: 'update_prop', name: 'result', value: 't2' } },
        ],
        isPublic: true,
      }],
    });

    const result = computeNewState(anf, 'test', { result: false }, { sig: 'aa', pk: 'bb' });
    expect(result.result).toBe(true);
  });

  it('hash160 produces real hash', () => {
    const anf = makeANF({
      properties: [{ name: 'h', type: 'ByteString', readonly: false }],
      methods: [{
        name: 'test',
        params: [
          { name: 'data', type: 'ByteString' },
          { name: '_changePKH', type: 'Ripemd160' },
          { name: '_changeAmount', type: 'bigint' },
          { name: 'txPreimage', type: 'SigHashPreimage' },
        ],
        body: [
          { name: 't0', value: { kind: 'load_param', name: 'data' } },
          { name: 't1', value: { kind: 'call', func: 'hash160', args: ['t0'] } },
          { name: 't2', value: { kind: 'update_prop', name: 'h', value: 't1' } },
        ],
        isPublic: true,
      }],
    });

    const result = computeNewState(anf, 'test', { h: '' }, { data: '' });
    // hash160 of empty input should be a 20-byte (40 hex char) hash
    expect(typeof result.h).toBe('string');
    expect((result.h as string).length).toBe(40);
  });
});

// ---------------------------------------------------------------------------
// Error handling
// ---------------------------------------------------------------------------

describe('ANF interpreter: errors', () => {
  it('throws for unknown method', () => {
    const anf = makeANF({
      methods: [{
        name: 'increment',
        params: [],
        body: [],
        isPublic: true,
      }],
    });

    expect(() => computeNewState(anf, 'nonexistent', {}, {})).toThrow(
      "method 'nonexistent' not found",
    );
  });

  it('throws for private method', () => {
    const anf = makeANF({
      methods: [{
        name: 'helper',
        params: [],
        body: [],
        isPublic: false,
      }],
    });

    expect(() => computeNewState(anf, 'helper', {}, {})).toThrow(
      "method 'helper' not found",
    );
  });
});

// ---------------------------------------------------------------------------
// @ref: alias handling
// ---------------------------------------------------------------------------

describe('ANF interpreter: @ref: aliases', () => {
  it('load_const with @ref: resolves to referenced binding', () => {
    const anf = makeANF({
      properties: [{ name: 'x', type: 'bigint', readonly: false }],
      methods: [{
        name: 'test',
        params: [
          { name: '_changePKH', type: 'Ripemd160' },
          { name: '_changeAmount', type: 'bigint' },
          { name: 'txPreimage', type: 'SigHashPreimage' },
        ],
        body: [
          { name: 't0', value: { kind: 'load_const', value: 42n } },
          { name: 't1', value: { kind: 'load_const', value: '@ref:t0' } },
          { name: 't2', value: { kind: 'update_prop', name: 'x', value: 't1' } },
        ],
        isPublic: true,
      }],
    });

    const result = computeNewState(anf, 'test', { x: 0n }, {});
    expect(result.x).toBe(42n);
  });
});

// ---------------------------------------------------------------------------
// Arithmetic operations
// ---------------------------------------------------------------------------

describe('ANF interpreter: arithmetic', () => {
  function makeArithANF(op: string): ANFProgram {
    return makeANF({
      properties: [{ name: 'result', type: 'bigint', readonly: false }],
      methods: [{
        name: 'compute',
        params: [
          { name: 'a', type: 'bigint' },
          { name: 'b', type: 'bigint' },
          { name: '_changePKH', type: 'Ripemd160' },
          { name: '_changeAmount', type: 'bigint' },
          { name: 'txPreimage', type: 'SigHashPreimage' },
        ],
        body: [
          { name: 't0', value: { kind: 'load_param', name: 'a' } },
          { name: 't1', value: { kind: 'load_param', name: 'b' } },
          { name: 't2', value: { kind: 'bin_op', op, left: 't0', right: 't1' } },
          { name: 't3', value: { kind: 'update_prop', name: 'result', value: 't2' } },
        ],
        isPublic: true,
      }],
    });
  }

  it('addition', () => {
    const result = computeNewState(makeArithANF('+'), 'compute', { result: 0n }, { a: 10n, b: 20n });
    expect(result.result).toBe(30n);
  });

  it('subtraction', () => {
    const result = computeNewState(makeArithANF('-'), 'compute', { result: 0n }, { a: 20n, b: 7n });
    expect(result.result).toBe(13n);
  });

  it('multiplication', () => {
    const result = computeNewState(makeArithANF('*'), 'compute', { result: 0n }, { a: 6n, b: 7n });
    expect(result.result).toBe(42n);
  });

  it('comparison ==', () => {
    const result = computeNewState(makeArithANF('=='), 'compute', { result: 0n }, { a: 5n, b: 5n });
    expect(result.result).toBe(true);
  });

  it('comparison !=', () => {
    const result = computeNewState(makeArithANF('!='), 'compute', { result: 0n }, { a: 5n, b: 3n });
    expect(result.result).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Implicit state via add_output stateValues
// ---------------------------------------------------------------------------

describe('ANF interpreter: add_output implicit state', () => {
  it('FungibleToken.send: owner changes via stateValues', () => {
    const anf = makeANF({
      contractName: 'FungibleToken',
      properties: [
        { name: 'owner', type: 'PubKey', readonly: false },
        { name: 'balance', type: 'bigint', readonly: false },
        { name: 'mergeBalance', type: 'bigint', readonly: false },
        { name: 'tokenId', type: 'ByteString', readonly: true },
      ],
      methods: [{
        name: 'send',
        params: [
          { name: 'sig', type: 'Sig' },
          { name: 'to', type: 'PubKey' },
          { name: 'outputSatoshis', type: 'bigint' },
          { name: '_changePKH', type: 'Ripemd160' },
          { name: '_changeAmount', type: 'bigint' },
          { name: '_newAmount', type: 'bigint' },
          { name: 'txPreimage', type: 'SigHashPreimage' },
        ],
        body: [
          { name: 't0', value: { kind: 'check_preimage', preimage: 'txPreimage' } },
          { name: 't1', value: { kind: 'deserialize_state', preimage: 'txPreimage' } },
          { name: 't5', value: { kind: 'load_param', name: 'outputSatoshis' } },
          { name: 't6', value: { kind: 'load_param', name: 'to' } },
          { name: 't7', value: { kind: 'load_prop', name: 'balance' } },
          { name: 't8', value: { kind: 'load_prop', name: 'mergeBalance' } },
          { name: 't9', value: { kind: 'bin_op', op: '+', left: 't7', right: 't8' } },
          { name: 't10', value: { kind: 'load_const', value: 0n } },
          { name: 't11', value: { kind: 'add_output', satoshis: 't5', stateValues: ['t6', 't9', 't10'], preimage: '' } },
        ],
        isPublic: true,
      }],
    });

    const result = computeNewState(
      anf, 'send',
      { owner: '02' + 'aa'.repeat(32), balance: 1000n, mergeBalance: 0n, tokenId: 'abcd' },
      { sig: null, to: '02' + 'bb'.repeat(32), outputSatoshis: 1n },
    );
    expect(result.owner).toBe('02' + 'bb'.repeat(32));
    expect(result.balance).toBe(1000n);
    expect(result.mergeBalance).toBe(0n);
    expect(result.tokenId).toBe('abcd'); // readonly, unchanged
  });

  it('NFT.transfer: owner changes via stateValues', () => {
    const anf = makeANF({
      contractName: 'SimpleNFT',
      properties: [
        { name: 'owner', type: 'PubKey', readonly: false },
        { name: 'tokenId', type: 'ByteString', readonly: true },
        { name: 'metadata', type: 'ByteString', readonly: true },
      ],
      methods: [{
        name: 'transfer',
        params: [
          { name: 'sig', type: 'Sig' },
          { name: 'newOwner', type: 'PubKey' },
          { name: 'outputSatoshis', type: 'bigint' },
          { name: '_changePKH', type: 'Ripemd160' },
          { name: '_changeAmount', type: 'bigint' },
          { name: '_newAmount', type: 'bigint' },
          { name: 'txPreimage', type: 'SigHashPreimage' },
        ],
        body: [
          { name: 't0', value: { kind: 'check_preimage', preimage: 'txPreimage' } },
          { name: 't1', value: { kind: 'deserialize_state', preimage: 'txPreimage' } },
          { name: 't5', value: { kind: 'load_param', name: 'outputSatoshis' } },
          { name: 't6', value: { kind: 'load_param', name: 'newOwner' } },
          { name: 't7', value: { kind: 'add_output', satoshis: 't5', stateValues: ['t6'], preimage: '' } },
        ],
        isPublic: true,
      }],
    });

    const result = computeNewState(
      anf, 'transfer',
      { owner: '02' + 'aa'.repeat(32), tokenId: 'nft1', metadata: 'meta1' },
      { sig: null, newOwner: '02' + 'cc'.repeat(32), outputSatoshis: 1n },
    );
    expect(result.owner).toBe('02' + 'cc'.repeat(32));
    expect(result.tokenId).toBe('nft1'); // readonly, unchanged
    expect(result.metadata).toBe('meta1'); // readonly, unchanged
  });
});

// ---------------------------------------------------------------------------
// Private method calls (method_call on private methods with bodies)
// ---------------------------------------------------------------------------

describe('ANF interpreter: private method calls', () => {
  it('FunctionPatterns.withdraw: computeFee resolved from private method', () => {
    const anf = makeANF({
      contractName: 'FunctionPatterns',
      properties: [
        { name: 'owner', type: 'PubKey', readonly: true },
        { name: 'balance', type: 'bigint', readonly: false },
      ],
      methods: [
        {
          name: 'withdraw',
          params: [
            { name: 'sig', type: 'Sig' },
            { name: 'amount', type: 'bigint' },
            { name: 'feeBps', type: 'bigint' },
            { name: '_changePKH', type: 'Ripemd160' },
            { name: '_changeAmount', type: 'bigint' },
            { name: '_newAmount', type: 'bigint' },
            { name: 'txPreimage', type: 'SigHashPreimage' },
          ],
          body: [
            { name: 't0', value: { kind: 'check_preimage', preimage: 'txPreimage' } },
            { name: 't1', value: { kind: 'deserialize_state', preimage: 'txPreimage' } },
            // method_call to computeFee (private method)
            { name: 't12', value: { kind: 'load_param', name: 'amount' } },
            { name: 't13', value: { kind: 'load_param', name: 'feeBps' } },
            { name: 't14', value: { kind: 'load_const', value: '@this' } },
            { name: 't15', value: { kind: 'method_call', object: 't14', method: 'computeFee', args: ['t12', 't13'] } },
            { name: 'fee', value: { kind: 'load_const', value: '@ref:t15' } },
            { name: 't16', value: { kind: 'load_param', name: 'amount' } },
            { name: 't17', value: { kind: 'bin_op', op: '+', left: 't16', right: 'fee' } },
            { name: 'total', value: { kind: 'load_const', value: '@ref:t17' } },
            { name: 't21', value: { kind: 'load_prop', name: 'balance' } },
            { name: 't22', value: { kind: 'bin_op', op: '-', left: 't21', right: 'total' } },
            { name: 't23', value: { kind: 'update_prop', name: 'balance', value: 't22' } },
          ],
          isPublic: true,
        },
        {
          // Private method: computeFee(amount, feeBps) -> percentOf(amount, feeBps)
          name: 'computeFee',
          params: [
            { name: 'amount', type: 'bigint' },
            { name: 'feeBps', type: 'bigint' },
          ],
          body: [
            { name: 't0', value: { kind: 'load_param', name: 'amount' } },
            { name: 't1', value: { kind: 'load_param', name: 'feeBps' } },
            { name: 't2', value: { kind: 'call', func: 'percentOf', args: ['t0', 't1'] } },
          ],
          isPublic: false,
        },
      ],
    });

    const result = computeNewState(
      anf, 'withdraw',
      { owner: '02' + 'aa'.repeat(32), balance: 1500n },
      { sig: null, amount: 200n, feeBps: 100n },
    );
    // percentOf(200, 100) = (200 * 100) / 10000 = 2 (100 bps = 1%)
    // total = 200 + 2 = 202
    // balance = 1500 - 202 = 1298
    expect(result.balance).toBe(1298n);
  });

  it('void private method (requireOwner) returns undefined without breaking', () => {
    const anf = makeANF({
      contractName: 'FunctionPatterns',
      properties: [
        { name: 'owner', type: 'PubKey', readonly: true },
        { name: 'balance', type: 'bigint', readonly: false },
      ],
      methods: [
        {
          name: 'deposit',
          params: [
            { name: 'sig', type: 'Sig' },
            { name: 'amount', type: 'bigint' },
            { name: '_changePKH', type: 'Ripemd160' },
            { name: '_changeAmount', type: 'bigint' },
            { name: '_newAmount', type: 'bigint' },
            { name: 'txPreimage', type: 'SigHashPreimage' },
          ],
          body: [
            { name: 't5', value: { kind: 'load_param', name: 'sig' } },
            { name: 't6', value: { kind: 'load_const', value: '@this' } },
            { name: 't7', value: { kind: 'method_call', object: 't6', method: 'requireOwner', args: ['t5'] } },
            { name: 't12', value: { kind: 'load_prop', name: 'balance' } },
            { name: 't13', value: { kind: 'load_param', name: 'amount' } },
            { name: 't14', value: { kind: 'bin_op', op: '+', left: 't12', right: 't13' } },
            { name: 't15', value: { kind: 'update_prop', name: 'balance', value: 't14' } },
          ],
          isPublic: true,
        },
        {
          name: 'requireOwner',
          params: [{ name: 'sig', type: 'Sig' }],
          body: [
            { name: 't0', value: { kind: 'load_param', name: 'sig' } },
            { name: 't1', value: { kind: 'load_prop', name: 'owner' } },
            { name: 't2', value: { kind: 'call', func: 'checkSig', args: ['t0', 't1'] } },
            { name: 't3', value: { kind: 'assert', value: 't2' } },
          ],
          isPublic: false,
        },
      ],
    });

    const result = computeNewState(
      anf, 'deposit',
      { owner: '02' + 'aa'.repeat(32), balance: 100n },
      { sig: null, amount: 50n },
    );
    expect(result.balance).toBe(150n);
  });
});

// ---------------------------------------------------------------------------
// Preserves unmodified state
// ---------------------------------------------------------------------------

describe('ANF interpreter: preserves unmodified state', () => {
  it('properties not touched by update_prop remain unchanged', () => {
    const anf = makeANF({
      properties: [
        { name: 'a', type: 'bigint', readonly: false },
        { name: 'b', type: 'bigint', readonly: false },
      ],
      methods: [{
        name: 'updateA',
        params: [
          { name: '_changePKH', type: 'Ripemd160' },
          { name: '_changeAmount', type: 'bigint' },
          { name: 'txPreimage', type: 'SigHashPreimage' },
        ],
        body: [
          { name: 't0', value: { kind: 'load_const', value: 99n } },
          { name: 't1', value: { kind: 'update_prop', name: 'a', value: 't0' } },
        ],
        isPublic: true,
      }],
    });

    const result = computeNewState(anf, 'updateA', { a: 1n, b: 42n }, {});
    expect(result.a).toBe(99n);
    expect(result.b).toBe(42n);
  });
});

// ---------------------------------------------------------------------------
// num2bin / bin2num roundtrip (row 470)
// ---------------------------------------------------------------------------

describe('ANF interpreter: num2bin / bin2num roundtrip', () => {
  it('num2bin(42, 4) produces 4-byte little-endian hex "2a000000"', () => {
    // Build an ANF program that calls num2bin and stores the result in state.
    const anf = makeANF({
      contractName: 'Num2BinTest',
      properties: [
        { name: 'result', type: 'ByteString', readonly: false },
      ],
      methods: [{
        name: 'run',
        params: [],
        body: [
          { name: 't0', value: { kind: 'load_const', value: 42n } },
          { name: 't1', value: { kind: 'load_const', value: 4n } },
          { name: 't2', value: { kind: 'call', func: 'num2bin', args: ['t0', 't1'] } },
          { name: 't3', value: { kind: 'update_prop', name: 'result', value: 't2' } },
        ],
        isPublic: true,
      }],
    });

    const state = computeNewState(anf, 'run', { result: '' }, {});
    expect(state.result).toBe('2a000000');
  });

  it('bin2num("2a000000") produces 42n', () => {
    // Build an ANF program that calls bin2num on a hex value and stores result.
    const anf = makeANF({
      contractName: 'Bin2NumTest',
      properties: [
        { name: 'result', type: 'bigint', readonly: false },
      ],
      methods: [{
        name: 'run',
        params: [],
        body: [
          { name: 't0', value: { kind: 'load_const', value: '2a000000' } },
          { name: 't1', value: { kind: 'call', func: 'bin2num', args: ['t0'] } },
          { name: 't2', value: { kind: 'update_prop', name: 'result', value: 't1' } },
        ],
        isPublic: true,
      }],
    });

    const state = computeNewState(anf, 'run', { result: 0n }, {});
    expect(state.result).toBe(42n);
  });

  it('num2bin/bin2num round-trip preserves value for various inputs', () => {
    // Test that bin2num(num2bin(n, 8)) === n for several values.
    const testCases: [bigint, number][] = [
      [0n, 4],
      [1n, 4],
      [255n, 4],
      [1000n, 4],
      [0xdeadn, 8],
    ];

    for (const [n, size] of testCases) {
      const num2binANF = makeANF({
        contractName: 'RoundTrip',
        properties: [{ name: 'result', type: 'bigint', readonly: false }],
        methods: [{
          name: 'run',
          params: [],
          body: [
            { name: 'n', value: { kind: 'load_const', value: n } },
            { name: 's', value: { kind: 'load_const', value: BigInt(size) } },
            { name: 'encoded', value: { kind: 'call', func: 'num2bin', args: ['n', 's'] } },
            { name: 'decoded', value: { kind: 'call', func: 'bin2num', args: ['encoded'] } },
            { name: 'upd', value: { kind: 'update_prop', name: 'result', value: 'decoded' } },
          ],
          isPublic: true,
        }],
      });
      const state = computeNewState(num2binANF, 'run', { result: 0n }, {});
      expect(state.result).toBe(n);
    }
  });
});
