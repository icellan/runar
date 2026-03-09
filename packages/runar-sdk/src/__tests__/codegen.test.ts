// ---------------------------------------------------------------------------
// codegen.test.ts — Tests for typed contract wrapper generation
// ---------------------------------------------------------------------------

import { describe, it, expect } from 'vitest';
import type { RunarArtifact } from 'runar-ir-schema';
import { generateTypescript } from '../codegen/index.js';
import {
  classifyParams,
  getUserParams,
  getSdkArgParams,
  isTerminalMethod,
  isStatefulArtifact,
  safeMethodName,
} from '../codegen/common.js';

// ---------------------------------------------------------------------------
// Fixture artifacts
// ---------------------------------------------------------------------------

const statelessArtifact: RunarArtifact = {
  version: 'runar-v0.1.0',
  compilerVersion: '0.1.0',
  contractName: 'P2PKH',
  abi: {
    constructor: {
      params: [{ name: 'pubKeyHash', type: 'Addr' }],
    },
    methods: [
      {
        name: 'unlock',
        params: [
          { name: 'sig', type: 'Sig' },
          { name: 'pubKey', type: 'PubKey' },
        ],
        isPublic: true,
      },
    ],
  },
  script: 'a9007c7c9c69007c7cac69',
  asm: 'OP_HASH160 ...',
  buildTimestamp: '2026-01-01T00:00:00.000Z',
};

const statefulArtifact: RunarArtifact = {
  version: 'runar-v0.1.0',
  compilerVersion: '0.1.0',
  contractName: 'Auction',
  abi: {
    constructor: {
      params: [
        { name: 'auctioneer', type: 'PubKey' },
        { name: 'highestBidder', type: 'PubKey' },
        { name: 'highestBid', type: 'bigint' },
        { name: 'deadline', type: 'bigint' },
      ],
    },
    methods: [
      {
        name: 'bid',
        params: [
          { name: 'sig', type: 'Sig' },
          { name: 'bidder', type: 'PubKey' },
          { name: 'bidAmount', type: 'bigint' },
          { name: '_changePKH', type: 'Ripemd160' },
          { name: '_changeAmount', type: 'bigint' },
          { name: 'txPreimage', type: 'SigHashPreimage' },
        ],
        isPublic: true,
        isTerminal: false,
      },
      {
        name: 'close',
        params: [
          { name: 'sig', type: 'Sig' },
          { name: 'txPreimage', type: 'SigHashPreimage' },
        ],
        isPublic: true,
        isTerminal: true,
      },
    ],
  },
  script: 'deadbeef',
  asm: '...',
  buildTimestamp: '2026-01-01T00:00:00.000Z',
  stateFields: [
    { name: 'highestBidder', type: 'PubKey', index: 1 },
    { name: 'highestBid', type: 'bigint', index: 2 },
  ],
};

const emptyCtorArtifact: RunarArtifact = {
  version: 'runar-v0.1.0',
  compilerVersion: '0.1.0',
  contractName: 'Simple',
  abi: {
    constructor: { params: [] },
    methods: [
      {
        name: 'execute',
        params: [{ name: 'data', type: 'ByteString' }],
        isPublic: true,
      },
    ],
  },
  script: 'cafe',
  asm: '...',
  buildTimestamp: '2026-01-01T00:00:00.000Z',
};

// ---------------------------------------------------------------------------
// common.ts unit tests
// ---------------------------------------------------------------------------

describe('codegen/common', () => {
  describe('isStatefulArtifact', () => {
    it('returns true for artifacts with stateFields', () => {
      expect(isStatefulArtifact(statefulArtifact)).toBe(true);
    });

    it('returns false for stateless artifacts', () => {
      expect(isStatefulArtifact(statelessArtifact)).toBe(false);
    });
  });

  describe('isTerminalMethod', () => {
    it('returns true for stateless contracts', () => {
      const method = statelessArtifact.abi.methods[0]!;
      expect(isTerminalMethod(method, false)).toBe(true);
    });

    it('returns true for explicit isTerminal flag', () => {
      const method = statefulArtifact.abi.methods[1]!; // close
      expect(isTerminalMethod(method, true)).toBe(true);
    });

    it('returns false for state-mutating methods', () => {
      const method = statefulArtifact.abi.methods[0]!; // bid
      expect(isTerminalMethod(method, true)).toBe(false);
    });

    it('falls back to _changePKH check for old artifacts', () => {
      const method = {
        name: 'test',
        params: [
          { name: '_changePKH', type: 'Ripemd160' },
          { name: '_changeAmount', type: 'bigint' },
          { name: 'txPreimage', type: 'SigHashPreimage' },
        ],
        isPublic: true,
        // no isTerminal field
      };
      expect(isTerminalMethod(method, true)).toBe(false);
    });
  });

  describe('classifyParams', () => {
    it('marks Sig, SigHashPreimage, _changePKH, _changeAmount as hidden for stateful', () => {
      const method = statefulArtifact.abi.methods[0]!; // bid
      const classified = classifyParams(method, true);
      const hidden = classified.filter((p) => p.hidden);
      expect(hidden.map((p) => p.name)).toEqual(['sig', '_changePKH', '_changeAmount', 'txPreimage']);
    });

    it('marks Sig as hidden even for stateless contracts', () => {
      const method = statelessArtifact.abi.methods[0]!;
      const classified = classifyParams(method, false);
      const hidden = classified.filter((p) => p.hidden);
      expect(hidden.map((p) => p.name)).toEqual(['sig']);
    });
  });

  describe('getUserParams', () => {
    it('returns only user-visible params for stateful method', () => {
      const method = statefulArtifact.abi.methods[0]!; // bid
      const userParams = getUserParams(method, true);
      expect(userParams.map((p) => p.name)).toEqual(['bidder', 'bidAmount']);
    });

    it('returns non-Sig params for stateless method', () => {
      const method = statelessArtifact.abi.methods[0]!;
      const userParams = getUserParams(method, false);
      expect(userParams.map((p) => p.name)).toEqual(['pubKey']);
    });
  });

  describe('getSdkArgParams', () => {
    it('excludes SigHashPreimage, _changePKH, _changeAmount for stateful', () => {
      const method = statefulArtifact.abi.methods[0]!; // bid
      const sdkArgs = getSdkArgParams(method, true);
      expect(sdkArgs.map((p) => p.name)).toEqual(['sig', 'bidder', 'bidAmount']);
    });

    it('keeps all params for stateless contracts', () => {
      const method = statelessArtifact.abi.methods[0]!; // unlock
      const sdkArgs = getSdkArgParams(method, false);
      expect(sdkArgs.map((p) => p.name)).toEqual(['sig', 'pubKey']);
    });

    it('keeps Sig but excludes SigHashPreimage for terminal stateful', () => {
      const method = statefulArtifact.abi.methods[1]!; // close
      const sdkArgs = getSdkArgParams(method, true);
      expect(sdkArgs.map((p) => p.name)).toEqual(['sig']);
    });
  });

  describe('safeMethodName', () => {
    it('renames reserved names', () => {
      expect(safeMethodName('connect')).toBe('callConnect');
      expect(safeMethodName('deploy')).toBe('callDeploy');
      expect(safeMethodName('contract')).toBe('callContract');
    });

    it('preserves non-reserved names', () => {
      expect(safeMethodName('bid')).toBe('bid');
      expect(safeMethodName('unlock')).toBe('unlock');
    });
  });
});

// ---------------------------------------------------------------------------
// generateTypescript tests
// ---------------------------------------------------------------------------

describe('generateTypescript', () => {
  it('generates a wrapper for a stateless contract', () => {
    const code = generateTypescript(statelessArtifact);

    expect(code).toContain('export class P2PKHContract');
    expect(code).toContain("import { RunarContract, buildP2PKHScript } from 'runar-sdk'");
    expect(code).toContain('pubKeyHash: string;');
    // Sig is hidden, only pubKey visible in main method
    expect(code).toContain('async unlock(pubKey: string | null');
    expect(code).not.toContain('async unlock(sig: string');
    // Args array passes null for hidden Sig
    expect(code).toContain("this.inner.call('unlock', [null, pubKey]");
    // prepare/finalize pair generated for Sig params
    expect(code).toContain('async prepareUnlock(pubKey: string | null, outputs?: TerminalOutput[]): Promise<PreparedCall>');
    expect(code).toContain('async finalizeUnlock(prepared: PreparedCall, sig: string): Promise<CallResult>');
    expect(code).toContain('this.inner.finalizeCall(prepared, { 0: sig })');
  });

  it('generates a wrapper for a stateful contract with terminal and state-mutating methods', () => {
    const code = generateTypescript(statefulArtifact);

    expect(code).toContain('export class AuctionContract');
    // Constructor args
    expect(code).toContain('auctioneer: string | null;');
    expect(code).toContain('highestBid: bigint;');
    expect(code).toContain('deadline: bigint;');

    // Options interface for state-mutating only
    expect(code).toContain('export interface AuctionStatefulCallOptions');

    // TerminalOutput type for terminal methods
    expect(code).toContain('export interface TerminalOutput');
    expect(code).toContain('address?: string');
    expect(code).toContain('scriptHex?: string');

    // State-mutating method — Sig hidden, only bidder + bidAmount visible
    expect(code).toContain('async bid(');
    expect(code).toContain('bidder: string | null');
    expect(code).toContain('bidAmount: bigint');
    expect(code).toContain('options?: AuctionStatefulCallOptions');
    // Args: null for sig, visible for bidder/bidAmount (SDK-implicit params excluded)
    expect(code).toContain("this.inner.call('bid', [null, bidder, bidAmount], options)");

    // Terminal method — no user params (sig hidden), takes outputs
    // Args: only sig as null (txPreimage is SDK-implicit, excluded)
    expect(code).toContain('async close(outputs: TerminalOutput[])');
    expect(code).toContain("this.inner.call('close', [null], {");
    expect(code).toContain('terminalOutputs: AuctionContract.resolveOutputs(outputs)');

    // JSDoc annotations
    expect(code).toContain('State-mutating');
    expect(code).toContain('Terminal');

    // prepare/finalize for state-mutating method (bid)
    expect(code).toContain('async prepareBid(');
    expect(code).toContain("this.inner.prepareCall('bid', [null, bidder, bidAmount], options)");
    expect(code).toContain('async finalizeBid(prepared: PreparedCall, sig: string): Promise<CallResult>');
    expect(code).toContain("this.inner.finalizeCall(prepared, { 0: sig })");

    // prepare/finalize for terminal method (close)
    expect(code).toContain('async prepareClose(outputs: TerminalOutput[]): Promise<PreparedCall>');
    expect(code).toContain("this.inner.prepareCall('close', [null], {");
    expect(code).toContain('async finalizeClose(prepared: PreparedCall, sig: string): Promise<CallResult>');
  });

  it('resolveOutputs converts address to scriptHex', () => {
    const code = generateTypescript(statefulArtifact);
    expect(code).toContain('private static resolveOutputs');
    expect(code).toContain('buildP2PKHScript(o.address!)');
  });

  it('handles empty constructor args', () => {
    const code = generateTypescript(emptyCtorArtifact);

    expect(code).toContain('constructor(artifact: RunarArtifact)');
    expect(code).not.toContain('args: {');
    expect(code).toContain('new RunarContract(artifact, [])');
  });

  it('handles method name collisions with reserved names', () => {
    const artifact: RunarArtifact = {
      ...statelessArtifact,
      contractName: 'Tricky',
      abi: {
        constructor: { params: [] },
        methods: [
          { name: 'connect', params: [], isPublic: true },
          { name: 'deploy', params: [], isPublic: true },
        ],
      },
    };

    const code = generateTypescript(artifact);

    expect(code).toContain('async callConnect(');
    expect(code).toContain('async callDeploy(');
    // Original connect/deploy methods still exist
    expect(code).toContain('connect(provider: Provider, signer: Signer)');
    expect(code).toContain('async deploy(');
  });

  it('includes deploy overloads', () => {
    const code = generateTypescript(statelessArtifact);

    expect(code).toContain('async deploy(options?: DeployOptions): Promise<CallResult>');
    expect(code).toContain(
      'async deploy(provider: Provider, signer: Signer, options?: DeployOptions): Promise<CallResult>',
    );
  });

  it('includes contract getter', () => {
    const code = generateTypescript(statelessArtifact);
    expect(code).toContain('get contract(): RunarContract');
  });

  it('generates header comment', () => {
    const code = generateTypescript(statelessArtifact);
    expect(code).toContain('// Generated by: runar codegen');
    expect(code).toContain('// Source: P2PKH');
    expect(code).toContain('// Do not edit manually.');
  });

  it('generates prepare/finalize with multiple Sig params', () => {
    const multiSigArtifact: RunarArtifact = {
      version: 'runar-v0.1.0',
      compilerVersion: '0.1.0',
      contractName: 'TicTacToe',
      abi: {
        constructor: { params: [] },
        methods: [
          {
            name: 'cancel',
            params: [
              { name: 'sigX', type: 'Sig' },
              { name: 'sigO', type: 'Sig' },
              { name: 'txPreimage', type: 'SigHashPreimage' },
            ],
            isPublic: true,
            isTerminal: true,
          },
        ],
      },
      script: 'deadbeef',
      asm: '...',
      buildTimestamp: '2026-01-01T00:00:00.000Z',
      stateFields: [{ name: 'board', type: 'bigint', index: 0 }],
    };

    const code = generateTypescript(multiSigArtifact);

    // prepareCancel takes outputs (terminal stateful), no Sig params
    // Args: [null, null] for sigX + sigO (txPreimage is SDK-implicit, excluded)
    expect(code).toContain('async prepareCancel(outputs: TerminalOutput[]): Promise<PreparedCall>');
    expect(code).toContain("this.inner.prepareCall('cancel', [null, null], {");

    // finalizeCancel takes both Sig params as strings
    expect(code).toContain('async finalizeCancel(prepared: PreparedCall, sigX: string, sigO: string): Promise<CallResult>');
    expect(code).toContain('this.inner.finalizeCall(prepared, { 0: sigX, 1: sigO })');
  });

  it('does not generate prepare/finalize for methods without Sig params', () => {
    const code = generateTypescript(emptyCtorArtifact);

    // Simple.execute has no Sig params
    expect(code).not.toContain('prepareExecute');
    expect(code).not.toContain('finalizeExecute');
  });
});
