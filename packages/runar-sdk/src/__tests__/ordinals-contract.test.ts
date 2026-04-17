import { describe, it, expect } from 'vitest';
import { RunarContract } from '../contract.js';
import { findLastOpReturn } from '../state.js';
import {
  buildInscriptionEnvelope,
  parseInscriptionEnvelope,
  findInscriptionEnvelope,
} from '../ordinals/envelope.js';
import { BSV20 } from '../ordinals/bsv20.js';
import type { RunarArtifact } from 'runar-ir-schema';

/** Convert a UTF-8 string to hex. */
function utf8ToHex(str: string): string {
  return Array.from(new TextEncoder().encode(str))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

// Minimal P2PKH artifact (stateless)
const p2pkhArtifact: RunarArtifact = {
  version: 'runar-v0.1.0',
  compilerVersion: '0.4.4',
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
  asm: 'OP_HASH160 OP_0 OP_SWAP OP_SWAP OP_NUMEQUAL OP_VERIFY OP_0 OP_SWAP OP_SWAP OP_CHECKSIG OP_VERIFY',
  constructorSlots: [
    { paramIndex: 0, byteOffset: 1 },
    { paramIndex: 0, byteOffset: 6 },
  ],
  buildTimestamp: '2026-01-01T00:00:00.000Z',
};

// Minimal Counter artifact (stateful)
const counterArtifact: RunarArtifact = {
  version: 'runar-v0.1.0',
  compilerVersion: '0.4.4',
  contractName: 'Counter',
  abi: {
    constructor: {
      params: [{ name: 'count', type: 'bigint' }],
    },
    methods: [
      {
        name: 'increment',
        params: [
          { name: '_changePKH', type: 'Addr' },
          { name: '_changeAmount', type: 'bigint' },
          { name: 'txPreimage', type: 'SigHashPreimage' },
        ],
        isPublic: true,
      },
    ],
  },
  // Fake minimal script — just enough to test envelope splicing
  script: 'aabbccdd',
  asm: 'OP_NOP',
  stateFields: [
    { name: 'count', type: 'bigint', index: 0 },
  ],
  buildTimestamp: '2026-01-01T00:00:00.000Z',
};

describe('RunarContract with inscription (stateless)', () => {
  it('getLockingScript includes inscription envelope', () => {
    const pubKeyHash = '00'.repeat(20);
    const contract = new RunarContract(p2pkhArtifact, [pubKeyHash]);
    contract.withInscription({
      contentType: 'text/plain',
      data: utf8ToHex('Hello!'),
    });

    const lockingScript = contract.getLockingScript();

    // The locking script should end with the inscription envelope
    const envelope = buildInscriptionEnvelope('text/plain', utf8ToHex('Hello!'));
    expect(lockingScript.endsWith(envelope)).toBe(true);

    // Should be parseable
    const parsed = parseInscriptionEnvelope(lockingScript);
    expect(parsed).not.toBeNull();
    expect(parsed!.contentType).toBe('text/plain');
    expect(parsed!.data).toBe(utf8ToHex('Hello!'));
  });

  it('getLockingScript without inscription is unchanged', () => {
    const pubKeyHash = '00'.repeat(20);
    const contractA = new RunarContract(p2pkhArtifact, [pubKeyHash]);
    const contractB = new RunarContract(p2pkhArtifact, [pubKeyHash]);

    // No inscription — should produce identical scripts
    expect(contractA.getLockingScript()).toBe(contractB.getLockingScript());
  });

  it('withInscription returns this for chaining', () => {
    const contract = new RunarContract(p2pkhArtifact, ['00'.repeat(20)]);
    const result = contract.withInscription({ contentType: 'text/plain', data: '' });
    expect(result).toBe(contract);
  });

  it('inscription getter returns the stored inscription', () => {
    const contract = new RunarContract(p2pkhArtifact, ['00'.repeat(20)]);
    expect(contract.inscription).toBeNull();
    contract.withInscription({ contentType: 'image/png', data: 'ff00ff' });
    expect(contract.inscription).toEqual({ contentType: 'image/png', data: 'ff00ff' });
  });
});

describe('RunarContract with inscription (stateful)', () => {
  it('getLockingScript places envelope between code and OP_RETURN', () => {
    const contract = new RunarContract(counterArtifact, [0n]);
    contract.withInscription({
      contentType: 'application/bsv-20',
      data: utf8ToHex('{"p":"bsv-20","op":"deploy","tick":"TEST","max":"1000"}'),
    });

    const lockingScript = contract.getLockingScript();
    const envelope = buildInscriptionEnvelope(
      'application/bsv-20',
      utf8ToHex('{"p":"bsv-20","op":"deploy","tick":"TEST","max":"1000"}'),
    );

    // Script structure: code + envelope + OP_RETURN + state
    // The artifact script is 'aabbccdd' (4 bytes / 8 hex chars)
    const codeEnd = lockingScript.indexOf(envelope);
    expect(codeEnd).toBeGreaterThan(0); // envelope follows code

    const afterEnvelope = lockingScript.slice(codeEnd + envelope.length);
    expect(afterEnvelope.startsWith('6a')).toBe(true); // OP_RETURN follows envelope
  });

  it('findLastOpReturn correctly skips envelope and finds real OP_RETURN', () => {
    const contract = new RunarContract(counterArtifact, [42n]);
    contract.withInscription({
      contentType: 'text/plain',
      data: utf8ToHex('test'),
    });

    const lockingScript = contract.getLockingScript();
    const opReturnPos = findLastOpReturn(lockingScript);

    expect(opReturnPos).toBeGreaterThan(0);
    // Everything before OP_RETURN should include both the code and the envelope
    const codePart = lockingScript.slice(0, opReturnPos);
    expect(codePart).toContain('aabbccdd'); // original code
    expect(findInscriptionEnvelope(codePart)).not.toBeNull(); // envelope present
  });
});

describe('RunarContract.fromUtxo with inscription', () => {
  it('detects inscription from stateless UTXO', () => {
    const pubKeyHash = '00'.repeat(20);
    const original = new RunarContract(p2pkhArtifact, [pubKeyHash]);
    original.withInscription({
      contentType: 'image/png',
      data: 'deadbeef',
    });

    const lockingScript = original.getLockingScript();
    const reconnected = RunarContract.fromUtxo(p2pkhArtifact, {
      txid: '00'.repeat(32),
      outputIndex: 0,
      satoshis: 1,
      script: lockingScript,
    });

    expect(reconnected.inscription).not.toBeNull();
    expect(reconnected.inscription!.contentType).toBe('image/png');
    expect(reconnected.inscription!.data).toBe('deadbeef');
  });

  it('detects inscription and state from stateful UTXO', () => {
    const original = new RunarContract(counterArtifact, [7n]);
    original.withInscription({
      contentType: 'text/plain',
      data: utf8ToHex('my counter'),
    });

    const lockingScript = original.getLockingScript();
    const reconnected = RunarContract.fromUtxo(counterArtifact, {
      txid: '00'.repeat(32),
      outputIndex: 0,
      satoshis: 1,
      script: lockingScript,
    });

    // Inscription round-trips
    expect(reconnected.inscription).not.toBeNull();
    expect(reconnected.inscription!.contentType).toBe('text/plain');
    expect(reconnected.inscription!.data).toBe(utf8ToHex('my counter'));

    // State round-trips
    expect(reconnected.state.count).toBe(7n);
  });

  it('produces identical locking script on reconnected stateful contract', () => {
    const original = new RunarContract(counterArtifact, [99n]);
    original.withInscription({
      contentType: 'text/plain',
      data: utf8ToHex('persisted'),
    });

    const lockingScript = original.getLockingScript();
    const reconnected = RunarContract.fromUtxo(counterArtifact, {
      txid: '00'.repeat(32),
      outputIndex: 0,
      satoshis: 1,
      script: lockingScript,
    });

    // Reconnected contract should produce the same locking script
    expect(reconnected.getLockingScript()).toBe(lockingScript);
  });

  it('fromUtxo with no inscription sets inscription to null', () => {
    const contract = new RunarContract(p2pkhArtifact, ['00'.repeat(20)]);
    const lockingScript = contract.getLockingScript();

    const reconnected = RunarContract.fromUtxo(p2pkhArtifact, {
      txid: '00'.repeat(32),
      outputIndex: 0,
      satoshis: 1,
      script: lockingScript,
    });

    expect(reconnected.inscription).toBeNull();
  });
});

describe('BSV-20 integration with RunarContract', () => {
  it('deploys a P2PKH contract with BSV-20 deploy inscription', () => {
    const inscription = BSV20.deploy({ tick: 'RUNAR', max: '21000000' });
    const contract = new RunarContract(p2pkhArtifact, ['00'.repeat(20)]);
    contract.withInscription(inscription);

    const lockingScript = contract.getLockingScript();
    const parsed = parseInscriptionEnvelope(lockingScript);

    expect(parsed).not.toBeNull();
    expect(parsed!.contentType).toBe('application/bsv-20');

    // Verify the JSON content
    const json = JSON.parse(
      new TextDecoder().decode(
        new Uint8Array(
          parsed!.data.match(/.{2}/g)!.map((b) => parseInt(b, 16)),
        ),
      ),
    );
    expect(json.p).toBe('bsv-20');
    expect(json.op).toBe('deploy');
    expect(json.tick).toBe('RUNAR');
  });
});
