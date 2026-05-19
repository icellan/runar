// ---------------------------------------------------------------------------
// runar-sdk/__tests__/script-size-guard.test.ts
//
// Item 8 — deploy/call/provider entry points reject scripts that exceed
// InputLimits.MAX_SCRIPT_BYTES with a typed ScriptSizeExceededError BEFORE
// any signing / broadcast work happens.
// ---------------------------------------------------------------------------

import { describe, it, expect } from 'vitest';
import { InputLimits } from 'runar-ir-schema';
import { RunarContract } from '../contract.js';
import { MockProvider } from '../providers/mock.js';
import { LocalSigner } from '../signers/local.js';
import { ScriptSizeExceededError } from '../errors.js';
import type { RunarArtifact, UTXO } from '../index.js';

const PRIV_KEY =
  '0000000000000000000000000000000000000000000000000000000000000001';

function makeArtifact(scriptHex: string): RunarArtifact {
  return {
    version: 'runar-v0.1.0',
    compilerVersion: '0.1.0',
    contractName: 'OversizedContract',
    asm: '',
    buildTimestamp: '2026-05-18T00:00:00.000Z',
    script: scriptHex,
    abi: { constructor: { params: [] }, methods: [] },
  };
}

async function setupSigner(): Promise<LocalSigner> {
  return new LocalSigner(PRIV_KEY);
}

function makeFundingUtxo(satoshis: number): UTXO {
  return {
    txid: 'aa'.repeat(32),
    outputIndex: 0,
    satoshis,
    script: '76a914' + '00'.repeat(20) + '88ac',
  };
}

// One hex byte = 2 hex chars. To exceed MAX_SCRIPT_BYTES (1 MiB) the hex
// string must contain (limit + 1) * 2 hex chars. Keep tests small by
// generating with String.repeat — 2 MiB of hex chars is cheap.
function oversizedScriptHex(): string {
  return '51'.repeat(InputLimits.MAX_SCRIPT_BYTES + 1);
}

function atLimitScriptHex(): string {
  return '51'.repeat(InputLimits.MAX_SCRIPT_BYTES);
}

describe('Item 8 — ScriptSizeExceededError at SDK entry points', () => {
  // -------------------------------------------------------------------------
  // deploy()
  // -------------------------------------------------------------------------

  it('deploy: rejects a locking script over MAX_SCRIPT_BYTES with typed error', async () => {
    const signer = await setupSigner();
    const address = await signer.getAddress();
    const provider = new MockProvider();
    provider.addUtxo(address, makeFundingUtxo(100_000));

    const contract = new RunarContract(makeArtifact(oversizedScriptHex()), []);
    let caught: unknown = null;
    try {
      await contract.deploy(provider, signer, { satoshis: 1_000 });
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(ScriptSizeExceededError);
    const err = caught as ScriptSizeExceededError;
    expect(err.limit).toBe(InputLimits.MAX_SCRIPT_BYTES);
    expect(err.actual).toBe(InputLimits.MAX_SCRIPT_BYTES + 1);
    expect(err.context).toContain('OversizedContract.deploy');
    expect(err.message).toContain(`limit=${InputLimits.MAX_SCRIPT_BYTES}`);
    expect(err.message).toContain(`actual=${InputLimits.MAX_SCRIPT_BYTES + 1}`);

    // No broadcast should have happened — guard fires BEFORE signing/broadcast.
    expect(provider.getBroadcastedTxs().length).toBe(0);
  });

  it('deploy: a script exactly at MAX_SCRIPT_BYTES passes the size guard', async () => {
    const signer = await setupSigner();
    const address = await signer.getAddress();
    const provider = new MockProvider();
    // Large funding to cover the giant deploy script's fee.
    provider.addUtxo(address, makeFundingUtxo(50_000_000));

    const contract = new RunarContract(makeArtifact(atLimitScriptHex()), []);
    // We only assert the size guard passes — downstream tx building / signing
    // may have its own opinions on giant scripts and that's fine, what
    // matters is the typed error is NOT thrown.
    let sizeErr: unknown = null;
    try {
      await contract.deploy(provider, signer, { satoshis: 1_000 });
    } catch (err) {
      if (err instanceof ScriptSizeExceededError) sizeErr = err;
    }
    expect(sizeErr).toBeNull();
  }, 60_000);

  // -------------------------------------------------------------------------
  // call()
  // -------------------------------------------------------------------------

  it('call: rejects a current locking script over MAX_SCRIPT_BYTES BEFORE signing', async () => {
    const signer = await setupSigner();
    const address = await signer.getAddress();
    const provider = new MockProvider();
    provider.addUtxo(address, makeFundingUtxo(100_000));

    // Use a minimal artifact (small script) so deploy succeeds, then manually
    // poison the contract's currentUtxo with an oversized script to simulate
    // a malicious / corrupted reconnect.
    const artifact = makeArtifact('51');
    artifact.abi.methods = [{ name: 'spend', params: [], isPublic: true }];
    const contract = new RunarContract(artifact, []);
    await contract.deploy(provider, signer, { satoshis: 1_000 });

    // Replace the locking script with an oversized one (covers fromUtxo
    // / overlay-injection style attack vectors).
    const utxo = contract.getUtxo()!;
    (contract as unknown as { currentUtxo: UTXO }).currentUtxo = {
      ...utxo,
      script: oversizedScriptHex(),
    };

    let caught: unknown = null;
    try {
      await contract.call('spend', [], provider, signer);
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(ScriptSizeExceededError);
    const err = caught as ScriptSizeExceededError;
    expect(err.limit).toBe(InputLimits.MAX_SCRIPT_BYTES);
    expect(err.actual).toBe(InputLimits.MAX_SCRIPT_BYTES + 1);
    expect(err.context).toContain('OversizedContract.call(spend)');

    // Deploy broadcast (1) is the only broadcast — the rejected call did NOT
    // broadcast a second transaction.
    expect(provider.getBroadcastedTxs().length).toBe(1);
  });

  // -------------------------------------------------------------------------
  // Provider.getUtxos / getContractUtxo
  // -------------------------------------------------------------------------

  it('MockProvider.getUtxos: rejects oversized UTXO script with typed error', async () => {
    const provider = new MockProvider();
    provider.addUtxo('addr', {
      txid: 'bb'.repeat(32),
      outputIndex: 0,
      satoshis: 1_000,
      script: oversizedScriptHex(),
    });

    let caught: unknown = null;
    try {
      await provider.getUtxos('addr');
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(ScriptSizeExceededError);
    const err = caught as ScriptSizeExceededError;
    expect(err.limit).toBe(InputLimits.MAX_SCRIPT_BYTES);
    expect(err.actual).toBe(InputLimits.MAX_SCRIPT_BYTES + 1);
    expect(err.context).toContain('MockProvider.getUtxos');
  });

  it('MockProvider.getContractUtxo: rejects oversized contract UTXO script', async () => {
    const provider = new MockProvider();
    provider.addContractUtxo('script-hash', {
      txid: 'cc'.repeat(32),
      outputIndex: 0,
      satoshis: 1_000,
      script: oversizedScriptHex(),
    });

    let caught: unknown = null;
    try {
      await provider.getContractUtxo('script-hash');
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(ScriptSizeExceededError);
    expect((caught as ScriptSizeExceededError).context).toContain(
      'MockProvider.getContractUtxo',
    );
  });

  it('MockProvider.getUtxos: at-limit script passes', async () => {
    const provider = new MockProvider();
    provider.addUtxo('addr', {
      txid: 'dd'.repeat(32),
      outputIndex: 0,
      satoshis: 1_000,
      script: atLimitScriptHex(),
    });
    const utxos = await provider.getUtxos('addr');
    expect(utxos.length).toBe(1);
    expect(utxos[0]!.script.length).toBe(InputLimits.MAX_SCRIPT_BYTES * 2);
  });
});
