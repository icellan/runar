/**
 * R-062 — the unsound-primitive deploy gate must cover the WALLET funding path.
 *
 * `RunarContract.deploy` refuses to fund an artifact the compiler marked
 * unsound unless the caller names every listed primitive. `deployWithWallet`
 * is a SECOND funding path — a BRC-100 wallet creates and funds the
 * transaction via `createAction` — and it ran the DoS script-size bound but
 * never the unsound gate. A Go-compiled SP1-FRI artifact handed to any
 * wallet-backed frontend was funded in silence.
 *
 * Three cases, because over-rejection here breaks every legitimate wallet
 * deploy:
 *   1. unsound + unacknowledged  -> refuse, naming the primitive and the site
 *   2. no unsound primitives     -> fund (control)
 *   3. unsound + acknowledged    -> fund (control)
 */

import { describe, it, expect } from 'vitest';
import { RunarContract } from '../contract.js';
import { WalletProvider } from '../providers/wallet-provider.js';
import type { Signer } from '../signers/signer.js';
import type { RunarArtifact } from 'runar-ir-schema';
import type { WalletClient } from '@bsv/sdk';

const stubSigner: Signer = {
  async getPublicKey() { return '02' + '11'.repeat(32); },
  async getAddress() { return '1BitcoinAddress'; },
  async sign() { return '00'.repeat(71); },
} as unknown as Signer;

/** Records every createAction the SDK reaches — proof the gate ran BEFORE it. */
class RecordingWallet {
  readonly actions: unknown[] = [];
  async createAction(args: unknown): Promise<{ txid: string }> {
    this.actions.push(args);
    return { txid: 'ab'.repeat(32) };
  }
}

const artifact = (unsound?: string[]): RunarArtifact =>
  ({
    version: 'runar-v1.0.0-rc.1',
    compilerVersion: '1.0.0-rc.1-go',
    contractName: 'Sp1Rollup',
    abi: { constructor: { params: [] }, methods: [] },
    script: '51',
    asm: 'OP_1',
    buildTimestamp: '2026-09-13T00:00:00Z',
    ...(unsound ? { unsoundPrimitives: unsound } : {}),
  }) as RunarArtifact;

function connected(unsound?: string[]): { contract: RunarContract; wallet: RecordingWallet } {
  const wallet = new RecordingWallet();
  const provider = new WalletProvider({
    wallet: wallet as unknown as WalletClient,
    signer: stubSigner,
    basket: 'test-basket',
  });
  const contract = new RunarContract(artifact(unsound), []);
  contract.connect(provider, stubSigner);
  return { contract, wallet };
}

describe('R-062 — deployWithWallet enforces the unsound-primitive gate', () => {
  it('refuses an unacknowledged unsound artifact, and never reaches the wallet', async () => {
    const { contract, wallet } = connected(['verifySP1FRI']);
    await expect(contract.deployWithWallet({ satoshis: 1 })).rejects.toThrow(
      /Sp1Rollup\.deployWithWallet[\s\S]*verifySP1FRI/,
    );
    await expect(contract.deployWithWallet({ satoshis: 1 })).rejects.toThrow(
      /acknowledgeUnsound/,
    );
    expect(wallet.actions).toHaveLength(0);
  });

  it('CONTROL: an ordinary artifact still funds through the wallet path', async () => {
    const { contract, wallet } = connected();
    const res = await contract.deployWithWallet({ satoshis: 1 });
    expect(res.txid).toBe('ab'.repeat(32));
    expect(wallet.actions).toHaveLength(1);
  });

  it('CONTROL: an acknowledged unsound artifact still funds through the wallet path', async () => {
    const { contract, wallet } = connected(['verifySP1FRI']);
    const res = await contract.deployWithWallet({
      satoshis: 1,
      acknowledgeUnsound: ['verifySP1FRI'],
    });
    expect(res.txid).toBe('ab'.repeat(32));
    expect(wallet.actions).toHaveLength(1);
  });

  it('a PARTIAL acknowledgement is still a refusal', async () => {
    const { contract, wallet } = connected(['verifySP1FRI', 'someFutureStub']);
    await expect(
      contract.deployWithWallet({ satoshis: 1, acknowledgeUnsound: ['verifySP1FRI'] }),
    ).rejects.toThrow(/someFutureStub/);
    expect(wallet.actions).toHaveLength(0);
  });
});
