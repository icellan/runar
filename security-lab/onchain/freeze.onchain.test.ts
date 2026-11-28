/**
 * F-2 on-chain: a 200-byte post must not strand the UTXO it lands on.
 *
 * The bug: a variable-length `ByteString` state field of 129..255 bytes was
 * written under an OP_PUSHDATA1 prefix whose length byte the read-back path
 * decoded SIGNED, so the scan asked for a negative split and every later spend
 * died. It was reachable anonymously — one `post` to somebody else's board — and
 * the node confirmed the poisoned state into a block before refusing to spend
 * it, which is the part an in-process oracle cannot show.
 *
 * The lengths are read unsigned now, so this is a regression guard: the 200-byte
 * post still has to be standard enough to mine, AND the very next spend of that
 * same UTXO still has to be accepted by the node, with the new message readable
 * back out of the mined output. If the signed read comes back, the follow-up
 * post is rejected `Invalid OP_SPLIT range` and this test says so.
 *
 * Run:  cd integration && ./regtest.sh start
 *       cd security-lab && npx vitest run
 */
import { it, expect } from 'vitest';
import { onchain } from './gate.js';
import { RunarContract } from 'runar-sdk';
import { compileContract } from '../../integration/ts/helpers/compile.js';
import { createFundedWallet } from '../../integration/ts/helpers/wallet.js';
import { createProvider, mineUntilConfirmed } from '../../integration/ts/helpers/node.js';
import { readOnChainState } from '../../integration/ts/helpers/on-chain-state.js';

const SRC = 'examples/ts/message-board/MessageBoard.runar.ts';
const ownerOf = (n: number) => 'ab'.repeat(n);
const sats = (btc: number) => Math.round(btc * 1e8);

async function board(funded: boolean) {
  const artifact = compileContract(SRC);
  const provider = createProvider();
  const owner = await createFundedWallet(provider, 0.5);
  const attacker = await createFundedWallet(provider, 0.5);
  const contract = new RunarContract(artifact, [ownerOf(8), owner.pubKeyHex]);
  const deploy = funded
    ? await contract.deploy(provider, owner.signer, { satoshis: sats(0.002) })
    : await contract.deploy(provider, owner.signer, {});
  await mineUntilConfirmed(deploy.txid);
  return { artifact, provider, owner, attacker, contract };
}

onchain('F-2 freeze, verified on a regtest node', () => {
  it('a 200-byte post is mined and the same UTXO stays spendable', async () => {
    const { provider, attacker, contract } = await board(true);

    const fat = await contract.call('post', [ownerOf(200)], provider, attacker.signer, { satoshis: sats(0.002) });
    await mineUntilConfirmed(fat.txid);
    console.log('  200-byte post accepted by the node, txid', fat.txid.slice(0, 16), '...');

    // The board really holds the value, in the state the attacker chose.
    const utxo = contract.getUtxo()!;
    const state = await readOnChainState(provider, contract.artifact, utxo);
    console.log('  on-chain message length now', (state.message as string).length / 2, 'bytes; UTXO holds', utxo.satoshis, 'sats');
    expect((state.message as string).length / 2).toBe(200);

    // The regression this guards: spending that UTXO again. Pre-fix the node
    // took the 200-byte post, mined it, and then rejected every later spend of
    // it with `Invalid OP_SPLIT range` — a confirmed, permanent dead end.
    let verdict: string;
    try {
      const next = await contract.call('post', [ownerOf(8)], provider, attacker.signer, { satoshis: sats(0.002) });
      await mineUntilConfirmed(next.txid);
      const after = await readOnChainState(provider, contract.artifact, contract.getUtxo()!);
      verdict = `follow-up post mined, on-chain message now ${(after.message as string).length / 2} bytes`;
      expect((after.message as string).length / 2).toBe(8);
    } catch (e) {
      verdict = '*** FROZEN AGAIN — node rejected the follow-up: ' + (String((e as Error).message).split('\n')[0] ?? '').slice(0, 120) + ' ***';
    }
    console.log('  ' + verdict);
    expect(verdict).toMatch(/follow-up post mined/);
  });

  it('control: a 127-byte post leaves the board spendable', async () => {
    const { provider, attacker, contract } = await board(true);
    const ok1 = await contract.call('post', [ownerOf(127)], provider, attacker.signer, { satoshis: sats(0.002) });
    await mineUntilConfirmed(ok1.txid);
    const ok2 = await contract.call('post', [ownerOf(8)], provider, attacker.signer, { satoshis: sats(0.002) });
    await mineUntilConfirmed(ok2.txid);
    console.log('  127-byte post then an 8-byte post: both mined');
    expect(ok2.txid.length).toBe(64);
  });
});
