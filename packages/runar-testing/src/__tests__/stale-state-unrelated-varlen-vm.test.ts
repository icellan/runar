/**
 * A terminal read of a fixed-size state field must see the LIVE on-chain value,
 * even when an untouched sibling field happens to be variable-length.
 *
 * R-074. `lowerDeserializeState` chooses its extraction strategy from a
 * CONTRACT-level fact — "does any mutable property carry a push-data length
 * prefix". When one does, the state section can only be located via the
 * `_codePart`-relative offset, so the entire deserialization is gated on
 * `_codePart` being on the stack; without it the pass drops the state section
 * and every `loadProp` resolves to the DEPLOY-TIME constructor placeholder that
 * is spliced into the locking script.
 *
 * `computeUsesCodePart`, which decides whether `_codePart` is provisioned,
 * asked a strictly narrower METHOD-level question: "does THIS method read a
 * variable-length property". A terminal method reading only the `bigint`
 * sibling answered no — and so read a value frozen at deploy time forever.
 *
 * This file is the EXECUTED proof, not an equality check against the compiler's
 * own output. The cycle runs on the real `@bsv/sdk` Script VM through
 * `MockProvider.enableBroadcastValidation()`:
 *
 *   deploy count = 1
 *   spend  bump(7)        → the continuation's state section now says 7
 *   spend  check(7)       → must VALIDATE   (reads live state)
 *   spend  check(1)       → must be REJECTED (1 is the stale deploy value)
 *
 * Pre-fix those last two are exactly inverted: `check(1)` validated and
 * `check(7)` was rejected. That inversion is the finding — a script that
 * authorises against a value no update can ever change.
 *
 * The matched control is the same contract with `tag: bigint`. No variable-
 * length property, the fixed-width split path, correct all along.
 *
 * Companion compile-level cases live in
 * `packages/runar-compiler/src/__tests__/stale-state-unrelated-varlen.test.ts`
 * (seven-tier byte identity) and in each tier's own regression test.
 */

import { describe, it, expect } from 'vitest';
import { compile } from 'runar-compiler';
import { RunarContract, MockProvider, LocalSigner } from 'runar-sdk';
import { PrivateKey } from '@bsv/sdk';
import type { RunarArtifact } from 'runar-ir-schema';

const PRIV = PrivateKey.fromString('c3'.repeat(32), 16);
const PKH = PRIV.toPublicKey().toHash('hex') as string;

/** Deploy-time value of `count`, baked into the locking script as a literal. */
const DEPLOYED_COUNT = 1n;
/** Value `bump` writes into the continuation's state section. */
const UPDATED_COUNT = 7n;

/**
 * `count` is fixed-size and is the ONLY field the terminal method reads.
 * `tag` is variable-length and the terminal method never touches it — its mere
 * presence is what flipped `lowerDeserializeState` onto the `_codePart` path.
 */
function probeSource(tagType: 'ByteString' | 'bigint'): string {
  const typeImport =
    tagType === 'ByteString' ? `import type { ByteString } from 'runar-lang';\n` : '';
  return `import { StatefulSmartContract, assert } from 'runar-lang';
${typeImport}
export class StaleStateProbe extends StatefulSmartContract {
  count: bigint;
  tag: ${tagType};
  constructor(count: bigint, tag: ${tagType}) {
    super(count, tag);
    this.count = count;
    this.tag = tag;
  }
  public bump(next: bigint, amount: bigint) {
    this.addOutput(amount, next, this.tag);
  }
  public check(expected: bigint) {
    assert(this.count === expected);
  }
}
`;
}

function compileOrThrow(source: string, fileName: string): RunarArtifact {
  const r = compile(source, { fileName });
  if (!r.success || !r.artifact) {
    throw new Error(`compile failed: ${r.diagnostics.map((d) => d.message).join('; ')}`);
  }
  return r.artifact as RunarArtifact;
}

/**
 * Deploy with `count = 1`, then spend once through `bump` so the live state
 * says 7 while the locking script's constructor placeholder still says 1.
 * Every subsequent `check` therefore has two different answers available, and
 * which one the script picks is the whole question.
 */
async function deployAndBump(tagType: 'ByteString' | 'bigint'): Promise<RunarContract> {
  const artifact = compileOrThrow(probeSource(tagType), 'StaleStateProbe.runar.ts');
  const signer = new LocalSigner(PRIV.toString());
  const provider = new MockProvider();
  provider.enableBroadcastValidation();
  provider.addUtxo(await signer.getAddress(), {
    txid: 'dd'.repeat(32),
    outputIndex: 0,
    satoshis: 1_000_000,
    script: '76a914' + PKH + '88ac',
  });

  const tagArg: unknown = tagType === 'ByteString' ? 'deadbeef' : 0n;
  const contract = new RunarContract(artifact, [DEPLOYED_COUNT, tagArg]);
  contract.connect(provider, signer);
  await contract.deploy({ satoshis: 200_000 });

  await contract.call('bump', [UPDATED_COUNT, 120_000n], { satoshis: 120_000 });
  expect(contract.state.count).toBe(UPDATED_COUNT);
  return contract;
}

describe.each(['ByteString', 'bigint'] as const)(
  'terminal read of `count` with a `%s` sibling field',
  (tagType) => {
    const label = tagType === 'ByteString' ? 'variable-length sibling' : 'control';

    it(`[${label}] the terminal read sees the UPDATED value`, async () => {
      const contract = await deployAndBump(tagType);
      // Validated by the real Script VM. If the read had fallen back to the
      // deploy-time placeholder, `assert(this.count === 7)` would compare
      // 1 === 7 and the spend would not validate.
      await expect(
        contract.call('check', [UPDATED_COUNT], { satoshis: 60_000 }),
      ).resolves.toBeDefined();
    });

    it(`[${label}] the terminal read does NOT see the stale deploy-time value`, async () => {
      const contract = await deployAndBump(tagType);
      // The sharp end of the finding: pre-fix THIS is what validated. A script
      // that still accepts the value the contract was deployed with, after
      // that value has been updated on-chain, is a stuck authorisation.
      await expect(
        contract.call('check', [DEPLOYED_COUNT], { satoshis: 60_000 }),
      ).rejects.toThrow();
    });
  },
);
