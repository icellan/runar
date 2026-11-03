import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { LocalSigner } from '../signers/local.js';

// N-170: Go, Zig and TS LocalSigners (and Java's digest-based signing path)
// were not replayed against conformance/sdk-bip143/fixtures.json's six
// FORKID-mode sigHex vectors; only Python, Rust and Ruby LocalSigners were.
//
// conformance/sdk-bip143/generate-fixtures.ts (the TS reference) builds the
// preimage via @bsv/sdk `TransactionSignature.format` and signs
// sha256d(preimage) with the low-level `sign` primitive from
// `@bsv/sdk/primitives/ECDSA` directly. `LocalSigner.sign()` is a DIFFERENT
// code path through the same library: it parses the tx via
// `Transaction.fromHex`, rebuilds `TransactionSignature.format`'s inputs from
// that parse, and signs via `PrivateKey.sign()` (a higher-level wrapper).
// Nothing before this test exercised LocalSigner.sign() against this fixture
// for any sighash mode, so a divergence in either code path -- e.g.
// LocalSigner reconstructing `otherInputs`/`outputs` incorrectly, or
// `PrivateKey.sign()` not being RFC-6979 + low-S like the primitive -- would
// not have been caught.
//
// Proves: for every fixture scenario, including all six FORKID modes
// (0x41/42/43/c1/c2/c3) on the shared 2-in/2-out tx signing input 1,
// LocalSigner.sign() reproduces the TS reference sigHex byte-for-byte.
// Does not prove: anything about a node accepting the signature (the fixture
// is cross-tier + Go go-sdk checked via integration/ts/bip143-crosstier.test.ts,
// not re-broadcast here), or WalletSigner's code path.

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURE_PATH = join(
  __dirname,
  '../../../../conformance/sdk-bip143/fixtures.json',
);

interface Bip143Scenario {
  scenario: string;
  unsignedTxHex: string;
  inputIndex: number;
  prevScriptHex: string;
  prevValueSats: number;
  sighashFlags: number;
  sigHex: string;
}

interface Bip143Fixture {
  signer_priv_hex: string;
  signer_pub_hex: string;
  scenarios: Bip143Scenario[];
}

function loadFixture(): Bip143Fixture {
  return JSON.parse(readFileSync(FIXTURE_PATH, 'utf8'));
}

describe('N-170: LocalSigner matches the TS BIP-143 fixture reference', () => {
  it('reproduces sigHex for every scenario, incl. all six FORKID modes', async () => {
    const fixture = loadFixture();
    expect(fixture.scenarios.length).toBeGreaterThan(0);

    const signer = new LocalSigner(fixture.signer_priv_hex);
    expect(await signer.getPublicKey()).toBe(fixture.signer_pub_hex);

    for (const s of fixture.scenarios) {
      const got = await signer.sign(
        s.unsignedTxHex,
        s.inputIndex,
        s.prevScriptHex,
        s.prevValueSats,
        s.sighashFlags,
      );
      expect(got).toBe(s.sigHex);
    }
  });
});
