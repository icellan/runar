/**
 * `WalletSigner` and `WalletProvider` typed their `wallet` option as the
 * concrete `@bsv/sdk` `WalletClient` class. `WalletClient` is the substrate
 * wrapper (window.CWI, XDM, HTTP, ...) and carries members (`substrate`,
 * `connectToSubstrate`) that other BRC-100 wallets do not have, so passing an
 * in-process wallet typed as `WalletInterface` failed to compile:
 *
 *   Type 'WalletInterface' is missing the following properties from type
 *   'WalletClient': substrate, connectToSubstrate
 *
 * The SDK only calls `getPublicKey`, `createSignature`, `listOutputs` and
 * `createAction`, all of which are `WalletInterface` methods.
 *
 * Proves (by compiling callers with the TypeScript compiler API, since vitest
 * does not typecheck; the SDK sources the callers import must compile too): a
 * `WalletInterface` is accepted by both constructors with no cast and
 * `walletClient` returns it as that type, not `any`; existing `WalletClient`
 * callers still compile, including `walletClient` read back as a
 * `WalletClient` and a subclass that uses a `WalletClient`-only member of
 * the protected `wallet`. At runtime, a `WalletSigner` over a `ProtoWallet`
 * (not a `WalletClient`; it has the key and signature methods the signer
 * calls) reports the key that signs, and its BIP-143 signature verifies
 * against that key.
 * Does NOT prove: anything about a particular wallet implementation's
 * permissions or originator handling.
 *
 * Like `tsc` for this package, the compile cases need the workspace
 * dependencies built first (`pnpm build`), because they resolve
 * `runar-ir-schema` and `runar-lang` through their `dist` types.
 */
import { describe, it, expect } from 'vitest';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import ts from 'typescript';
import {
  ECDSA,
  Hash,
  PrivateKey,
  ProtoWallet,
  PublicKey,
  Signature,
  Transaction,
  TransactionSignature,
  Script,
  BigNumber,
  Utils,
  type SecurityLevel,
} from '@bsv/sdk';
import { WalletSigner } from '../signers/wallet.js';
import { buildP2PKHScript } from '../script-utils.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const indexJs = path.resolve(here, '../index.js');

const sdkSrc = path.resolve(here, '..') + path.sep;

/** Diagnostics for the virtual caller and for every SDK source file it reaches. */
function diagnose(source: string): string[] {
  const file = path.resolve(here, '__wallet_interface_virtual__.ts');
  // The package's own compiler options, so the callers are checked the way
  // `tsc` checks the package.
  const configPath = path.resolve(here, '../../tsconfig.json');
  const { config } = ts.readConfigFile(configPath, ts.sys.readFile);
  const parsed = ts.parseJsonConfigFileContent(config, ts.sys, path.dirname(configPath));
  const options: ts.CompilerOptions = { ...parsed.options, noEmit: true };
  const host = ts.createCompilerHost(options);
  const origRead = host.readFile.bind(host);
  const origExists = host.fileExists.bind(host);
  const origSource = host.getSourceFile.bind(host);
  host.fileExists = (f) => f === file || origExists(f);
  host.readFile = (f) => (f === file ? source : origRead(f));
  host.getSourceFile = (f, l, ...rest) =>
    f === file ? ts.createSourceFile(f, source, l) : origSource(f, l, ...rest);
  const program = ts.createProgram([file], options, host);
  return ts
    .getPreEmitDiagnostics(program)
    .filter((d) => {
      const name = d.file ? path.resolve(d.file.fileName) : '';
      return name === file || (name.startsWith(sdkSrc) && !name.includes(`${path.sep}__tests__${path.sep}`));
    })
    .map((d) => ts.flattenDiagnosticMessageText(d.messageText, '\n'));
}

const PROTOCOL: [SecurityLevel, string] = [2, 'wallet interface test'];

describe('WalletSigner and WalletProvider accept any WalletInterface', () => {
  it('a WalletInterface is accepted without a cast, and walletClient returns it', () => {
    const source = `
import { WalletSigner, WalletProvider } from ${JSON.stringify(indexJs)};
import type { WalletInterface } from '@bsv/sdk';
declare const wallet: WalletInterface;
const signer = new WalletSigner({ protocolID: [2, 'my app'], keyID: '1', wallet });
const provider = new WalletProvider({ wallet, signer, basket: 'my-app' });
export const back: WalletInterface = provider.walletClient;
`;
    expect(diagnose(source)).toEqual([]);
  });

  it('walletClient keeps the type of the wallet passed in (not any)', () => {
    const source = `
import { WalletSigner, WalletProvider } from ${JSON.stringify(indexJs)};
import type { WalletClient, WalletInterface } from '@bsv/sdk';
declare const wallet: WalletInterface;
const signer = new WalletSigner({ protocolID: [2, 'my app'], keyID: '1', wallet });
const provider = new WalletProvider({ wallet, signer, basket: 'my-app' });
export const client: WalletClient = provider.walletClient;
`;
    const diags = diagnose(source);
    expect(diags).toHaveLength(1);
    expect(diags[0]).toMatch(/missing the following properties from type 'WalletClient'/);
  });

  it('an existing WalletClient caller still compiles', () => {
    const source = `
import { WalletSigner, WalletProvider } from ${JSON.stringify(indexJs)};
import { WalletClient } from '@bsv/sdk';
const wallet = new WalletClient();
const signer = new WalletSigner({ protocolID: [2, 'my app'], keyID: '1', wallet });
export const provider = new WalletProvider({ wallet, signer, basket: 'my-app' });
export const defaulted = new WalletSigner({ protocolID: [2, 'my app'], keyID: '1' });
export const back: WalletClient = provider.walletClient;
export const connect: () => Promise<void> = () => provider.walletClient.connectToSubstrate();
`;
    expect(diagnose(source)).toEqual([]);
  });

  it('an existing subclass and options annotation still compile', () => {
    const source = `
import { WalletProvider, type WalletProviderOptions } from ${JSON.stringify(indexJs)};
export class MyProvider extends WalletProvider {
  constructor(options: WalletProviderOptions) {
    super(options);
  }
  reconnect(): Promise<void> {
    return this.wallet.connectToSubstrate();
  }
}
export let annotated: WalletProvider | undefined;
`;
    expect(diagnose(source)).toEqual([]);
  });

  it('a ProtoWallet-backed signer reports the key that signs, and the signature verifies', async () => {
    const root = PrivateKey.fromRandom();
    const wallet = new ProtoWallet(root);
    const signer = new WalletSigner({ protocolID: PROTOCOL, keyID: '1', wallet });

    const pubKeyHex = await signer.getPublicKey();
    const { publicKey: selfKey } = await wallet.getPublicKey({
      protocolID: PROTOCOL,
      keyID: '1',
      counterparty: 'self',
    });
    expect(pubKeyHex).toBe(selfKey);

    // A one-input, one-output transaction spending a P2PKH output to that key.
    const subscript = buildP2PKHScript(pubKeyHex);
    const satoshis = 1000;
    const txHex =
      '01000000' + '01' + '11'.repeat(32) + '00000000' + '00' + 'ffffffff' +
      '01' + 'e803000000000000' + '01' + '51' + '00000000';
    const sigHex = await signer.sign(txHex, 0, subscript, satoshis);

    const tx = Transaction.fromHex(txHex);
    const input = tx.inputs[0]!;
    const preimage = TransactionSignature.format({
      sourceTXID: input.sourceTXID!,
      sourceOutputIndex: input.sourceOutputIndex,
      sourceSatoshis: satoshis,
      transactionVersion: tx.version,
      otherInputs: [],
      outputs: tx.outputs,
      inputIndex: 0,
      subscript: Script.fromHex(subscript),
      inputSequence: input.sequence ?? 0xffffffff,
      lockTime: tx.lockTime,
      scope: 0x41,
    });
    const sighash = Hash.hash256(preimage);
    const der = Utils.toArray(sigHex, 'hex').slice(0, -1);
    expect(sigHex.slice(-2)).toBe('41');
    expect(
      ECDSA.verify(
        new BigNumber(sighash),
        Signature.fromDER(der),
        PublicKey.fromString(pubKeyHex),
      ),
    ).toBe(true);
  });
});
