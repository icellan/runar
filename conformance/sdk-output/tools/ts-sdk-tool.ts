import { readFileSync } from 'fs';
import { RunarContract } from '../../../packages/runar-sdk/src/contract.js';
import { WalletProvider } from '../../../packages/runar-sdk/src/providers/wallet-provider.js';
import { extractConstructorArgs, matchesArtifact } from '../../../packages/runar-sdk/src/script-utils.js';

interface TypedArg {
  type: string;
  value: string;
}

interface InscriptionInput {
  contentType: string;
  data: string;
}

/**
 * R-062: drive the tier's WALLET funding path (a BRC-100 wallet builds and
 * funds the tx itself) instead of just building the locking script, so all
 * seven tiers can be asked to agree on accept-vs-refuse for one artifact.
 */
interface WalletDeployInput {
  satoshis?: number;
  acknowledgeUnsound?: string[];
}

interface Input {
  artifact: Record<string, unknown>;
  constructorArgs: TypedArg[];
  inscription?: InscriptionInput;
  walletDeploy?: WalletDeployInput;
}

function convertArg(arg: TypedArg): unknown {
  switch (arg.type) {
    case 'bigint':
    case 'int':
      return BigInt(arg.value);
    // `boolean` is the spelling the compiler's ABI carries; `bool` is the
    // alias some frontends use. Accept both (R-248).
    case 'bool':
    case 'boolean':
      return arg.value === 'true';
    default:
      // ByteString, PubKey, Addr, Sig, Ripemd160, Sha256, Point — all hex strings
      return arg.value;
  }
}

const inputPath = process.argv[2];
if (!inputPath) {
  process.stderr.write('Usage: ts-sdk-tool <input.json>\n');
  process.exit(1);
}

const input: Input = JSON.parse(readFileSync(inputPath, 'utf-8'));

/**
 * Readback mode (conformance/sdk-vertical): input `{artifact, scriptHex}`.
 * Prints `{matches, args, error}` — `args` positional by paramIndex as
 * `{type, value}` (decimal / 'true'|'false' / lowercase hex), null for a
 * param extractConstructorArgs does not report; `error` is the message
 * extractConstructorArgs (or matchesArtifact) raised, else null.
 */
const readbackScript = (input as unknown as { scriptHex?: unknown }).scriptHex;
if (typeof readbackScript === 'string') {
  const artifact = input.artifact as any;
  let matches: boolean | null = null;
  let args: Array<{ type: string; value: string } | null> | null = null;
  let error: string | null = null;
  try {
    matches = matchesArtifact(artifact, readbackScript);
  } catch (e) {
    error = (e as Error).message;
  }
  try {
    const got = extractConstructorArgs(artifact, readbackScript);
    const params = artifact.abi.constructor.params as Array<{ name: string; type: string }>;
    args = params.map((p) => {
      if (!(p.name in got)) return null;
      const v = got[p.name];
      const value = typeof v === 'bigint' || typeof v === 'boolean' ? String(v) : String(v).toLowerCase();
      return { type: p.type, value };
    });
  } catch (e) {
    error ??= (e as Error).message;
  }
  process.stdout.write(JSON.stringify({ matches, args, error }));
  process.exit(0);
}
const args = input.constructorArgs.map(convertArg);
const contract = new RunarContract(input.artifact as any, args);
if (input.inscription) {
  contract.withInscription(input.inscription);
}

if (input.walletDeploy) {
  // R-062: a refusal is a RESULT, not a crash — exit non-zero with the reason
  // on stderr so the runner can compare the verdict across all seven tiers.
  const stubSigner = {
    async getPublicKey() { return '02' + '11'.repeat(32); },
    async getAddress() { return '1BitcoinAddress'; },
    async sign() { return '00'.repeat(71); },
  };
  const wallet = { async createAction() { return { txid: 'ab'.repeat(32) }; } };
  const provider = new WalletProvider({
    wallet: wallet as never,
    signer: stubSigner as never,
    basket: 'conformance',
  });
  contract.connect(provider, stubSigner as never);
  try {
    await contract.deployWithWallet({
      satoshis: input.walletDeploy.satoshis ?? 1,
      acknowledgeUnsound: input.walletDeploy.acknowledgeUnsound ?? [],
    });
  } catch (e) {
    process.stderr.write(`${(e as Error).message}\n`);
    process.exit(1);
  }
}

process.stdout.write(contract.getLockingScript());
