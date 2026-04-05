import { readFileSync } from 'fs';
import { RunarContract } from '../../../packages/runar-sdk/src/contract.js';

interface TypedArg {
  type: string;
  value: string;
}

interface Input {
  artifact: Record<string, unknown>;
  constructorArgs: TypedArg[];
}

function convertArg(arg: TypedArg): unknown {
  switch (arg.type) {
    case 'bigint':
    case 'int':
      return BigInt(arg.value);
    case 'bool':
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
const args = input.constructorArgs.map(convertArg);
const contract = new RunarContract(input.artifact as any, args);
process.stdout.write(contract.getLockingScript());
