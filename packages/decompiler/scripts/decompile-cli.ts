/**
 * Single-script decompile CLI.
 *
 * Run: pnpm --filter runar-decompiler run decompile -- path/to/script.hex
 *
 * Accepts a path to a file containing the hex of a compiled script, or
 * a `--hex <hex>` literal. Writes the recovered TS source to stdout and a
 * verification report to stderr.
 */

import { readFileSync } from 'node:fs';
import { hexToBytes } from 'runar-testing';
import { decompile } from '../src/index.js';

function readHexInput(argv: string[]): string {
  if (argv.length === 0) {
    throw new Error('usage: decompile-cli <hex-file> | --hex <hex>');
  }
  if (argv[0] === '--hex') {
    if (!argv[1]) throw new Error('--hex requires a value');
    return argv[1].trim();
  }
  return readFileSync(argv[0]!, 'utf8').trim();
}

function main() {
  const hex = readHexInput(process.argv.slice(2));
  const bytes = hexToBytes(hex);
  const result = decompile(bytes);

  process.stdout.write(result.source);

  if (result.ok) {
    process.stderr.write(`\n[OK] round-tripped in ${result.attempts} attempts\n`);
    process.exit(0);
  }
  if (result.diff) {
    process.stderr.write(`\n[DIFF] diverged at offset ${result.diff.divergenceOffset} (after ${result.attempts} attempts)\n`);
  } else {
    process.stderr.write(`\n[FAIL] no diff captured (after ${result.attempts} attempts)\n`);
  }
  process.exit(1);
}

main();
