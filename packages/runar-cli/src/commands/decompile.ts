/**
 * CLI command: runar decompile — recover Rúnar TypeScript source from
 * a Bitcoin Script byte stream.
 *
 * Accepts input as:
 *   - Hex string: runar decompile 76a90088ac
 *   - .hex file:  runar decompile expected-script.hex
 *   - Artifact:   runar decompile artifacts/P2PKH.json (reads "script" field)
 *   - Stdin:      echo 76a90088ac | runar decompile -
 *
 * Recovered source goes to stdout. The exit code reflects the round-trip:
 *   0 — recovered source re-compiles to byte-identical input (full round-trip)
 *   1 — recovered source does not re-compile to identical bytes (partial)
 *   2 — input could not be processed (read error, malformed hex)
 */

import { readFileSync, existsSync, writeFileSync } from 'node:fs';
import { extname } from 'node:path';
import { decompile } from 'runar-decompiler';
import { hexToBytes } from 'runar-testing';

export interface DecompileOptions {
  outFile?: string;
  quiet?: boolean;
  /**
   * Force the raw_script path: skip templates and the symbolic recognizer,
   * wrap the entire input in a single `asm({...})` call, verify via
   * `compileFromANF`. Honest output for arbitrary byte streams — round-trips
   * byte-identically without claiming structural recovery.
   */
  raw?: boolean;
}

function resolveInput(input: string): string {
  if (input === '-') {
    return readFileSync(0, 'utf-8').trim();
  }
  if (existsSync(input)) {
    const ext = extname(input).toLowerCase();
    if (ext === '.json') {
      const content = readFileSync(input, 'utf-8');
      const artifact = JSON.parse(content) as { script?: unknown; scriptHex?: unknown };
      const hex = artifact.script ?? artifact.scriptHex;
      if (typeof hex !== 'string') {
        throw new Error(`Artifact JSON at ${input} does not contain a "script" or "scriptHex" field`);
      }
      return hex;
    }
    return readFileSync(input, 'utf-8').trim();
  }
  return input;
}

export function decompileCommand(input: string, opts: DecompileOptions): void {
  let hex: string;
  try {
    hex = resolveInput(input).replace(/\s+/g, '');
  } catch (e: unknown) {
    process.stderr.write(`error: ${e instanceof Error ? e.message : String(e)}\n`);
    process.exit(2);
  }

  if (!/^[0-9a-fA-F]*$/.test(hex)) {
    process.stderr.write('error: input is not valid hex\n');
    process.exit(2);
  }

  let bytes: Uint8Array;
  try {
    bytes = hexToBytes(hex);
  } catch (e: unknown) {
    process.stderr.write(`error: ${e instanceof Error ? e.message : String(e)}\n`);
    process.exit(2);
  }

  const result = decompile(bytes, { raw: opts.raw === true });

  if (opts.outFile) {
    writeFileSync(opts.outFile, result.source);
  } else {
    process.stdout.write(result.source);
    if (!result.source.endsWith('\n')) process.stdout.write('\n');
  }

  if (!opts.quiet) {
    if (result.ok) {
      process.stderr.write(`\n[round-trip OK] ${bytes.length} bytes recovered byte-identical\n`);
    } else if (result.diff) {
      process.stderr.write(
        `\n[round-trip PARTIAL] divergence at byte ${result.diff.divergenceOffset} (input is ${bytes.length} bytes)\n`,
      );
    } else {
      process.stderr.write('\n[round-trip FAILED] could not produce a verifiable candidate\n');
    }
  }

  process.exit(result.ok ? 0 : 1);
}
