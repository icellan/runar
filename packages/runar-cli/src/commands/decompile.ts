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
  /**
   * Opt into the general (semantic) lifter: when standard byte-identity-gated
   * recovery declines (a foreign, non-Rúnar script), recover structure —
   * recognized idioms, contract kind, owner pkh, OP_RETURN state — keeping the
   * executable body as byte-exact asm islands and printing a fidelity summary.
   */
  semantic?: boolean;
  /**
   * With `--semantic`: print the byte-exact companion (the asm-island tiling
   * that recompiles BYTE-IDENTICAL) instead of the readable native-if view.
   * The default semantic output lifts control flow to native Rúnar if/else and
   * is semantic-only; this flag prints the verifiable image behind it.
   */
  byteExact?: boolean;
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

  const result = decompile(bytes, { raw: opts.raw === true, semantic: opts.semantic === true });

  // `--byte-exact` prints the verifiable companion (semantic path only); the
  // default semantic `source` is the readable native-if view.
  const output =
    opts.byteExact && result.byteExactSource ? result.byteExactSource : result.source;

  if (opts.outFile) {
    writeFileSync(opts.outFile, output);
  } else {
    process.stdout.write(output);
    if (!output.endsWith('\n')) process.stdout.write('\n');
  }

  if (!opts.quiet) {
    if (result.recoveryPath === 'semantic' && result.fidelity) {
      const s = result.fidelity.summary;
      const recognized = result.fidelity.spans.filter((sp) => sp.idiom).length;
      // The decompiler actually recompiled the shown source: warn only when
      // that check shows divergence. A source that reproduces the bytes needs
      // no warning.
      if (opts.byteExact && result.byteExactSource) {
        process.stderr.write('\n[byte-exact] companion shown — recompiles BYTE-IDENTICAL to the input\n');
      } else if (result.sourceByteIdentical) {
        process.stderr.write('\n[verified] recompiling the shown source reproduces the input byte-identical\n');
      } else if (result.byteExactSource) {
        process.stderr.write(
          '\n⚠ WARNING: recompiling the shown source does NOT reproduce the original bytes\n' +
            '  (checked) — control flow + conditions are reconstructed.\n' +
            '  Re-run with --byte-exact for the byte-identical companion.\n',
        );
      }
      process.stderr.write(
        `\n[semantic] ${s.coveredBytes}/${s.totalBytes} bytes covered — ` +
          `${result.fidelity.spans.length} spans: ${s.byteVerified} byte-verified, ` +
          `${s.semanticOnly} semantic-only, ${s.asmIslands} asm islands (${recognized} recognized)\n`,
      );
      for (const sp of result.fidelity.spans) {
        const label = sp.idiom ? sp.idiom : '(unrecognized)';
        const note = sp.note ? ` — ${sp.note}` : '';
        process.stderr.write(
          `  @${sp.originalRange[0]}..${sp.originalRange[1]}  ${sp.verdict}  ${label}${note}\n`,
        );
      }
    } else if (result.ok) {
      process.stderr.write(`\n[round-trip OK] ${bytes.length} bytes recovered byte-identical\n`);
    } else if (result.diff) {
      process.stderr.write(
        `\n[round-trip PARTIAL] divergence at byte ${result.diff.divergenceOffset} (input is ${bytes.length} bytes)\n`,
      );
    } else {
      process.stderr.write('\n[round-trip FAILED] could not produce a verifiable candidate\n');
    }
  }

  // A semantic result is success-with-caveats: it produced structured output +
  // a fidelity map even though it is not (necessarily) a byte-identical
  // round-trip of a Rúnar contract.
  process.exit(result.recoveryPath === 'semantic' || result.ok ? 0 : 1);
}
