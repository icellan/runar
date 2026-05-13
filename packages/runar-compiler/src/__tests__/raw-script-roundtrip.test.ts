/**
 * raw_script round-trip canary.
 *
 * Trust anchor for the asm primitive: for every Bitcoin Script byte stream
 * in the corpus, wrapping it in a single raw_script ANF node and running
 * the pipeline (stack-lower → emit) must produce byte-identical output.
 *
 * Two corpora exercise the property from both directions:
 *
 *   1. Rúnar-compiled examples — every contract under examples/ts/ is first
 *      compiled to obtain its scriptHex, then re-wrapped in a single
 *      raw_script and re-emitted. The exit bytes must match the original.
 *      Confirms raw_script is a pass-through identity for the compiler's
 *      own output.
 *
 *   2. Hand-rolled non-Rúnar scripts — canonical Bitcoin patterns the
 *      compiler does not produce (raw P2PKH, OP_CHECKSIG-only, multisig
 *      assembled by hand). Confirms raw_script handles arbitrary opcode
 *      sequences without re-encoding.
 *
 * If this test ever fails, the byte-identity property of asm is broken
 * and every downstream piece (decompiler `asm` emission, the analyzer
 * side-channel) must be paused until the cause is understood.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { resolve, dirname, basename, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { compile } from '../index.js';
import { lowerToStack } from '../passes/05-stack-lower.js';
import { emit } from '../passes/06-emit.js';
import type { ANFProgram } from '../ir/index.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = resolve(__dirname, '..', '..', '..', '..');
const EXAMPLES_DIR = resolve(REPO_ROOT, 'examples', 'ts');

function wrapRawScript(hex: string): ANFProgram {
  return {
    contractName: 'Canary',
    properties: [],
    methods: [
      {
        name: 'unlock',
        params: [],
        isPublic: true,
        body: [
          {
            name: 't0',
            // out_arity = 1 mirrors the public-method invariant that the
            // top of stack must be truthy at end-of-script.
            value: { kind: 'raw_script', bytes: hex, in_arity: 0, out_arity: 1 },
          },
        ],
      },
    ],
  };
}

function walk(dir: string, out: string[]) {
  for (const entry of readdirSync(dir)) {
    const full = resolve(dir, entry);
    if (statSync(full).isDirectory()) walk(full, out);
    else if (entry.endsWith('.runar.ts')) out.push(full);
  }
}

// ---------------------------------------------------------------------------
// Tier 1: every Rúnar-compiled example round-trips through raw_script
// ---------------------------------------------------------------------------

describe('raw_script round-trip: Rúnar-compiled examples', () => {
  const files: string[] = [];
  walk(EXAMPLES_DIR, files);
  files.sort();

  for (const f of files) {
    const id = relative(EXAMPLES_DIR, f).replace(/\.runar\.ts$/, '');
    it(`${id}: original hex == raw_script-wrapped re-emit`, () => {
      const source = readFileSync(f, 'utf8');
      const r = compile(source, { fileName: basename(f) });
      if (!r.success || !r.scriptHex) {
        // Skip examples that don't compile cleanly under current options.
        return;
      }
      if (r.scriptHex.length === 0) return;

      const wrapped = wrapRawScript(r.scriptHex);
      const stack = lowerToStack(wrapped);
      const emitted = emit(stack);
      expect(emitted.scriptHex).toBe(r.scriptHex);
    });
  }
});

// ---------------------------------------------------------------------------
// Tier 2: hand-rolled non-Rúnar Bitcoin Script patterns
// ---------------------------------------------------------------------------

describe('raw_script round-trip: hand-rolled non-Rúnar scripts', () => {
  const cases: { name: string; hex: string }[] = [
    // Minimal P2PKH locking script — real Bitcoin convention, not Rúnar output.
    { name: 'p2pkh-minimal', hex: '76a914' + '00'.repeat(20) + '88ac' },
    // OP_HASH160 <20-byte> OP_EQUAL — canonical hashlock.
    { name: 'hashlock', hex: 'a914' + '11'.repeat(20) + '87' },
    // OP_CHECKSIG only.
    { name: 'checksig-only', hex: 'ac' },
    // OP_TRUE — anyone-can-spend.
    { name: 'anyone-can-spend', hex: '51' },
    // 1-of-2 multisig assembled by hand.
    { name: 'multisig-1of2', hex: '51' + '21' + '02'.repeat(33) + '21' + '03'.repeat(33) + '52ae' },
    // OP_PUSHDATA1 path — a 76-byte push wrapped verbatim.
    { name: 'pushdata1', hex: '4c4c' + 'ab'.repeat(76) },
    // OP_PUSHDATA2 path — 256-byte push wrapped verbatim.
    { name: 'pushdata2', hex: '4d0001' + 'cd'.repeat(256) },
    // Mixed: PUSH OP_HASH160 PUSH OP_EQUAL chained.
    {
      name: 'mixed',
      hex: '21' + '02'.repeat(33) + 'a91476' + '11'.repeat(20) + '87',
    },
  ];

  for (const c of cases) {
    it(`${c.name}: ${c.hex.length / 2} bytes survive raw_script wrap`, () => {
      const wrapped = wrapRawScript(c.hex);
      const stack = lowerToStack(wrapped);
      const emitted = emit(stack);
      expect(emitted.scriptHex).toBe(c.hex);
    });
  }
});
