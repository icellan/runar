/**
 * Generate fingerprints.json by compiling minimal contracts that invoke
 * each in-scope EC builtin and recording the emitted opcode template.
 *
 * v0 in-scope: ecAdd, ecMul, ecMulGen, ecOnCurve, ecPointX, ecPointY.
 * Single-opcode builtins (hash160/sha256/ripemd160/checkSig/...) are NOT
 * fingerprinted — the symbolic lifter recovers them via type inference.
 *
 * Probe strategy (source-map-driven, since v0.5.1)
 * -----------------------------------------------
 * Each probe is a one-method stateless contract where every operand is a
 * method parameter (consumed from scriptSig at runtime, not pushed by the
 * locking script). The EC primitive is emitted on a dedicated statement
 * line, and the wrapper that keeps the script terminating-truthy lives on
 * a separate statement line below it. Example:
 *
 *     public probe(a: Point, b: Point): void {
 *       const r = ecAdd(a, b);      // line L
 *       assert(ecOnCurve(r));       // line L+1 (wrapper, NOT fingerprinted)
 *     }
 *
 * The compiler emits a per-opcode source map via assembleArtifact when
 * `includeSourceMap: true` is passed (already the default for `compile()`).
 * The extractor finds the contiguous opcode-index range whose nearest-prior
 * source mapping points at the EC primitive's line, then slices those bytes
 * out as the fingerprint. The wrapper's bytes are excluded — fingerprints
 * are now "primitive-only", not "primitive + wrapper".
 *
 * Source-map sparsity: the EC codegen passes some ops directly into
 * `if.then/else` arrays without routing them through `emitOp`, so those
 * inherit no `sourceLoc` and produce no source-map entry. We handle this
 * via the standard source-map walk: opcode `i`'s source position is the
 * most recent mapping at or before index `i`. The range for the primitive
 * is therefore `[firstIdxOnTargetLine, firstIdxAfterTargetLine - 1]`.
 *
 * If a probe produces zero source-map entries on the target line, the
 * extractor emits a hard error — silent truncation hides probe regressions.
 *
 * Run: pnpm --filter runar-decompiler run fingerprints:build
 */

import { writeFileSync, readFileSync, existsSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { compile } from 'runar-compiler';
import { hexToBytes, bytesToHex } from 'runar-testing';
import { disassemble } from '../src/disasm.js';
import type { Fingerprint, FingerprintDB, Op } from '../src/types.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

interface Probe {
  name: string;
  arity: number;
  /** The Rúnar source. The EC primitive must be the FIRST executable
   *  statement of the public method (e.g. `const r = ecAdd(a, b);`) so its
   *  emitted opcodes are contiguous and immediately discoverable in the
   *  source map. */
  source: string;
  /** Marker comment placed on the EXACT source line of the primitive call.
   *  The extractor uses it to locate the target line by string search; this
   *  is robust against indentation changes and avoids hard-coding line
   *  numbers. */
  primitiveLineMarker: string;
}

// ---------------------------------------------------------------------------
// Probe sources. Every probe:
//   - takes its arguments as method parameters (no leading locking-script
//     pushes — script-sig supplies them at runtime),
//   - puts the EC primitive on its own statement (`const r = <prim>(...)`),
//     marked with `// @primitive` so the extractor can locate the line,
//   - wraps the result on a SEPARATE following statement to keep the script
//     terminating-truthy. The wrapper line is NOT part of the fingerprint.
// ---------------------------------------------------------------------------

const PROBES: Probe[] = [
  {
    name: 'ecOnCurve',
    arity: 1,
    primitiveLineMarker: '// @primitive ecOnCurve',
    source: `
import { SmartContract, assert, ecOnCurve } from 'runar-lang';
import type { Point } from 'runar-lang';
export class Probe_ecOnCurve extends SmartContract {
  constructor() { super(); }
  public probe(p: Point): void {
    const r = ecOnCurve(p); // @primitive ecOnCurve
    assert(r);
  }
}
`,
  },
  {
    name: 'ecAdd',
    arity: 2,
    primitiveLineMarker: '// @primitive ecAdd',
    source: `
import { SmartContract, assert, ecAdd, ecOnCurve } from 'runar-lang';
import type { Point } from 'runar-lang';
export class Probe_ecAdd extends SmartContract {
  constructor() { super(); }
  public probe(a: Point, b: Point): void {
    const r = ecAdd(a, b); // @primitive ecAdd
    assert(ecOnCurve(r));
  }
}
`,
  },
  {
    name: 'ecMul',
    arity: 2,
    primitiveLineMarker: '// @primitive ecMul',
    source: `
import { SmartContract, assert, ecMul, ecOnCurve } from 'runar-lang';
import type { Point } from 'runar-lang';
export class Probe_ecMul extends SmartContract {
  constructor() { super(); }
  public probe(p: Point, k: bigint): void {
    const r = ecMul(p, k); // @primitive ecMul
    assert(ecOnCurve(r));
  }
}
`,
  },
  {
    name: 'ecMulGen',
    arity: 1,
    primitiveLineMarker: '// @primitive ecMulGen',
    source: `
import { SmartContract, assert, ecMulGen, ecOnCurve } from 'runar-lang';
export class Probe_ecMulGen extends SmartContract {
  constructor() { super(); }
  public probe(k: bigint): void {
    const r = ecMulGen(k); // @primitive ecMulGen
    assert(ecOnCurve(r));
  }
}
`,
  },
  {
    // ecPointX returns bigint; wrap result with `>= 0n` on a SEPARATE line
    // so the comparison opcodes are not included in the fingerprint.
    name: 'ecPointX',
    arity: 1,
    primitiveLineMarker: '// @primitive ecPointX',
    source: `
import { SmartContract, assert, ecPointX } from 'runar-lang';
import type { Point } from 'runar-lang';
export class Probe_ecPointX extends SmartContract {
  constructor() { super(); }
  public probe(p: Point): void {
    const r = ecPointX(p); // @primitive ecPointX
    assert(r >= 0n);
  }
}
`,
  },
  {
    name: 'ecPointY',
    arity: 1,
    primitiveLineMarker: '// @primitive ecPointY',
    source: `
import { SmartContract, assert, ecPointY } from 'runar-lang';
import type { Point } from 'runar-lang';
export class Probe_ecPointY extends SmartContract {
  constructor() { super(); }
  public probe(p: Point): void {
    const r = ecPointY(p); // @primitive ecPointY
    assert(r >= 0n);
  }
}
`,
  },
];

// ---------------------------------------------------------------------------
// Source-map-driven primitive-only byte extraction
// ---------------------------------------------------------------------------

/** Locate the 1-based source line that contains the marker comment. */
function findPrimitiveLine(source: string, marker: string): number {
  const lines = source.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (lines[i]!.includes(marker)) return i + 1; // 1-based
  }
  throw new Error(`probe marker not found in source: ${marker}`);
}

interface ExtractionResult {
  /** Inclusive op index of the first opcode that belongs to the primitive. */
  firstOpIdx: number;
  /** Exclusive end op index — first opcode AFTER the primitive's span. */
  endOpIdx: number;
  /** Byte offset where the primitive's emission begins. */
  byteStart: number;
  /** Byte offset where the primitive's emission ends (exclusive). */
  byteEnd: number;
}

/**
 * Locate the contiguous opcode-index span attributable to `targetLine`.
 *
 * Walks the source-map mappings in opcodeIndex order. Returns the half-open
 * interval `[firstIdx, endIdx)` such that every opcode `i` in that interval
 * has its nearest-prior mapping on `targetLine`.
 *
 * Throws if no mapping points at `targetLine` — that's a probe regression
 * the human needs to see, not a silent truncation.
 */
function extractPrimitiveSpan(
  ops: Op[],
  mappings: ReadonlyArray<{ opcodeIndex: number; line: number; column: number }>,
  targetLine: number,
): ExtractionResult {
  if (mappings.length === 0) {
    throw new Error('probe produced no source-map entries — cannot extract primitive span');
  }

  // Build (opcodeIndex, line) sorted by opcodeIndex (assembler emits in order
  // but we sort defensively).
  const sorted = [...mappings].sort((a, b) => a.opcodeIndex - b.opcodeIndex);

  let firstOpIdx = -1;
  let endOpIdx = -1;
  for (let i = 0; i < sorted.length; i++) {
    const m = sorted[i]!;
    if (firstOpIdx === -1 && m.line === targetLine) {
      firstOpIdx = m.opcodeIndex;
      continue;
    }
    if (firstOpIdx !== -1 && m.line !== targetLine) {
      endOpIdx = m.opcodeIndex;
      break;
    }
  }
  if (firstOpIdx === -1) {
    throw new Error(`no source-map entries on target line ${targetLine}`);
  }
  if (endOpIdx === -1) {
    // Primitive runs to the end of the method body.
    endOpIdx = ops.length;
  }

  if (firstOpIdx < 0 || endOpIdx > ops.length || firstOpIdx >= endOpIdx) {
    throw new Error(
      `extracted span [${firstOpIdx},${endOpIdx}) is invalid (ops.length=${ops.length})`,
    );
  }

  // Translate op indices to byte offsets.
  const byteStart = ops[firstOpIdx]!.offset;
  const lastOp = ops[endOpIdx - 1]!;
  const byteEnd = lastOp.offset + lastOp.size;

  return { firstOpIdx, endOpIdx, byteStart, byteEnd };
}

function fingerprintFor(probe: Probe): Fingerprint | null {
  const fileName = `Probe_${probe.name}.runar.ts`;
  const r = compile(probe.source, { fileName });
  if (!r.success || !r.scriptHex || !r.artifact) {
    const errs = r.diagnostics
      .filter((d) => d.severity === 'error')
      .map((d) => d.message)
      .join('; ');
    console.warn(`[fingerprints] probe ${probe.name} failed to compile: ${errs}`);
    return null;
  }

  const targetLine = findPrimitiveLine(probe.source, probe.primitiveLineMarker);
  const mappings = r.artifact.sourceMap?.mappings ?? [];
  if (mappings.length === 0) {
    console.warn(`[fingerprints] probe ${probe.name}: artifact carries no source map`);
    return null;
  }

  const fullBytes = hexToBytes(r.scriptHex);
  const ops = disassemble(fullBytes);

  let span: ExtractionResult;
  try {
    span = extractPrimitiveSpan(ops, mappings, targetLine);
  } catch (e) {
    console.error(`[fingerprints] probe ${probe.name}: ${(e as Error).message}`);
    return null;
  }

  const bytes = fullBytes.subarray(span.byteStart, span.byteEnd);
  if (bytes.length === 0) {
    console.warn(`[fingerprints] probe ${probe.name} produced empty template body`);
    return null;
  }

  const normalizedHex = bytesToHex(bytes);
  const hash = createHash('sha256').update(normalizedHex).digest('hex');
  return {
    name: probe.name,
    arity: probe.arity,
    length: bytes.length,
    normalizedHex,
    hash,
  };
}

function main() {
  const entries: Fingerprint[] = [];
  for (const p of PROBES) {
    const fp = fingerprintFor(p);
    if (fp) {
      entries.push(fp);
      console.log(
        `[fingerprints] ${fp.name}: ${fp.length} bytes (hash ${fp.hash.slice(0, 12)}…)`,
      );
    }
  }

  const out = resolve(__dirname, '..', 'fingerprints.json');

  // Preserve generatedAt when entries are semantically unchanged, so the
  // drift gate fires only on real DB changes, not on timestamp churn.
  let preservedTimestamp: string | null = null;
  if (existsSync(out)) {
    try {
      const prev = JSON.parse(readFileSync(out, 'utf8')) as FingerprintDB;
      const prevKey = JSON.stringify(prev.entries);
      const nextKey = JSON.stringify(entries);
      if (prevKey === nextKey) preservedTimestamp = prev.generatedAt;
    } catch {
      // ignore parse errors — fall through to fresh timestamp
    }
  }

  const db: FingerprintDB = {
    compilerVersion: '0.5.0',
    generatedAt: preservedTimestamp ?? new Date().toISOString(),
    entries,
  };

  writeFileSync(out, JSON.stringify(db, null, 2) + '\n', 'utf8');
  console.log(
    `[fingerprints] wrote ${entries.length} entries → ${out}${
      preservedTimestamp ? ' (timestamp preserved)' : ''
    }`,
  );
}

main();
