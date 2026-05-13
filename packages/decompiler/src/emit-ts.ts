/**
 * ANF → TypeScript Rúnar source pretty-printer.
 *
 * v0.1 status: renders recognized SSA bindings (`assert_const`,
 * `assert_chain`) directly, and falls back to `/* RAW: <hex> *\/`
 * comments wrapped with a safety `assert(true)` terminator for
 * unrecognized bodies so the public-method validator (which requires every
 * public method to end with an assert call) still accepts the recovered
 * source.
 */

import type { LiftedMethod } from './lift.js';
import type { SsaBinding } from './symexec.js';
import { bytesToHex } from 'runar-testing';

const PREAMBLE = `import { SmartContract, assert } from 'runar-lang';
`;

function emitBinding(b: SsaBinding, indent: string): string[] {
  if (b.kind === 'assert_const' && b.constValue !== undefined) {
    return [`${indent}assert(${b.constValue});`];
  }
  if (b.kind === 'assert_chain' && b.chainValues) {
    return b.chainValues.map(v => `${indent}assert(${v});`);
  }
  if (b.kind === 'raw_block' && b.rawHex !== undefined) {
    const lines = [];
    if (b.rawHex.length > 0) lines.push(`${indent}/* RAW: ${b.rawHex} */`);
    else lines.push(`${indent}// (empty body)`);
    // Safety terminator: every public method must end with assert(), and
    // we cannot synthesize anything else without a real symbolic lifter.
    lines.push(`${indent}assert(true);`);
    return lines;
  }
  return [`${indent}// unhandled SSA binding: ${b.kind} ${b.name}`, `${indent}assert(true);`];
}

function methodSource(m: LiftedMethod): string {
  const lines: string[] = [];
  lines.push(`  public _method${m.index}(): void {`);
  if (m.bindings.length === 0) {
    // Empty body — must still satisfy the public-method-ends-in-assert validator.
    lines.push(`    assert(true);`);
  } else {
    for (const b of m.bindings) {
      lines.push(...emitBinding(b, '    '));
    }
  }
  lines.push('  }');
  return lines.join('\n');
}

export interface EmitOptions {
  className?: string;
}

export function emitTs(methods: LiftedMethod[], opts: EmitOptions = {}): string {
  const className = opts.className ?? '_Recovered';
  const methodBlocks = methods.map(methodSource).join('\n\n');
  return `${PREAMBLE}
export class ${className} extends SmartContract {
  constructor() {
    super();
  }

${methodBlocks}
}
`;
}

export interface EmitRawScriptOptions {
  className?: string;
  methodName?: string;
  inArity?: number;
  outArity?: number;
}

/**
 * Pretty-print a single-`raw_script` recovery as `asm({...})` source.
 *
 * This output is for HUMAN reading — the round-trip verification path
 * uses `compileFromANF` against an ANFProgram constructed in
 * `buildRawScriptProgram`, so the source string here doesn't gate
 * byte-identity. When Phase 3 surface syntax lands, this source becomes
 * directly re-compilable through the standard `compile()` entry.
 *
 * The emitted shape mirrors the planned surface syntax:
 *
 *     asm({ body: '<hex>', in_arity, out_arity });
 *
 * Hex preserves byte order exactly — pretty-printing back to OP_*
 * mnemonics is left for a later refinement pass.
 */
export function emitRawScriptSource(bytes: Uint8Array, opts: EmitRawScriptOptions = {}): string {
  const className  = opts.className  ?? '_Recovered';
  const methodName = opts.methodName ?? 'unlock';
  const inArity    = opts.inArity    ?? 0;
  const outArity   = opts.outArity   ?? 1;
  const hex = bytesToHex(bytes);
  return `// Recovered via runar-decompiler raw_script path. The asm({...}) call
// preserves the exact opcode bytes; round-trip is byte-identical via
// compileFromANF. When Phase 3 surface syntax lands, this source becomes
// directly re-compilable through the standard \`compile()\` entry.
import { SmartContract, asm } from 'runar-lang';

export class ${className} extends SmartContract {
  constructor() {
    super();
  }

  public ${methodName}(): void {
    asm({ body: '${hex}', in_arity: ${inArity}, out_arity: ${outArity} });
  }
}
`;
}
