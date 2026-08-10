/**
 * I4 — recover a contract skeleton from labeled segments and render annotated
 * Rúnar source.
 *
 * Milestone 1 keeps the executable body as byte-exact `asm()` islands (one per
 * segment, arities chained so they consume each other on the stack with no
 * inserted drops). The recovered *structure* — stateful vs stateless, owner
 * pubkey hash, OP_RETURN state fields, inferred spending inputs — is surfaced
 * as a header comment block and per-island annotations. Because every island
 * is the original bytes, the rendered source recompiles byte-identical.
 */

import type { ANFProgram } from 'runar-compiler';
import { bytesToHex } from 'runar-testing';
import type { AsmSegment, Segment } from './general-lift.js';
import { scanIdioms } from './general-lift.js';
import { disassemble } from './disasm.js';
import { parseRange, type CFNode, type CFLinear, type CFIf } from './control-flow.js';
import { symExec, describeSym, simplify, type SymValue } from './symcore.js';
import { analyzeRegion } from './symanalyze.js';
import type { Op } from './types.js';

export interface RecoveredState {
  hex: string;
  ascii?: string;
}

export interface RecoveredContract {
  className: string;
  kind: 'stateful' | 'stateless';
  methodName: string;
  ownerPkh?: string;
  state: RecoveredState[];
  /** Inferred spending inputs (best-effort, from recognized idioms). */
  inferredInputs: string[];
  segments: Segment[];
}

function asAsm(seg: Segment): AsmSegment | undefined {
  return seg.kind === 'asm' ? seg : undefined;
}

/** Decode a hex string to printable ASCII, or undefined if any byte is non-printable. */
function toAscii(hex: string): string | undefined {
  if (hex.length === 0 || hex.length % 2 !== 0) return undefined;
  let out = '';
  for (let i = 0; i < hex.length; i += 2) {
    const b = parseInt(hex.slice(i, i + 2), 16);
    if (b < 0x20 || b > 0x7e) return undefined;
    out += String.fromCharCode(b);
  }
  return out;
}

export function recoverContract(_bytes: Uint8Array, segments: Segment[]): RecoveredContract {
  const idiomOf = (name: string) =>
    segments.map(asAsm).find((s) => s?.idiom === name);

  const hasPushTx = idiomOf('op_push_tx') !== undefined;
  const gate = idiomOf('p2pkh_sig_gate');
  const stateSeg = idiomOf('op_return_state');

  const state: RecoveredState[] = [];
  const fields = stateSeg?.data?.fields;
  if (Array.isArray(fields)) {
    for (const hex of fields as string[]) {
      const ascii = toAscii(hex);
      state.push(ascii !== undefined ? { hex, ascii } : { hex });
    }
  }

  // Order to match the body's reading order: owner gate first, then OP_PUSH_TX.
  const inferredInputs: string[] = [];
  if (gate) {
    inferredInputs.push('sig: Sig');
    inferredInputs.push('pubKey: PubKey');
  }
  if (hasPushTx) inferredInputs.push('preimage: SigHashPreimage');

  return {
    className: '_Recovered',
    kind: hasPushTx ? 'stateful' : 'stateless',
    methodName: 'spend',
    ownerPkh: gate?.data?.pubKeyHash as string | undefined,
    state,
    inferredInputs,
    segments,
  };
}

/**
 * The byte-exact verified artifact: an ANFProgram of `raw_script` islands (one
 * per segment). `compileFromANF` reproduces the original bytes exactly, so this
 * is what Invariant 2 checks. The rendered TS source below is the human view.
 */
export function buildCandidateProgram(recovered: RecoveredContract, bytes: Uint8Array): ANFProgram {
  const body = recovered.segments.map((seg, i) => {
    const a = asAsm(seg);
    const span = a ? a.span : seg.span;
    const inArity = a ? a.inArity : i === 0 ? 0 : 1;
    const outArity = a ? a.outArity : 1;
    return {
      name: `t${i}`,
      value: {
        kind: 'raw_script' as const,
        bytes: bytesToHex(bytes.slice(span[0], span[1])),
        in_arity: inArity,
        out_arity: outArity,
      },
    };
  });
  return {
    contractName: recovered.className,
    properties: [],
    methods: [{ name: recovered.methodName, params: [], isPublic: true, body }],
  };
}

/** Rúnar pseudocode an idiom corresponds to (the bytes stay verbatim for byte-exactness). */
function runarEquivalent(idiom: string | undefined): string | null {
  switch (idiom) {
    case 'op_push_tx':
      return 'assert(checkPreimage(preimage));';
    case 'preimage_extract':
      return 'const scriptCode = extractScriptCode(preimage); // + outpoint / hashPrevouts / value';
    case 'build_p2pkh_output':
      return 'this.addOutput(amount, recipientPkh); // P2PKH';
    case 'outputs_enforce':
      return 'assert(hash256(outputs) === extractOutputs(preimage));';
    default:
      return null;
  }
}

function describeSegment(seg: AsmSegment, recovered: RecoveredContract): string {
  switch (seg.idiom) {
    case 'p2pkh_sig_gate':
      return `owner pubkey-hash gate (${recovered.ownerPkh ?? '?'})`;
    case 'op_push_tx':
      return 'optimal OP_PUSH_TX — forces preimage to be the spending tx sighash';
    case 'op_return_state':
      return `state data: ${recovered.state
        .map((s) => (s.ascii !== undefined ? `"${s.ascii}"` : s.hex))
        .join(', ')}`;
    case 'preimage_extract':
      return 'BIP-143 preimage field carving (version/hashPrevouts/hashSequence/outpoint)';
    case 'outputs_enforce':
      return 'enforce HASH256(outputs) == preimage hashOutputs';
    case 'build_p2pkh_output':
      return `P2PKH output script template (${(seg.data?.template as string) ?? '?'})`;
    default:
      return seg.analysis
        ? `unrecognized — symbolic analysis: ${seg.analysis}`
        : 'unrecognized region (kept verbatim)';
  }
}

/** Heuristic property name for a recovered OP_RETURN state field. */
function stateFieldName(index: number, state: RecoveredState, asciiSeen: number): string {
  if (state.ascii !== undefined) return asciiSeen === 0 ? 'symbol' : asciiSeen === 1 ? 'name' : `label${index}`;
  if (index === 0 && state.hex.length === 40) return 'tokenId';
  if (state.hex.length <= 2) return 'flag';
  return `field${index}`;
}

/**
 * Readable reconstruction: recognized idioms become real Rúnar; unrecognized
 * spans are bracketed with their symbolic analysis and kept as asm(). This is
 * an *illustrative* view for human reading — the byte-exact verified artifact
 * is the ANF program (`buildCandidateProgram`). Recognized canonical idioms
 * (e.g. the P2PKH gate) match Rúnar's own codegen, so the lifted lines are
 * faithful, but the whole reconstruction is not asserted byte-identical.
 */
export function renderReadable(recovered: RecoveredContract, bytes: Uint8Array): string {
  // Name the OP_RETURN state fields.
  let asciiSeen = 0;
  const props = recovered.state.map((s, i) => {
    const name = stateFieldName(i, s, s.ascii !== undefined ? asciiSeen++ : -1);
    const comment = s.ascii !== undefined ? `"${s.ascii}"` : `0x${s.hex}`;
    return { name, comment, hex: s.hex };
  });

  const L: string[] = [];
  L.push('// Structural reconstruction by runar-decompiler --semantic.');
  L.push('// Recognized idioms are lifted to Rúnar; unrecognized logic is kept as asm()');
  L.push('// with its symbolic analysis. Illustrative view — the byte-exact verified');
  L.push('// artifact is the ANF/asm form (see the fidelity map).');
  L.push(`// Detected: ${recovered.kind === 'stateful' ? 'stateful contract (OP_PUSH_TX)' : 'stateless contract'}.`);
  L.push('');
  L.push("import {");
  L.push('  UnsafeSmartContract, asm, assert, checkSig, hash160, checkPreimage,');
  L.push('  extractScriptCode, extractOutputs, hash256,');
  L.push("} from 'runar-lang';");
  L.push("import type { Sig, PubKey, SigHashPreimage, ByteString } from 'runar-lang';");
  L.push('');
  L.push(`export class ${recovered.className} extends UnsafeSmartContract {`);
  if (recovered.ownerPkh) L.push(`  readonly ownerPkh: ByteString = '${recovered.ownerPkh}';`);
  for (const p of props) L.push(`  readonly ${p.name}: ByteString = '${p.hex}'; // ${p.comment}`);
  // Initialized properties are excluded from the constructor; super() takes no args.
  L.push('  constructor() { super(); }');
  L.push('');
  const sig = recovered.inferredInputs.length > 0 ? recovered.inferredInputs.join(', ') : '';
  L.push(`  public ${recovered.methodName}(${sig}): void {`);

  for (const seg of recovered.segments) {
    const a = asAsm(seg);
    if (!a) continue;
    switch (a.idiom) {
      case 'p2pkh_sig_gate':
        L.push('    // owner gate');
        L.push('    assert(hash160(pubKey) === this.ownerPkh);');
        L.push('    assert(checkSig(sig, pubKey));');
        break;
      case 'op_push_tx':
        L.push('    // OP_PUSH_TX — force `preimage` to be this transaction’s sighash');
        L.push('    assert(checkPreimage(preimage));');
        break;
      case 'preimage_extract':
        L.push('    // BIP-143 fields: version, hashPrevouts, hashSequence, outpoint');
        L.push('    const scriptCode = extractScriptCode(preimage);');
        break;
      case 'build_p2pkh_output':
        L.push(`    // assemble a P2PKH output script (template ${(a.data?.template as string) ?? '?'})`);
        break;
      case 'outputs_enforce':
        L.push('    // enforce that the tx pays exactly the contract-built outputs');
        L.push('    assert(hash256(builtOutputs) === extractOutputs(preimage));');
        break;
      case 'op_return_state':
        L.push(`    // state committed via OP_RETURN: ${props.map((p) => p.name).join(', ')}`);
        break;
      default: {
        const [start, end] = a.span;
        if (a.analysis) L.push(`    // opaque @${start}..${end} — ${a.analysis}`);
        else L.push(`    // opaque @${start}..${end} (kept verbatim)`);
        const hex = bytesToHex(bytes.slice(start, end));
        L.push(`    asm({ body: '${hex}', in_arity: ${a.inArity}, out_arity: ${a.outArity} });`);
        break;
      }
    }
  }
  L.push('  }');
  L.push('}');
  return L.join('\n') + '\n';
}

/**
 * Compiling reconstruction: lift byte-verified idioms to real Rúnar and keep
 * the rest as one asm island, such that the whole source recompiles
 * BYTE-IDENTICAL via `compile()`. Today the leading P2PKH owner gate is the
 * byte-verifiable idiom — its `assert(hash160(pubKey) === this.ownerPkh);
 * assert(checkSig(sig, pubKey))` re-emits to the exact P2PKH bytes. Rúnar's
 * tail-assert optimization drops the gate's final OP_VERIFY, so the asm island
 * starts one byte early (at that OP_VERIFY) with `in_arity: 1` to consume the
 * leftover checkSig result.
 */
export function renderCompiling(recovered: RecoveredContract, bytes: Uint8Array): string {
  const segs = recovered.segments;
  const first = segs[0];
  const gate =
    first && first.kind === 'asm' && first.idiom === 'p2pkh_sig_gate' &&
    bytes[first.span[1] - 1] === 0x69 && recovered.ownerPkh
      ? { ownerPkh: recovered.ownerPkh, boundary: first.span[1] - 1 }
      : null;

  // Method params = recovered spending inputs. The gate needs `sig, pubKey` as
  // the top two stack items (pubKey last/top for its OP_DUP), so other recovered
  // inputs (e.g. the OP_PUSH_TX `preimage`) come first/deepest. Those deeper
  // inputs survive the gate, so the first post-gate island consumes them too.
  const others = recovered.inferredInputs.filter((p) => !/^(sig|pubKey):/.test(p));
  const methodParams = gate ? [...others, 'sig: Sig', 'pubKey: PubKey'].join(', ') : '';
  const otherTypes = others.map((p) => p.split(':')[1]?.trim()).filter((t): t is string => !!t);
  const typeImports = [...new Set(['Sig', 'PubKey', ...otherTypes, 'ByteString'])];
  const hasOpReturn = segs.some((s) => s.kind === 'asm' && s.idiom === 'op_return_state');

  const L: string[] = [];
  L.push('// Compiling reconstruction by runar-decompiler --semantic.');
  L.push('// Byte-verified idioms are lifted to real Rúnar; every other region is its');
  L.push('// own annotated asm() island. Recompiles BYTE-IDENTICAL via compile().');
  if (recovered.kind === 'stateful') L.push('// Detected: stateful contract (OP_PUSH_TX).');
  if (recovered.state.length > 0) {
    const fields = recovered.state
      .map((s, i) => `field${i}=${s.ascii !== undefined ? `"${s.ascii}"` : `0x${s.hex}`}`)
      .join(' ');
    L.push(`// OP_RETURN state: ${fields}.`);
  }
  if (gate) {
    L.push(`// Deploy: new ${recovered.className}(ownerPkh = 0x${gate.ownerPkh}) reproduces the exact script.`);
  }
  L.push('');
  const valueImports = ['UnsafeSmartContract', 'asm'];
  if (gate) valueImports.push('assert', 'checkSig', 'hash160');
  if (hasOpReturn) valueImports.push('opReturn');
  L.push(`import { ${valueImports.join(', ')} } from 'runar-lang';`);
  if (gate) L.push(`import type { ${typeImports.join(', ')} } from 'runar-lang';`);
  L.push('');
  L.push(`export class ${recovered.className} extends UnsafeSmartContract {`);
  if (gate) {
    // Idiomatic: the owner pkh is a constructor arg (spliced at deploy via
    // constructorSlots), not a hardcoded literal.
    L.push('  readonly ownerPkh: ByteString;');
    L.push('  constructor(ownerPkh: ByteString) { super(ownerPkh); this.ownerPkh = ownerPkh; }');
  } else {
    L.push('  constructor() { super(); }');
  }
  L.push('');
  L.push(`  public ${recovered.methodName}(${methodParams}): void {`);

  let asmBlocks = 0;
  for (let i = 0; i < segs.length; i++) {
    const seg = asAsm(segs[i]!);
    if (!seg) continue;
    if (gate && i === 0) {
      L.push('    // owner gate — byte-verified: re-emits to the exact P2PKH bytes');
      L.push('    assert(hash160(pubKey) === this.ownerPkh);');
      L.push('    assert(checkSig(sig, pubKey));');
      L.push('');
      continue;
    }
    // First post-gate island absorbs the gate's trailing OP_VERIFY byte and the
    // deeper inputs the gate left on the stack (e.g. the preimage) plus the
    // checkSig result — hence in_arity = others.length + 1.
    const start = gate && asmBlocks === 0 ? gate.boundary : seg.span[0];
    const end = seg.span[1];
    const inArity = gate
      ? asmBlocks === 0
        ? others.length + 1
        : 1
      : asmBlocks === 0
        ? 0
        : 1;
    asmBlocks++;
    const label = seg.idiom ? `[asm:${seg.idiom}]` : '[asm]';
    const eq = runarEquivalent(seg.idiom);
    L.push(`    // ${label} @${start}..${end} — ${describeSegment(seg, recovered)}`);
    if (eq) L.push(`    //   ≈ ${eq}`);
    if (seg.idiom === 'op_push_tx' && others.length > 0) {
      L.push('    //   consumes (from the stack): preimage — asm() escape-hatch cannot name its stack inputs');
    }
    if (seg.idiom === 'op_return_state' && recovered.state.length > 0) {
      // opReturn shorthand — OP_RETURN + the recovered state pushes, byte-exact.
      const fields = recovered.state
        .map((s) => `'${s.hex}'${s.ascii !== undefined ? ` /* "${s.ascii}" */` : ''}`)
        .join(', ');
      L.push(`    opReturn([${fields}]);`);
    } else {
      L.push(`    asm({ body: '${bytesToHex(bytes.slice(start, end))}', in_arity: ${inArity}, out_arity: 1 });`);
    }
    L.push('');
  }
  if (L[L.length - 1] === '') L.pop(); // no trailing blank before the closing brace
  L.push('  }');
  L.push('}');
  return L.join('\n') + '\n';
}

// ── Native-if structured reconstruction (S9) ──────────────────────────────
//
// Lifts control flow to real Rúnar `if/else`, keeps branch bodies as byte-exact
// asm() islands, and recovers large top-level branches as named private methods
// (the "function boundaries"). Conditions are recovered best-effort by symbolic
// execution of the preceding linear run, so this whole view is semantic-only —
// the byte-exact image is the companion asm tiling (renderCompiling /
// buildCandidateProgram).

/** Top-level branch (op count) at/above which a branch is recovered as a method. */
const FN_THRESHOLD = 40;

const COND_OPS: Record<string, string> = {
  OP_GREATERTHAN: '>',
  OP_LESSTHAN: '<',
  OP_GREATERTHANOREQUAL: '>=',
  OP_LESSTHANOREQUAL: '<=',
  OP_EQUAL: '==',
  OP_NUMEQUAL: '==',
  OP_BOOLAND: '&&',
  OP_BOOLOR: '||',
  OP_ADD: '+',
  OP_SUB: '-',
  OP_MUL: '*',
  OP_DIV: '/',
  OP_MOD: '%',
  OP_MIN: 'min',
  OP_MAX: 'max',
};

/** Friendly names for opaque unary ops in recovered expressions. */
const UNOP_NAMES: Record<string, string> = {
  OP_HASH256: 'hash256',
  OP_HASH160: 'hash160',
  OP_SHA256: 'sha256',
  OP_RIPEMD160: 'ripemd160',
  OP_SHA1: 'sha1',
  OP_NOT: 'not',
  OP_ABS: 'abs',
  OP_NEGATE: 'neg',
  OP_0NOTEQUAL: 'isNonzero',
  OP_INVERT: 'invert',
};

/** Render a recovered SymValue as a readable Rúnar-ish expression. */
function prettyCond(v: SymValue): string {
  switch (v.t) {
    case 'input':
      return v.id;
    case 'const':
      return '0x' + (v.hex || '00');
    case 'bin2num':
    case 'num2bin':
      return prettyCond(v.v); // numeric reinterpretation — transparent
    case 'size':
      return `len(${prettyCond(v.v)})`;
    case 'split':
      return v.side === 'lo'
        ? `${prettyCond(v.src)}[..${prettyCond(v.at)}]`
        : `${prettyCond(v.src)}[${prettyCond(v.at)}..]`;
    case 'cat':
      return `${prettyCond(v.a)}++${prettyCond(v.b)}`;
    case 'binop': {
      const o = COND_OPS[v.op];
      if (!o) return `${v.op}(${prettyCond(v.a)}, ${prettyCond(v.b)})`;
      if (o === 'min' || o === 'max') return `${o}(${prettyCond(v.a)}, ${prettyCond(v.b)})`;
      return `(${prettyCond(v.a)} ${o} ${prettyCond(v.b)})`;
    }
    case 'unop':
      return `${UNOP_NAMES[v.op] ?? v.op}(${prettyCond(v.v)})`;
    case 'select':
      return `(${prettyCond(v.cond)} ? ${prettyCond(v.whenTrue)} : ${prettyCond(v.whenFalse)})`;
    case 'reverse':
      return v.range
        ? `reverse(${prettyCond(v.v)}[${v.range[0]}..${v.range[1]}])`
        : `reverse(${prettyCond(v.v)})`;
    case 'unknown':
      return '_';
  }
}

/** Max ops shown inline as an if-condition; earlier ops stay in the setup island. */
const COND_TAIL_MAX = 14;

const COND_SEED = Array.from({ length: 16 }, (_, k) => `s${k}`);

/**
 * Recover the condition an `if` tests. The tested value is NOT secret — it is
 * computed by the preceding run. A stack simulator (`symExec`, which now models
 * the gate's hash/checksig ops, an alt stack, and depth-relative rolls) runs the
 * run from its start — seeded with the named inputs at script entry — so the
 * tested value's operands trace back to `preimage`/`sig`/`pubKey` and constants.
 * Returns the recovered top `SymValue` (for the `≈` annotation) and the op-index
 * the inline condition `asm([...])` should start at (capped for readability).
 */
function analyzeCond(ctx: StructCtx, run: CFLinear): { condStart: number; top: SymValue | null } {
  const seed = run.startIndex === 0 && ctx.inputNames.length > 0 ? ctx.inputNames : COND_SEED;
  let from = run.startIndex;
  let lastTop: SymValue | undefined;
  while (from < run.endIndex) {
    const st = symExec(ctx.ops.slice(from, run.endIndex), { initialStack: seed });
    const t = st.stack[st.stack.length - 1];
    if (t) lastTop = t;
    if (st.modeled) break;
    from += st.steps + 1; // skip an op the simulator still can't model
  }
  let condStart = run.startIndex;
  if (run.endIndex - condStart > COND_TAIL_MAX) condStart = run.endIndex - COND_TAIL_MAX;
  return { condStart, top: lastTop ?? null };
}

/** Truncate a recovered expression so a comment line stays readable. */
function truncExpr(s: string): string {
  return s.length > 160 ? s.slice(0, 157) + '…' : s;
}

/**
 * Is the whole-program threaded condition strictly better than the local one?
 * Only when it traces cleanly back to a named input (preimage/sig/pubKey) with
 * no unknown/underflow leaves — otherwise the global pass drifted and the local
 * per-run analysis reads cleaner.
 */
function tracesToInput(v: SymValue, inputs: string[]): boolean {
  const s = describeSym(v);
  if (s.includes('?')) return false; // unknown / underflow / elided leaf
  return inputs.some((id) => new RegExp(`\\b${id}\\b`).test(s));
}

/**
 * Comment lines describing a recovered condition. A top-level comparison is
 * broken into its two operands (what was on the stack just before the compare,
 * and how each was computed); anything else is a single `≈` line.
 */
function condComment(raw: SymValue | null, negate: boolean, pad: string): string[] {
  if (!raw) return [];
  const top = simplify(raw); // collapse byte-reversal idioms etc. for readability
  if (top.t === 'binop' && COND_OPS[top.op]) {
    const sym = COND_OPS[top.op]!;
    return [
      `${pad}//   ${negate ? 'NOT ' : ''}left  ≈ ${truncExpr(prettyCond(top.a))}`,
      `${pad}//   ${negate ? '    ' : ''}      ${sym}`,
      `${pad}//   ${negate ? '    ' : ''}right ≈ ${truncExpr(prettyCond(top.b))}`,
    ];
  }
  return [`${pad}//   ≈ ${negate ? '!' : ''}${truncExpr(prettyCond(top))}`];
}

function byteRange(ops: Op[], startIndex: number, endIndex: number): [number, number] {
  const last = ops[endIndex - 1]!;
  return [ops[startIndex]!.offset, last.offset + last.size];
}

/** First op index at or after a byte offset (segment spans are op-aligned). */
function opIndexAtOffset(ops: Op[], offset: number): number {
  for (let i = 0; i < ops.length; i++) {
    if (ops[i]!.offset >= offset) return i;
  }
  return ops.length;
}

interface StructCtx {
  ops: Op[];
  bytes: Uint8Array;
  recovered: RecoveredContract;
  methods: Array<{ name: string; comment: string; body: string[] }>;
  fnCounter: { n: number };
  firstIsland: { done: boolean };
  paramCount: number;
  /** Opcode identifiers referenced by emitted asm arrays (for the import line). */
  usedOps: Set<string>;
  /** Method param names, bottom→top stack order, used to seed condition tracing. */
  inputNames: string[];
  /**
   * Threaded condition per `OP_IF` (keyed by absolute op index), from one
   * whole-program symbolic pass: nested branch conditions trace through the
   * phi-merges back to the seeded inputs, not just stack slots.
   */
  condMap: Map<number, SymValue>;
  /** Threaded stack-top after each op (absolute index) — what an island produces. */
  topMap: Map<number, SymValue>;
}

/**
 * Render an op-index range as an asm() array body: named opcodes verbatim and
 * pushdata as `push('<hex>')`. Far more readable than a raw hex blob, and the
 * referenced opcode identifiers are collected into `used` so they can be
 * imported. (Semantic view — not byte-verified, so non-minimal pushes are fine.)
 */
function opArray(ops: Op[], start: number, end: number, used: Set<string>): string {
  const toks: string[] = [];
  for (let i = start; i < end; i++) {
    const o = ops[i]!;
    if (o.data && o.data.length > 0) {
      toks.push(`push('${bytesToHex(o.data)}')`);
      used.add('push');
    } else {
      toks.push(o.name);
      used.add(o.name);
    }
  }
  return toks.join(', ');
}

/** Emit an op-index range as lifted idioms + annotated asm() islands. */
function emitLinearRange(ctx: StructCtx, startIndex: number, endIndex: number, indent: number): string[] {
  if (endIndex <= startIndex) return [];
  const pad = ' '.repeat(indent);
  const L: string[] = [];
  const spans = scanIdioms(ctx.ops, startIndex, endIndex);
  for (const sp of spans) {
    const [start, end] = byteRange(ctx.ops, sp.startIndex, sp.endIndex);
    if (sp.idiom === 'p2pkh_sig_gate' && ctx.recovered.ownerPkh) {
      L.push(`${pad}// owner gate — byte-verified: re-emits to the exact P2PKH bytes`);
      L.push(`${pad}assert(hash160(pubKey) === this.ownerPkh);`);
      L.push(`${pad}assert(checkSig(sig, pubKey));`);
      L.push('');
      continue;
    }
    if (sp.idiom === 'op_return_state' && ctx.recovered.state.length > 0) {
      const fields = ctx.recovered.state
        .map((s) => `'${s.hex}'${s.ascii !== undefined ? ` /* "${s.ascii}" */` : ''}`)
        .join(', ');
      L.push(`${pad}// [op_return_state] @${start}..${end} — ${describeIdiom(sp.idiom, ctx.recovered)}`);
      L.push(`${pad}opReturn([${fields}]);`);
      L.push('');
      ctx.firstIsland.done = true;
      continue;
    }
    const inArity = ctx.firstIsland.done ? 1 : ctx.paramCount;
    ctx.firstIsland.done = true;
    const label = sp.idiom ? `[asm:${sp.idiom}]` : '[asm]';
    const desc = sp.idiom
      ? describeIdiom(sp.idiom, ctx.recovered, sp.data)
      : analysisNote(ctx.ops, sp.startIndex, sp.endIndex);
    const eq = runarEquivalent(sp.idiom);
    const produces = producesNote(ctx, sp.endIndex);
    const body = opArray(ctx.ops, sp.startIndex, sp.endIndex, ctx.usedOps);
    L.push(`${pad}// ${label} @${start}..${end} — ${desc}`);
    if (eq) L.push(`${pad}//   ≈ ${eq}`);
    if (produces) L.push(`${pad}//   produces ≈ ${produces}`);
    L.push(`${pad}asm({ body: [${body}], in_arity: ${inArity}, out_arity: 1 });`);
    L.push('');
  }
  return L;
}

function analysisNote(ops: Op[], start: number, end: number): string {
  const a = analyzeRegion(ops, start, end);
  return a.findings.length > 0 ? `symbolic analysis: ${a.summary}` : 'unrecognized region (kept verbatim)';
}

/**
 * What an asm island leaves on top of the stack — the whole-program threaded
 * value after its last op, simplified (so the byte-reversal island reads
 * `reverse(hash256(preimage))`). Returns null unless the value reveals real
 * structure (a recognized op, an input, or an operator) — a bare stack slot or
 * constant isn't worth annotating.
 */
function producesNote(ctx: StructCtx, endIndex: number): string | null {
  const v = ctx.topMap.get(endIndex - 1);
  if (!v) return null;
  const s = prettyCond(simplify(v));
  if (s.includes('?') || s.includes('_')) return null; // unknown/underflow leaf — not clean
  const informative =
    s.includes('reverse(') ||
    /hash\d*|sha\d*|ripemd/.test(s) ||
    ctx.inputNames.some((n) => new RegExp(`\\b${n}\\b`).test(s)) ||
    /[+\-*\/%<>[\]]|==/.test(s); // contains an operator, comparison, or slice
  return informative ? truncExpr(s) : null;
}

function describeIdiom(
  idiom: string | undefined,
  recovered: RecoveredContract,
  data?: Record<string, unknown>,
): string {
  switch (idiom) {
    case 'op_push_tx':
      return 'optimal OP_PUSH_TX — forces preimage to be the spending tx sighash';
    case 'op_return_state':
      return `state data: ${recovered.state
        .map((s) => (s.ascii !== undefined ? `"${s.ascii}"` : s.hex))
        .join(', ')}`;
    case 'preimage_extract':
      return 'BIP-143 preimage field carving (version/hashPrevouts/hashSequence/outpoint)';
    case 'outputs_enforce':
      return 'enforce HASH256(outputs) == preimage hashOutputs';
    case 'build_p2pkh_output':
      return `P2PKH output script template (${(data?.template as string) ?? '?'})`;
    default:
      return 'recognized idiom';
  }
}

interface PendingCond {
  start: number;
  end: number;
  top: SymValue | null;
}

/**
 * Render an `if`/`notif` node. The condition is the ACTUAL script: `pending`
 * carries the op-index range that computes the tested value (the tail of the
 * preceding run), shown inline as `asm([...])` — so e.g. `OP_GREATERTHAN` is
 * right there — preceded by `≈` comment lines breaking the recovered comparison
 * into its two operands and how each was computed. No fabricated names.
 */
function renderIf(
  n: CFIf,
  pending: PendingCond | undefined,
  indent: number,
  topLevel: boolean,
  ctx: StructCtx,
): string[] {
  const pad = ' '.repeat(indent);
  const L: string[] = [];
  const negate = n.op === 'notif';
  const condCode =
    pending && pending.end > pending.start
      ? `asm([${opArray(ctx.ops, pending.start, pending.end, ctx.usedOps)}])`
      : 'stackTop'; // value left by the preceding block — no condition ops here
  const test = negate ? `!${condCode}` : condCode;
  const comments = condComment(pending?.top ?? null, negate, pad);
  const bodyOps = n.endIndex - n.ifIndex;

  if (topLevel && bodyOps > FN_THRESHOLD) {
    const fnName = `recoveredFn${++ctx.fnCounter.n}`;
    L.push(
      `${pad}// ── recovered function boundary (was OP_${n.op.toUpperCase()} @${n.span[0]}..${n.span[1]}, ${bodyOps} ops) ──`,
    );
    L.push(...comments);
    L.push(`${pad}if (${test}) {`);
    L.push(`${pad}  this.${fnName}();`);
    ctx.methods.push({
      name: fnName,
      comment: `function boundary lifted from OP_${n.op.toUpperCase()} @${n.span[0]}..${n.span[1]}`,
      body: emitNodes(n.then, 4, false, ctx),
    });
    if (n.else.length > 0) {
      const elseFn = `${fnName}Else`;
      L.push(`${pad}} else {`);
      L.push(`${pad}  this.${elseFn}();`);
      ctx.methods.push({
        name: elseFn,
        comment: `else-branch of the function boundary @${n.span[0]}..${n.span[1]}`,
        body: emitNodes(n.else, 4, false, ctx),
      });
    }
    L.push(`${pad}}`);
    L.push('');
    return L;
  }

  L.push(`${pad}// if @${n.span[0]}..${n.span[1]}`);
  L.push(...comments);
  L.push(`${pad}if (${test}) {`);
  L.push(...emitNodes(n.then, indent + 2, false, ctx));
  if (L[L.length - 1] === '') L.pop();
  if (n.else.length > 0) {
    L.push(`${pad}} else {`);
    L.push(...emitNodes(n.else, indent + 2, false, ctx));
    if (L[L.length - 1] === '') L.pop();
  }
  L.push(`${pad}}`);
  L.push('');
  return L;
}

/**
 * Walk a list of control-flow nodes, emitting native if/else. The linear run
 * immediately before an `if` is split: its prefix becomes setup asm islands and
 * its condition tail is handed to `renderIf` to inline as the actual condition.
 */
function emitNodes(nodes: CFNode[], indent: number, topLevel: boolean, ctx: StructCtx): string[] {
  const L: string[] = [];
  let pending: PendingCond | undefined;
  for (let i = 0; i < nodes.length; i++) {
    const n = nodes[i]!;
    if (n.kind === 'linear') {
      const next = nodes[i + 1];
      if (next && next.kind === 'if') {
        const { condStart, top } = analyzeCond(ctx, n);
        L.push(...emitLinearRange(ctx, n.startIndex, condStart, indent));
        // Prefer the whole-program threaded condition, but only when it traced
        // cleanly back to a named input; otherwise the local analysis is cleaner.
        const threaded = ctx.condMap.get(next.ifIndex);
        const best = threaded && tracesToInput(threaded, ctx.inputNames) ? threaded : top;
        pending = { start: condStart, end: n.endIndex, top: best };
      } else {
        L.push(...emitLinearRange(ctx, n.startIndex, n.endIndex, indent));
        pending = undefined;
      }
      continue;
    }
    L.push(...renderIf(n, pending, indent, topLevel, ctx));
    pending = undefined;
  }
  return L;
}

/**
 * Structured reconstruction: native `if/else` with byte-exact asm() branch
 * bodies, large top-level branches recovered as private methods, the owner gate
 * lifted to real asserts. Semantic-only (conditions reconstructed) — pair it
 * with `renderCompiling` for the byte-identical image.
 */
export function renderStructured(recovered: RecoveredContract, bytes: Uint8Array): string {
  const ops = disassemble(bytes);

  const hasGate = recovered.ownerPkh !== undefined;
  const others = recovered.inferredInputs.filter((p) => !/^(sig|pubKey):/.test(p));
  const methodParams = hasGate ? [...others, 'sig: Sig', 'pubKey: PubKey'] : [...others];
  const otherTypes = others.map((p) => p.split(':')[1]?.trim()).filter((t): t is string => !!t);
  const typeImports = [...new Set([...(hasGate ? ['Sig', 'PubKey'] : []), ...otherTypes, 'ByteString'])];
  const hasOpReturn = recovered.state.length > 0;
  const hasPushTx = recovered.segments.some((s) => asAsm(s)?.idiom === 'op_push_tx');

  // Stack at script entry, bottom→top, = method params in declaration order.
  const inputNames = methodParams.map((p) => p.split(':')[0]!.trim());
  // One whole-program symbolic pass threads stack state through the entire
  // control-flow tree, recording every IF's tested value traced to the inputs.
  const condMap = new Map<number, SymValue>();
  const topMap = new Map<number, SymValue>();
  // Bounded node cap: the whole-program pass merges branches over loops and would
  // otherwise grow provenance trees without limit. Local per-run analysis below
  // is control-flow-free and stays uncapped.
  if (inputNames.length > 0) {
    symExec(ops, { initialStack: inputNames, record: condMap, recordTop: topMap, maxNodes: 800 });
  }

  const ctx: StructCtx = {
    ops,
    bytes,
    recovered,
    methods: [],
    fnCounter: { n: 0 },
    firstIsland: { done: false },
    paramCount: methodParams.length,
    usedOps: new Set<string>(),
    inputNames,
    condMap,
    topMap,
  };
  // Render per recovered segment: a recognized idiom is an ATOMIC unit (lifted to
  // its Rúnar meaning), and native-if reconstruction is confined to the
  // unrecognized "asm in between" — where the control flow IS the contract's
  // logic. This is why the whole optimal OP_PUSH_TX construction (sighash
  // reversal + low-S scalar + DER assembly + its internal length-handling ifs)
  // collapses to one `assert(checkPreimage(preimage))` instead of leaking those
  // ifs/arithmetic as fragments.
  const bodyLines: string[] = [];
  for (const seg of recovered.segments) {
    const a = asAsm(seg);
    if (!a) continue;
    if (a.idiom === 'op_push_tx') {
      bodyLines.push('    // optimal OP_PUSH_TX — a low-S signature is constructed from the sighash so');
      bodyLines.push('    // OP_CHECKSIG forces `preimage` to be the real spending-tx preimage. (The');
      bodyLines.push('    // byte-reversal + DER assembly is the implementation; this is its meaning.)');
      bodyLines.push('    assert(checkPreimage(preimage));');
      bodyLines.push('');
      ctx.firstIsland.done = true;
      continue;
    }
    const startOp = opIndexAtOffset(ops, a.span[0]);
    const endOp = opIndexAtOffset(ops, a.span[1]);
    if (endOp <= startOp) continue;
    bodyLines.push(...emitNodes(parseRange(ops, startOp, endOp), 4, true, ctx));
  }
  if (bodyLines[bodyLines.length - 1] === '') bodyLines.pop();

  const L: string[] = [];
  L.push('// Structured reconstruction by runar-decompiler --semantic — the SPIRIT of the');
  L.push('// contract, not a byte-identical image (see the .byteexact companion for that).');
  L.push('// Recognized idioms are lifted to their Rúnar MEANING as atomic units: the owner');
  L.push('// gate → asserts, the whole optimal OP_PUSH_TX construction → checkPreimage(),');
  L.push('// OP_RETURN state → opReturn(). Native if/else is reconstructed only in the');
  L.push('// unrecognized "asm in between", where the control flow IS the logic; large');
  L.push('// branches become private methods (function boundaries). Remaining if-conditions');
  L.push('// are shown as asm([...]) (the verbatim script that leaves the tested value on');
  L.push('// top), with `≈` lines giving the operands recovered by symbolic execution.');
  L.push('// Per-span trust: see the fidelity map.');
  if (recovered.kind === 'stateful') L.push('// Detected: stateful contract (OP_PUSH_TX).');
  if (recovered.state.length > 0) {
    const fields = recovered.state
      .map((s, i) => `field${i}=${s.ascii !== undefined ? `"${s.ascii}"` : `0x${s.hex}`}`)
      .join(' ');
    L.push(`// OP_RETURN state: ${fields}.`);
  }
  if (hasGate) {
    L.push(`// Deploy: new ${recovered.className}(ownerPkh = 0x${recovered.ownerPkh}) for the exact owner.`);
  }
  L.push('');
  const valueImports = ['UnsafeSmartContract', 'asm'];
  if (hasGate) valueImports.push('assert', 'checkSig', 'hash160');
  if (hasPushTx) valueImports.push(...(hasGate ? [] : ['assert']), 'checkPreimage');
  if (hasOpReturn) valueImports.push('opReturn');
  // Opcode identifiers + push() referenced by the asm() arrays, sorted for a
  // stable import line (push first, then OP_* alphabetically).
  const opTokens = [...ctx.usedOps].sort((a, b) =>
    a === 'push' ? -1 : b === 'push' ? 1 : a.localeCompare(b),
  );
  valueImports.push(...opTokens);
  L.push(`import { ${valueImports.join(', ')} } from 'runar-lang';`);
  L.push(`import type { ${typeImports.join(', ')} } from 'runar-lang';`);
  L.push('');
  L.push(`export class ${recovered.className} extends UnsafeSmartContract {`);
  if (hasGate) {
    L.push('  readonly ownerPkh: ByteString;');
    L.push('  constructor(ownerPkh: ByteString) { super(ownerPkh); this.ownerPkh = ownerPkh; }');
  } else {
    L.push('  constructor() { super(); }');
  }
  L.push('');
  L.push(`  public ${recovered.methodName}(${methodParams.join(', ')}): void {`);
  L.push(...bodyLines);
  L.push('  }');
  for (const m of ctx.methods) {
    L.push('');
    L.push(`  // ${m.comment}`);
    L.push(`  private ${m.name}(): void {`);
    const body = [...m.body];
    if (body[body.length - 1] === '') body.pop();
    L.push(...body);
    L.push('  }');
  }
  L.push('}');
  return L.join('\n') + '\n';
}

export function renderSemanticSource(recovered: RecoveredContract, bytes: Uint8Array): string {
  const lines: string[] = [];
  lines.push('// Recovered by runar-decompiler --semantic.');
  lines.push('// Foreign script (not Rúnar-emitted): structure recovered, executable');
  lines.push('// bytes preserved as byte-exact asm() islands. Trust per the fidelity map.');
  lines.push(`// Detected: ${recovered.kind}${recovered.kind === 'stateful' ? ' (OP_PUSH_TX present)' : ''}.`);
  if (recovered.inferredInputs.length > 0) {
    lines.push(`// Inferred spending inputs: ${recovered.inferredInputs.join(', ')}.`);
  }
  if (recovered.ownerPkh) lines.push(`// Owner pubkey hash: ${recovered.ownerPkh}.`);
  if (recovered.state.length > 0) {
    const fields = recovered.state
      .map((s, i) => `field${i}=${s.ascii !== undefined ? `"${s.ascii}"` : s.hex}`)
      .join(' ');
    lines.push(`// OP_RETURN state: ${fields}.`);
  }
  lines.push('//');
  lines.push('// NOTE: illustrative view. asm() requires UnsafeSmartContract; the');
  lines.push('// byte-exact verified artifact is the ANF program (compileFromANF).');
  lines.push('');
  lines.push("import { UnsafeSmartContract, asm } from 'runar-lang';");
  lines.push('');
  lines.push(`export class ${recovered.className} extends UnsafeSmartContract {`);
  lines.push('  constructor() {');
  lines.push('    super();');
  lines.push('  }');
  lines.push('');
  lines.push(`  public ${recovered.methodName}(): void {`);
  for (const seg of recovered.segments) {
    const a = asAsm(seg);
    if (!a) continue;
    const [start, end] = a.span;
    const label = a.idiom ? `[asm:${a.idiom}]` : '[asm]';
    lines.push(`    // ${label} @${start}..${end} — ${describeSegment(a, recovered)}`);
    const hex = bytesToHex(bytes.slice(start, end));
    lines.push(`    asm({ body: '${hex}', in_arity: ${a.inArity}, out_arity: ${a.outArity} });`);
  }
  lines.push('  }');
  lines.push('}');
  return lines.join('\n') + '\n';
}
