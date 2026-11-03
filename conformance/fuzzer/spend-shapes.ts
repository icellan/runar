/**
 * Construct-biased contract SHAPE generator for the Spend-oracle fuzzer
 * (testing-gap remediation Phase E2, plan §3 "E2. Shape injection into
 * generators", reviewer point #6).
 *
 * WHY A SEPARATE GENERATOR
 * ------------------------
 * `packages/runar-testing/src/fuzzer/generator.ts` (`arbGeneratedContract` /
 * `arbGeneratedStatefulContract`) drives the PARITY fuzzers: its contract IR
 * (`contract-ir.ts`) has no readonly constructor-slot modelling, and —
 * decisively — no way to state what the post-spend state SHOULD be. Its
 * consumers only ever compare tier-vs-tier hex or interpreter-vs-VM
 * accept/reject, so it never needed one.
 *
 * A Spend-oracle needs the opposite: a small, fully-modelled construct space
 * where the generator KNOWS the answer before the compiler is invoked. This
 * module therefore generates (source, args, expected-post-state) TRIPLES. The
 * expected state is decided by the generator when it picks the values, and is
 * NEVER read back out of the compiler, the ANF interpreter, or the SDK — see
 * `spend-oracle.ts`'s "poisoned expectation" note for why that independence is
 * the whole point.
 *
 * THE THREE INJECTED SHAPE FAMILIES (plan E2 a/b/c)
 * -------------------------------------------------
 * (a) **multi-local branch merges** — >=2 locals initialised from state fields
 *     and reassigned across an `if`, including the asymmetric (arms rebind
 *     DIFFERENT locals) variant that is the PALMER-1 shape, plus k=1, k=2,
 *     k=3+, both-arms-rebind, if-without-else, nested-if, and — the issue-#149
 *     shape — NESTED-SIBLING: an inner `if` that rebinds only a PREFIX of the
 *     locals (leaving >=1 live untouched sibling in the region inherited from
 *     the enclosing arm) under an outer `if` that has NO else. See the
 *     `ArmStyle` comment for why BOTH halves are required and why the corpus
 *     was blind to this shape while a fund-safety defect was open.
 * (b) **1-byte OP_N-range ByteString state** — `0x01`..`0x10` and `0x81`, plus
 *     `0x00`, empty `""`, 1-byte-outside-range and multi-byte (the PALMER-2
 *     shape), AND **negative bigint state** (`-1`, `-2`, `-128`, ...): a
 *     fund-safety bug was confirmed in a peer tier's `-1` encoding and no
 *     generator or checked-in golden anywhere produced a negative state value.
 * (d) **loop-carried locals fed to `addOutput`** — the construct ledger's
 *     `loop-carried-locals-k2`. A bounded loop carries >=2 locals across
 *     iterations and both are handed to `this.addOutput(...)`, so the post-loop
 *     values are the state the covenant commits to. Includes the confirmed
 *     2026-08-06 miscompile shape (a carried local REASSIGNED and then READ
 *     AGAIN in the same iteration), its read-before-reassign and no-cross-read
 *     controls, and both NESTED forms. This family exists because a
 *     verdict-only oracle cannot see it: at one iteration the source and the
 *     miscompiled script agree on the VALUE and the spend is still rejected,
 *     and at N>1 the script is happily spendable with the WRONG total. Only a
 *     post-state VALUE pin catches it, which is exactly what this generator's
 *     independent model provides.
 *
 * (c) **multi-slot constructor-arg shapes** — several `constructorSlots` of
 *     mixed types, deliberately including a case where an EARLIER slot's
 *     encoded length differs from its 1-byte `OP_0` template placeholder, so
 *     every later slot's deployed offset shifts. Each slot is referenced by an
 *     equality assert against its own baked value, which makes a mis-splice an
 *     on-chain script REJECTION rather than a silent byte difference.
 *
 * DETERMINISM
 * -----------
 * `generateShapes(seed, count)` is a pure function of (seed, count). Case `i`
 * always draws the same "primary family" (round-robin, so even a 20-case PR
 * gate covers every construct at least once) and the same mulberry32 draws for
 * everything else. Re-running with the same seed reproduces the exact corpus.
 */

// ---------------------------------------------------------------------------
// Value / tag vocabulary
// ---------------------------------------------------------------------------

/** Rúnar types this generator models end-to-end (source + wire + model). */
export type ShapeType = 'bigint' | 'boolean' | 'ByteString' | 'PubKey';

/** A concrete value: bigint / boolean / lowercase hex (ByteString, PubKey). */
export type ShapeValue = bigint | boolean | string;

/**
 * Construct tags. The E2 unit test asserts a seeded run reaches every one of
 * these, so this list doubles as the machine-checked construct inventory for
 * the Spend-oracle corpus.
 */
export type ShapeTag =
  // (a) branch merges
  | 'merge-locals-k1'
  | 'merge-locals-k2'
  | 'merge-locals-k3plus'
  | 'merge-both-arms'
  | 'merge-asymmetric'
  | 'merge-no-else'
  | 'merge-nested-if'
  | 'merge-nested-sibling'
  // (b) state value classes
  | 'state-bytestring-empty'
  | 'state-bytestring-0x00'
  | 'state-bytestring-op-n'
  | 'state-bytestring-1byte-outside'
  | 'state-bytestring-multibyte'
  | 'state-bigint-zero'
  | 'state-bigint-negative'
  | 'state-bigint-op-n'
  | 'state-bigint-large'
  | 'state-boolean'
  | 'state-pubkey'
  // (c) constructor-arg slots
  | 'ctor-slots-multi'
  | 'ctor-slots-shifting-offsets'
  | 'ctor-slot-bytestring-op-n'
  // (d) loop-carried locals -> addOutput
  | 'loop-carried-locals-k1'
  | 'loop-carried-locals-k2'
  | 'loop-cross-read'
  | 'loop-read-before-reassign'
  | 'loop-independent'
  | 'loop-nested'
  // intent
  | 'intent-reject';

/** Every tag the corpus must reach (E2 acceptance list). */
export const REQUIRED_TAGS: readonly ShapeTag[] = [
  'merge-locals-k1',
  'merge-locals-k2',
  'merge-locals-k3plus',
  'merge-both-arms',
  'merge-asymmetric',
  'merge-no-else',
  'merge-nested-if',
  'merge-nested-sibling',
  'state-bytestring-empty',
  'state-bytestring-0x00',
  'state-bytestring-op-n',
  'state-bytestring-1byte-outside',
  'state-bytestring-multibyte',
  'state-bigint-zero',
  'state-bigint-negative',
  'state-bigint-op-n',
  'state-bigint-large',
  'state-boolean',
  'state-pubkey',
  'ctor-slots-multi',
  'ctor-slots-shifting-offsets',
  'ctor-slot-bytestring-op-n',
  'loop-carried-locals-k1',
  'loop-carried-locals-k2',
  'loop-cross-read',
  'loop-read-before-reassign',
  'loop-independent',
  'loop-nested',
  'intent-reject',
];

// ---------------------------------------------------------------------------
// Emitted shape
// ---------------------------------------------------------------------------

export interface ShapeMember {
  name: string;
  type: ShapeType;
  value: ShapeValue;
}

export interface GeneratedShape {
  /** Stable id: `<seed>-<index>-<family>`. Printed on every finding. */
  id: string;
  /** Index within the generated corpus (replay handle). */
  index: number;
  /** Primary construct family this case was drawn for. */
  family: string;
  contractName: string;
  fileName: string;
  source: string;
  tags: ShapeTag[];
  /** `readonly` properties → artifact `constructorSlots`, in declaration order. */
  slots: ShapeMember[];
  /** Mutable properties → the OP_RETURN state section, in declaration order. */
  fields: ShapeMember[];
  /** Positional constructor args: slots then fields, declaration order. */
  constructorArgs: ShapeValue[];
  method: string;
  methodParams: { name: string; type: ShapeType }[];
  methodArgs: ShapeValue[];
  /**
   * The generator's OWN model of the post-call state, decided when the values
   * were picked. `null` for `intent: 'reject'` (no continuation exists).
   *
   * This is NOT derived from the compiler, the ANF interpreter, or the SDK.
   */
  expectedState: Record<string, ShapeValue> | null;
  /** What the generator says the real Script engine must do. */
  intent: 'accept' | 'reject';
  /** Satoshis in the explicit `this.addOutput(<sats>, ...)` continuation. */
  continuationSatoshis: number;
  /**
   * Phase E4 — SEMANTICS-PRESERVING rewrites of `source`. Each variant must
   * produce the SAME engine verdict AND the SAME `expectedState` bytes; a
   * difference is a miscompile that depends on something the source semantics
   * do not (a name, or which arm a value came from).
   *
   * `renameLocals` — every merged local `lN` renamed to `mlN`.
   * `swapArms`     — the two arms of a plain `if/else` exchanged and the
   *                  condition negated (`p0 > 0n` <-> `p0 <= 0n`). `null` for
   *                  the `no-else` / `nested` / single-armed forms, which have
   *                  no pure arm pair to swap.
   */
  variants: { renameLocals: string; swapArms: string | null };
}

// ---------------------------------------------------------------------------
// Deterministic RNG (mulberry32 — same one the ANF / execute fuzzers use)
// ---------------------------------------------------------------------------

function mulberry32(a: number): () => number {
  let state = a >>> 0;
  return function next(): number {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 0x100000000;
  };
}

function pick<T>(rng: () => number, xs: readonly T[]): T {
  return xs[Math.floor(rng() * xs.length) % xs.length]!;
}

function intIn(rng: () => number, lo: number, hi: number): number {
  return lo + Math.floor(rng() * (hi - lo + 1));
}

// ---------------------------------------------------------------------------
// Value classes
// ---------------------------------------------------------------------------

interface ClassedValue {
  value: ShapeValue;
  tag: ShapeTag;
}

/** Two fixed 33-byte compressed pubkeys (valid points; never signed with). */
const PUBKEY_A = '02' + 'a1'.repeat(32);
const PUBKEY_B = '03' + 'b2'.repeat(32);

/**
 * ByteString state value classes. The 1-byte `0x01`..`0x10` / `0x81` rows are
 * the PALMER-2 shape: those are exactly the payloads a MINIMALDATA push encoder
 * collapses to `OP_1`..`OP_16` / `OP_1NEGATE`, while the compiler's on-chain
 * state codec writes `<len><data>`. Framing the state section with MINIMALDATA
 * makes such a contract permanently unspendable.
 */
const BYTESTRING_CLASSES: readonly ClassedValue[] = [
  { value: '', tag: 'state-bytestring-empty' },
  { value: '00', tag: 'state-bytestring-0x00' },
  { value: '01', tag: 'state-bytestring-op-n' },
  { value: '05', tag: 'state-bytestring-op-n' },
  { value: '0a', tag: 'state-bytestring-op-n' },
  { value: '10', tag: 'state-bytestring-op-n' },
  { value: '81', tag: 'state-bytestring-op-n' },
  { value: '11', tag: 'state-bytestring-1byte-outside' },
  { value: 'ff', tag: 'state-bytestring-1byte-outside' },
  { value: '0011', tag: 'state-bytestring-multibyte' },
  { value: 'deadbeef', tag: 'state-bytestring-multibyte' },
  { value: 'c0'.repeat(20), tag: 'state-bytestring-multibyte' },
];

/**
 * bigint state value classes. `-1` / `-2` / `-128` are here because a peer
 * tier's negative-value state encoding was a confirmed fund-safety bug and no
 * generator or checked-in golden anywhere produced a negative state value.
 */
const BIGINT_CLASSES: readonly ClassedValue[] = [
  { value: 0n, tag: 'state-bigint-zero' },
  { value: 1n, tag: 'state-bigint-op-n' },
  { value: 7n, tag: 'state-bigint-op-n' },
  { value: 16n, tag: 'state-bigint-op-n' },
  { value: -1n, tag: 'state-bigint-negative' },
  { value: -2n, tag: 'state-bigint-negative' },
  { value: -128n, tag: 'state-bigint-negative' },
  { value: -70000n, tag: 'state-bigint-negative' },
  { value: 17n, tag: 'state-bigint-large' },
  { value: 127n, tag: 'state-bigint-large' },
  { value: 128n, tag: 'state-bigint-large' },
  { value: 70000n, tag: 'state-bigint-large' },
  { value: 2147483647n, tag: 'state-bigint-large' },
];

const BOOLEAN_CLASSES: readonly ClassedValue[] = [
  { value: true, tag: 'state-boolean' },
  { value: false, tag: 'state-boolean' },
];

const PUBKEY_CLASSES: readonly ClassedValue[] = [
  { value: PUBKEY_A, tag: 'state-pubkey' },
  { value: PUBKEY_B, tag: 'state-pubkey' },
];

function classesFor(t: ShapeType): readonly ClassedValue[] {
  switch (t) {
    case 'bigint':
      return BIGINT_CLASSES;
    case 'boolean':
      return BOOLEAN_CLASSES;
    case 'ByteString':
      return BYTESTRING_CLASSES;
    case 'PubKey':
      return PUBKEY_CLASSES;
  }
}

/**
 * Encoded byte length of a constructor-slot value in the DEPLOYED code part.
 * Mirrors the encoding classes documented in `packages/runar-sdk/slot-layout.ts`
 * — reimplemented here (not imported) so the "does this slot shift later slot
 * offsets?" tag is decided by this generator, not by the code under test.
 * The template placeholder is a single `OP_0` byte, so any length != 1 shifts
 * every later slot.
 */
function slotEncodedLength(type: ShapeType, value: ShapeValue): number {
  if (type === 'boolean') return 1; // OP_1 / OP_0
  if (type === 'bigint') {
    const n = value as bigint;
    if (n === 0n) return 1; // OP_0
    if (n === -1n) return 1; // OP_1NEGATE
    if (n >= 1n && n <= 16n) return 1; // OP_1..OP_16
    // scriptnum push: 1 header byte + LE sign-magnitude payload
    let mag = n < 0n ? -n : n;
    let bytes = 0;
    while (mag > 0n) {
      mag >>= 8n;
      bytes += 1;
    }
    // extra sign byte when the MSB of the top payload byte is already used
    const abs = n < 0n ? -n : n;
    if ((abs >> BigInt((bytes - 1) * 8)) & 0x80n) bytes += 1;
    return 1 + bytes;
  }
  // ByteString / PubKey data push
  const hex = value as string;
  const len = hex.length / 2;
  if (len === 0) return 1; // OP_0
  if (len <= 75) return 1 + len;
  if (len <= 0xff) return 2 + len;
  if (len <= 0xffff) return 3 + len;
  return 5 + len;
}

// ---------------------------------------------------------------------------
// Independent state-section codec (the ABSOLUTE pin)
// ---------------------------------------------------------------------------

/**
 * Encode a state section exactly the way the COMPILER's on-chain codec does
 * (`emitPushDataEncode` in `packages/runar-compiler/src/passes/05-stack-lower.ts`
 * plus the fixed-width NUM2BIN / bool layout).
 *
 * Deliberately a SECOND implementation: it does not import
 * `runar-sdk`'s `serializeState`, because the whole point of the Spend-oracle
 * job is to have a pin the SDK's encoder cannot co-change with (PALMER-2 moved
 * all seven SDK encoders AND all seven SDK decoders in one commit and every
 * round-trip test stayed green).
 *
 *   bigint     -> 8 raw bytes, little-endian sign-magnitude (sign bit = MSB of
 *                 the last byte)
 *   boolean    -> 1 raw byte 0x00 / 0x01
 *   PubKey     -> 33 raw bytes
 *   ByteString -> <len><data>, NEVER MINIMALDATA
 */
export function encodeStateSectionHex(fields: readonly ShapeMember[], values: Record<string, ShapeValue>): string {
  let hex = '';
  for (const f of fields) {
    const v = values[f.name];
    switch (f.type) {
      case 'bigint':
        hex += num2binLE8(v as bigint);
        break;
      case 'boolean':
        hex += v ? '01' : '00';
        break;
      case 'PubKey':
        hex += v as string;
        break;
      case 'ByteString': {
        const data = v as string;
        const len = data.length / 2;
        if (len <= 75) hex += len.toString(16).padStart(2, '0') + data;
        else if (len <= 0xff) hex += '4c' + len.toString(16).padStart(2, '0') + data;
        else {
          const lo = (len & 0xff).toString(16).padStart(2, '0');
          const hi = ((len >> 8) & 0xff).toString(16).padStart(2, '0');
          hex += '4d' + lo + hi + data;
        }
        break;
      }
    }
  }
  return hex;
}

/** 8-byte LE sign-magnitude (OP_NUM2BIN 8) encoding of a bigint. */
function num2binLE8(n: bigint): string {
  const bytes = new Uint8Array(8);
  const negative = n < 0n;
  let mag = negative ? -n : n;
  for (let i = 0; i < 8 && mag > 0n; i++) {
    bytes[i] = Number(mag & 0xffn);
    mag >>= 8n;
  }
  if (negative) bytes[7]! |= 0x80;
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

// ---------------------------------------------------------------------------
// Source rendering
// ---------------------------------------------------------------------------

function tsLiteral(type: ShapeType, v: ShapeValue): string {
  switch (type) {
    case 'bigint':
      return `${v as bigint}n`;
    case 'boolean':
      return String(v);
    default:
      return `'${v as string}'`;
  }
}

function tsTypeName(t: ShapeType): string {
  return t;
}

// ---------------------------------------------------------------------------
// Shape families (round-robin primary construct)
// ---------------------------------------------------------------------------

/**
 * `nested-sibling` is the issue-#149 shape and the reason the plain `nested`
 * style could never reach it. Two degrees of freedom have to be drawn TOGETHER,
 * and `nested` supplies neither:
 *
 *  1. the INNER `if` rebinds only a PREFIX of the locals, so >=1 sibling stays
 *     LIVE and UNTOUCHED in the region the arm inherited from its parent. When
 *     every local is a declared result of the inner `if` (what `nested` does)
 *     there is no inherited slot left for an adopted result to rotate past, so
 *     the adopt-then-remove sequence cannot disturb any layout;
 *  2. the OUTER `if` has NO else, so only ONE outer path rearranges that region
 *     and the two paths leave equal DEPTH with different LAYOUT. With an outer
 *     else both paths get rearranged and the post-`OP_ENDIF` reads resolve the
 *     same way on either.
 *
 * This is a MEASURED reachability claim, not a plausible-sounding one. Against
 * the compiler as it stood before `fix(stack-lower): restore inherited slot
 * order after adopting declared results`, the corpus WITHOUT this style
 * reported 0 failures over 4000 cases / 11,750 spend inputs while the defect
 * was open and reproducible by hand; WITH it, seed 20260817 at `--num 400`
 * reports 62 failures over 2590 spend inputs (31 `reject-when-accept-intended`
 * + 31 `interpreter-vs-spend`) — unspendable UTXOs, i.e. fund loss. The same
 * seed and count report 0 once that fix is applied.
 */
type ArmStyle = 'both' | 'asymmetric' | 'no-else' | 'nested' | 'nested-sibling';

/**
 * Loop-body topologies (d). `cross-read` is the confirmed 2026-08-06
 * miscompile: the carried local is rebound and then READ AGAIN by a different
 * statement in the same iteration. The other four are its controls and its
 * nested variants; the generator must reach all of them so a failure names a
 * topology rather than "loops".
 */
type LoopStyle =
  | 'single'
  | 'independent'
  | 'cross-read'
  | 'read-before'
  | 'nested-cross-read'
  | 'nested-outer-read';

interface LoopSpec {
  style: LoopStyle;
  /** Iterations of the (outer) loop. */
  outer: number;
  /** Iterations of the inner loop — nested styles only. */
  inner?: number;
}

interface FamilySpec {
  name: string;
  /** Number of merged locals (== number of mutable state fields). */
  k?: number;
  arms?: ArmStyle;
  /** Pin one state field to this value class (index 0). */
  pinnedValue?: ShapeValue;
  /** Pin the type of state field 0. */
  pinnedType?: ShapeType;
  /** Force this many readonly constructor-slot properties. */
  slotCount?: number;
  /** Force the slot type list (drives the offset-shift case). */
  slotTypes?: ShapeType[];
  slotValues?: ShapeValue[];
  intent?: 'accept' | 'reject';
  /**
   * (d) Emit a bounded LOOP over the carried locals instead of an `if`. Every
   * state field is forced to `bigint` and `p0` becomes the loop step, so the
   * post-state is a plain arithmetic function of values this generator picked.
   */
  loop?: LoopSpec;
}

/**
 * Round-robin family list. Case `i` uses `FAMILIES[i % FAMILIES.length]`, so a
 * 20-case PR run touches every construct at least once and larger runs vary
 * everything else randomly around it.
 */
const FAMILIES: readonly FamilySpec[] = [
  { name: 'merge-k1-both', k: 1, arms: 'both' },
  { name: 'merge-k2-both', k: 2, arms: 'both' },
  { name: 'merge-k2-asymmetric', k: 2, arms: 'asymmetric' },
  { name: 'merge-k2-no-else', k: 2, arms: 'no-else' },
  { name: 'merge-k3-both', k: 3, arms: 'both' },
  { name: 'merge-k3-asymmetric', k: 3, arms: 'asymmetric' },
  { name: 'merge-k4-asymmetric', k: 4, arms: 'asymmetric' },
  { name: 'merge-nested-if', k: 2, arms: 'nested' },
  { name: 'merge-k3-nested-if', k: 3, arms: 'nested' },
  // The issue-#149 family: inner `if` rebinds a PREFIX (>=1 live untouched
  // sibling), outer `if` has NO else. Drawn at k=2/3/4 because the number of
  // inherited slots the adopted results have to cross — and therefore whether
  // the rotation is observable at all — is a function of k minus the prefix.
  { name: 'merge-k2-nested-sibling', k: 2, arms: 'nested-sibling' },
  { name: 'merge-k3-nested-sibling', k: 3, arms: 'nested-sibling' },
  { name: 'merge-k4-nested-sibling', k: 4, arms: 'nested-sibling' },
  { name: 'state-bytestring-op-n', k: 2, pinnedType: 'ByteString', pinnedValue: '05' },
  { name: 'state-bytestring-op-n-high', k: 2, pinnedType: 'ByteString', pinnedValue: '10' },
  { name: 'state-bytestring-op-1negate', k: 2, pinnedType: 'ByteString', pinnedValue: '81' },
  { name: 'state-bytestring-0x00', k: 2, pinnedType: 'ByteString', pinnedValue: '00' },
  { name: 'state-bytestring-empty', k: 2, pinnedType: 'ByteString', pinnedValue: '' },
  { name: 'state-bytestring-outside', k: 2, pinnedType: 'ByteString', pinnedValue: 'ff' },
  { name: 'state-bytestring-multibyte', k: 2, pinnedType: 'ByteString', pinnedValue: 'deadbeef' },
  { name: 'state-bigint-negative-one', k: 2, pinnedType: 'bigint', pinnedValue: -1n },
  { name: 'state-bigint-negative-large', k: 2, pinnedType: 'bigint', pinnedValue: -70000n },
  { name: 'state-bigint-zero', k: 2, pinnedType: 'bigint', pinnedValue: 0n },
  { name: 'state-bigint-large', k: 2, pinnedType: 'bigint', pinnedValue: 2147483647n },
  { name: 'state-boolean', k: 2, pinnedType: 'boolean', pinnedValue: true },
  { name: 'state-pubkey', k: 2, pinnedType: 'PubKey', pinnedValue: PUBKEY_A },
  {
    // (c) EARLY slot is a 34-byte push while its template placeholder is one
    // OP_0 byte, so both later slots' deployed offsets shift by 33.
    name: 'ctor-slots-shifting',
    k: 2,
    slotTypes: ['PubKey', 'bigint', 'ByteString'],
    slotValues: [PUBKEY_B, 70000n, 'deadbeef'],
  },
  {
    // (c) mixed slot types incl. a 1-byte OP_N-range ByteString slot — the
    // UNLOCK/splice side of the PALMER-2 value class (which must stay
    // MINIMALDATA, unlike the state section).
    name: 'ctor-slots-mixed',
    k: 2,
    slotTypes: ['ByteString', 'bigint', 'boolean', 'PubKey'],
    slotValues: ['05', 5n, true, PUBKEY_A],
  },
  { name: 'reject-guard', k: 2, intent: 'reject' },
  // (d) loop-carried locals -> addOutput. `loop-k2-cross-read` is the ledger's
  // `loop-carried-locals-k2` proper; the rest are its controls and nested
  // variants. k=1 is here because ONE iteration of the cross-read shape is
  // value-identical to the source and still leaves an unspendable UTXO — the
  // case a value-only oracle would call covered.
  { name: 'loop-k1-single', k: 1, loop: { style: 'single', outer: 3 } },
  { name: 'loop-k2-cross-read', k: 2, loop: { style: 'cross-read', outer: 3 } },
  { name: 'loop-k2-cross-read-1iter', k: 2, loop: { style: 'cross-read', outer: 1 } },
  { name: 'loop-k2-read-before', k: 2, loop: { style: 'read-before', outer: 3 } },
  { name: 'loop-k2-independent', k: 2, loop: { style: 'independent', outer: 3 } },
  { name: 'loop-k2-nested-cross-read', k: 2, loop: { style: 'nested-cross-read', outer: 2, inner: 2 } },
  { name: 'loop-k2-nested-outer-read', k: 2, loop: { style: 'nested-outer-read', outer: 2, inner: 2 } },
];

/**
 * How many cases a run must generate to touch every family at least once.
 * `generateShapes` draws `FAMILIES[i % FAMILIES.length]`, so a run with
 * `--num` below this NEVER reaches the tail families. The CI gates pass
 * `--num` explicitly; keep them at or above this number.
 */
export const REQUIRED_CASE_COUNT = FAMILIES.length;

// ---------------------------------------------------------------------------
// Generator
// ---------------------------------------------------------------------------

const FIELD_TYPES: readonly ShapeType[] = ['bigint', 'ByteString', 'boolean', 'PubKey'];

/** Initial values for loop-carried state. Small: the post-state is
 *  `init + step*iterations` (or its triangular sum) and must stay a
 *  well-behaved script number in every intermediate. */
const LOOP_SEED_VALUES: readonly bigint[] = [0n, 1n, 7n, -1n, -2n];

const LOOP_STYLE_TAGS: Record<LoopStyle, ShapeTag> = {
  single: 'loop-independent',
  independent: 'loop-independent',
  'cross-read': 'loop-cross-read',
  'read-before': 'loop-read-before-reassign',
  'nested-cross-read': 'loop-nested',
  'nested-outer-read': 'loop-nested',
};

/**
 * THE MODEL for a loop family: the post-loop value of every carried local,
 * evaluated here in plain TypeScript from values this generator picked.
 *
 * It mirrors `renderLoop` statement for statement and is never derived from
 * the compiler, the ANF interpreter or the SDK — same independence rule as the
 * branch-merge model above. A miscompiled loop therefore disagrees with this
 * function, which is exactly the `expected-state-mismatch` the Spend oracle
 * reports.
 */
function modelLoop(spec: LoopSpec, init: bigint[], step: bigint): bigint[] {
  const l = [...init];
  const inner = spec.inner ?? 1;
  for (let i = 0; i < spec.outer; i++) {
    for (let j = 0; j < inner; j++) {
      switch (spec.style) {
        case 'single':
          l[0] = l[0]! + step;
          break;
        case 'independent':
          l[0] = l[0]! + step;
          l[1] = l[1]! + step;
          break;
        case 'cross-read':
        case 'nested-cross-read':
          l[0] = l[0]! + step;
          l[1] = l[1]! + l[0]!; // reads the local just rebound, same iteration
          break;
        case 'read-before':
          l[1] = l[1]! + l[0]!; // reads BEFORE the rebind
          l[0] = l[0]! + step;
          break;
        case 'nested-outer-read':
          l[0] = l[0]! + step;
          break;
      }
    }
    // `nested-outer-read`: the carried local is rebound only in the INNER body
    // and read here, one scope out.
    if (spec.style === 'nested-outer-read') l[1] = l[1]! + l[0]!;
  }
  return l;
}

export interface GenerateShapesOptions {
  seed: number;
  count: number;
}

export function generateShapes(opts: GenerateShapesOptions): GeneratedShape[] {
  const out: GeneratedShape[] = [];
  for (let i = 0; i < opts.count; i++) {
    // Per-case RNG: derived from (seed, i) so a single case can be replayed
    // without regenerating its predecessors.
    const rng = mulberry32((opts.seed ^ (i * 0x9e3779b9)) >>> 0);
    out.push(buildShape(opts.seed, i, FAMILIES[i % FAMILIES.length]!, rng));
  }
  return out;
}

function buildShape(seed: number, index: number, fam: FamilySpec, rng: () => number): GeneratedShape {
  const tags = new Set<ShapeTag>();
  const intent = fam.intent ?? 'accept';
  if (intent === 'reject') tags.add('intent-reject');

  // ---- constructor slots (readonly props) --------------------------------
  const slotTypes: ShapeType[] =
    fam.slotTypes ?? Array.from({ length: fam.slotCount ?? intIn(rng, 0, 2) }, () => pick(rng, FIELD_TYPES));
  const slots: ShapeMember[] = slotTypes.map((t, si) => {
    const v = fam.slotValues?.[si] ?? pick(rng, classesFor(t)).value;
    return { name: `s${si}`, type: t, value: v };
  });
  if (slots.length >= 2) tags.add('ctor-slots-multi');
  // A non-final slot whose encoded length differs from the 1-byte template
  // placeholder shifts every later slot's deployed offset.
  for (let si = 0; si < slots.length - 1; si++) {
    if (slotEncodedLength(slots[si]!.type, slots[si]!.value) !== 1) {
      tags.add('ctor-slots-shifting-offsets');
      break;
    }
  }
  for (const s of slots) {
    if (s.type === 'ByteString') {
      const hex = s.value as string;
      if (hex.length === 2 && (isOpNByte(hex) || hex === '81')) tags.add('ctor-slot-bytestring-op-n');
    }
  }

  // ---- mutable state fields (== merged / loop-carried locals) ------------
  const k = fam.k ?? intIn(rng, 1, 4);
  const fields: ShapeMember[] = [];
  for (let fi = 0; fi < k; fi++) {
    const pinned = fi === 0 && fam.pinnedType !== undefined;
    // A loop accumulates, so every carried local must be arithmetic. The value
    // classes are the SMALL ones: the post-state is `init + step*iterations`
    // (or its triangular sum), which must stay a well-behaved script number.
    if (fam.loop !== undefined) {
      const v = pick(rng, LOOP_SEED_VALUES);
      fields.push({ name: `f${fi}`, type: 'bigint', value: v });
      tags.add(v === 0n ? 'state-bigint-zero' : v < 0n ? 'state-bigint-negative' : 'state-bigint-op-n');
      continue;
    }
    const type: ShapeType = pinned ? fam.pinnedType! : pick(rng, FIELD_TYPES);
    // A family that pins a value class pins it as field 0's INITIAL state, so
    // the deploy-time state section (checked against the independent codec) is
    // guaranteed to carry that class on every seed.
    const cv =
      pinned && fam.pinnedValue !== undefined
        ? (classesFor(type).find((c) => c.value === fam.pinnedValue) ?? {
            value: fam.pinnedValue,
            tag: classesFor(type)[0]!.tag,
          })
        : pick(rng, classesFor(type));
    fields.push({ name: `f${fi}`, type, value: cv.value });
    tags.add(cv.tag);
  }

  // ---- method params ------------------------------------------------------
  // p0 (bigint) drives the branch condition and the guard assert; the rest
  // supply arm values of each type actually used by the fields.
  const usedTypes = new Set(fields.map((f) => f.type));
  const methodParams: { name: string; type: ShapeType }[] = [{ name: 'p0', type: 'bigint' }];
  const paramByType = new Map<ShapeType, string>([['bigint', 'p0']]);
  let pi = 1;
  for (const t of ['ByteString', 'PubKey', 'boolean'] as ShapeType[]) {
    if (usedTypes.has(t)) {
      const nm = `p${pi++}`;
      methodParams.push({ name: nm, type: t });
      paramByType.set(t, nm);
    }
  }

  // Condition: `p0 > 0n`. The generator PICKS whether it holds. For a loop
  // family `p0` is the accumulation STEP instead, so it stays small and
  // positive and the guard is trivially satisfied.
  const condTrue = fam.loop !== undefined ? true : rng() < 0.5;
  const p0Value =
    fam.loop !== undefined
      ? BigInt(intIn(rng, 1, 6))
      : condTrue
        ? BigInt(intIn(rng, 1, 4000))
        : BigInt(intIn(rng, -4000, 0));
  const methodArgs: ShapeValue[] = [p0Value];
  for (const p of methodParams.slice(1)) {
    methodArgs.push(pickParamValue(rng, p.type, tags));
  }
  const paramValue = new Map<string, ShapeValue>();
  methodParams.forEach((p, idx) => paramValue.set(p.name, methodArgs[idx]!));

  // Nested inner condition: `p0 > 2000n`.
  const innerTrue = condTrue && p0Value > 2000n;

  // ---- arm assignments ----------------------------------------------------
  const arms =
    fam.arms ?? pick(rng, ['both', 'asymmetric', 'no-else', 'nested', 'nested-sibling'] as ArmStyle[]);
  if (fam.loop !== undefined) {
    tags.add(k === 1 ? 'loop-carried-locals-k1' : 'loop-carried-locals-k2');
    tags.add(LOOP_STYLE_TAGS[fam.loop.style]);
  } else {
    if (k === 1) tags.add('merge-locals-k1');
    else if (k === 2) tags.add('merge-locals-k2');
    else tags.add('merge-locals-k3plus');
    if (arms === 'both') tags.add('merge-both-arms');
    else if (arms === 'asymmetric') tags.add('merge-asymmetric');
    else if (arms === 'no-else') tags.add('merge-no-else');
    else if (arms === 'nested') tags.add('merge-nested-if');
    else tags.add('merge-nested-sibling');
  }

  /** One arm's assignments: local index -> (source expression, modelled value). */
  type Assignment = { expr: string; value: ShapeValue };

  const armValue = (f: ShapeMember): Assignment => {
    const pname = paramByType.get(f.type);
    // Prefer the method param when one of the right type exists (exercises the
    // witness -> merged-local -> state path); otherwise a fresh literal.
    if (pname !== undefined && rng() < 0.5) {
      return { expr: pname, value: paramValue.get(pname)! };
    }
    const cv = pick(rng, classesFor(f.type));
    tags.add(cv.tag);
    return { expr: tsLiteral(f.type, cv.value), value: cv.value };
  };

  const thenAssign = new Map<number, Assignment>();
  const elseAssign = new Map<number, Assignment>();
  const innerThenAssign = new Map<number, Assignment>();
  const innerElseAssign = new Map<number, Assignment>();

  switch (fam.loop !== undefined ? ('__loop' as const) : arms) {
    case '__loop':
      break; // a loop family has no arms; its locals are driven by the loop
    case 'both':
      for (let fi = 0; fi < k; fi++) {
        thenAssign.set(fi, armValue(fields[fi]!));
        elseAssign.set(fi, armValue(fields[fi]!));
      }
      break;
    case 'no-else':
      for (let fi = 0; fi < k; fi++) thenAssign.set(fi, armValue(fields[fi]!));
      break;
    case 'asymmetric': {
      // Split the locals into two DISJOINT, non-empty-when-possible halves:
      // the then-arm rebinds the first half, the else-arm the second. This is
      // the exact PALMER-1 shape (arms reassign DIFFERENT locals).
      const split = k === 1 ? 1 : intIn(rng, 1, k - 1);
      for (let fi = 0; fi < split; fi++) thenAssign.set(fi, armValue(fields[fi]!));
      for (let fi = split; fi < k; fi++) elseAssign.set(fi, armValue(fields[fi]!));
      break;
    }
    case 'nested':
      // Outer then-arm holds an inner if whose two arms both rebind all k;
      // the outer else-arm rebinds all k directly.
      for (let fi = 0; fi < k; fi++) {
        innerThenAssign.set(fi, armValue(fields[fi]!));
        innerElseAssign.set(fi, armValue(fields[fi]!));
        elseAssign.set(fi, armValue(fields[fi]!));
      }
      break;
    case 'nested-sibling': {
      // The #149 shape. Both inner arms rebind the same PREFIX `l0..l[m-1]`
      // (so `m` locals are the inner `if`'s declared results), and `l[m]..`
      // stay LIVE + UNTOUCHED in the slot region the outer arm inherited —
      // the slots an adopted result has to cross. `elseAssign` is left EMPTY:
      // the outer `if` renders with no else, so its fall-through path keeps
      // the pre-`if` layout while the taken path rotates it.
      //
      // The inner `if` keeps a real else on purpose: the confirmed #149 inner
      // `if` had one, and the repair must not be gated on its absence.
      const m = k <= 1 ? 1 : intIn(rng, 1, k - 1);
      for (let fi = 0; fi < m; fi++) {
        innerThenAssign.set(fi, armValue(fields[fi]!));
        innerElseAssign.set(fi, armValue(fields[fi]!));
      }
      break;
    }
  }

  // ---- THE MODEL: post-state, decided here, not read back -----------------
  const expectedState: Record<string, ShapeValue> = {};
  if (fam.loop !== undefined) {
    // (d): the post-state is the loop's arithmetic on the values picked above.
    const post = modelLoop(fam.loop, fields.map((f) => f.value as bigint), p0Value);
    fields.forEach((f, fi) => {
      expectedState[f.name] = post[fi]!;
    });
  }
  // (a)-(c): the post-state is whichever arm the chosen `p0` takes.
  for (let fi = 0; fam.loop === undefined && fi < k; fi++) {
    const f = fields[fi]!;
    let v: ShapeValue = f.value; // pre-branch local value = the state field
    if (arms === 'nested' || arms === 'nested-sibling') {
      if (condTrue) {
        // A local outside the inner `if`'s rebound prefix has no entry in
        // either inner map, so it correctly keeps its pre-branch value — that
        // is precisely the untouched live sibling.
        const a = innerTrue ? innerThenAssign.get(fi) : innerElseAssign.get(fi);
        if (a) v = a.value;
      } else {
        // `nested-sibling` has no outer else, so this map is empty and every
        // local keeps its pre-branch value on the fall-through path.
        const a = elseAssign.get(fi);
        if (a) v = a.value;
      }
    } else if (condTrue) {
      const a = thenAssign.get(fi);
      if (a) v = a.value;
    } else {
      const a = elseAssign.get(fi);
      if (a) v = a.value;
    }
    expectedState[f.name] = v;
  }

  // ---- render source ------------------------------------------------------
  const contractName = `Shape${index}`;
  const renderOpts: RenderOptions = {
    contractName,
    slots,
    fields,
    methodParams,
    guardTrue: intent === 'accept',
    guardValue: p0Value,
    arms,
    thenAssign,
    elseAssign,
    innerThenAssign,
    innerElseAssign,
    continuationSatoshis: 1000,
    loop: fam.loop,
  };
  const source = renderShape(renderOpts);

  // Phase E4 metamorphic variants — semantics-preserving rewrites.
  const swappable =
    arms !== 'nested' &&
    arms !== 'nested-sibling' &&
    arms !== 'no-else' &&
    thenAssign.size > 0 &&
    elseAssign.size > 0;
  const variants = {
    renameLocals: renameLocals(source),
    swapArms: swappable ? renderShape({ ...renderOpts, swapArms: true }) : null,
  };

  return {
    id: `${seed}-${index}-${fam.name}`,
    index,
    family: fam.name,
    contractName,
    fileName: `${contractName}.runar.ts`,
    source,
    tags: [...tags].sort(),
    slots,
    fields,
    constructorArgs: [...slots.map((s) => s.value), ...fields.map((f) => f.value)],
    method: 'step',
    methodParams,
    methodArgs,
    expectedState: intent === 'accept' ? expectedState : null,
    intent,
    continuationSatoshis: 1000,
    variants,
  };
}

/**
 * Rename every merged local `lN` -> `mlN`. Purely a naming change: no other
 * identifier this generator emits matches `\bl\d+\b` (properties are `fN`/`sN`,
 * params `pN`, the class `Shape<index>`).
 */
function renameLocals(source: string): string {
  return source.replace(/\bl(\d+)\b/g, 'ml$1');
}

function isOpNByte(hex: string): boolean {
  const b = parseInt(hex, 16);
  return b >= 0x01 && b <= 0x10;
}

function pickParamValue(rng: () => number, t: ShapeType, tags: Set<ShapeTag>): ShapeValue {
  const cv = pick(rng, classesFor(t));
  tags.add(cv.tag);
  return cv.value;
}

interface RenderOptions {
  contractName: string;
  slots: ShapeMember[];
  fields: ShapeMember[];
  methodParams: { name: string; type: ShapeType }[];
  guardTrue: boolean;
  guardValue: bigint;
  arms: ArmStyle;
  thenAssign: Map<number, { expr: string; value: ShapeValue }>;
  elseAssign: Map<number, { expr: string; value: ShapeValue }>;
  innerThenAssign: Map<number, { expr: string; value: ShapeValue }>;
  innerElseAssign: Map<number, { expr: string; value: ShapeValue }>;
  continuationSatoshis: number;
  /** E4: emit the arms exchanged with the condition negated. */
  swapArms?: boolean;
  /** (d) emit a bounded loop over the carried locals instead of an `if`. */
  loop?: LoopSpec;
}

/** The loop body for a family (d) shape, mirrored exactly by `modelLoop`. */
function renderLoopBody(style: LoopStyle, indent: string): string[] {
  switch (style) {
    case 'single':
      return [`${indent}l0 = l0 + p0;`];
    case 'independent':
      return [`${indent}l0 = l0 + p0;`, `${indent}l1 = l1 + p0;`];
    case 'cross-read':
    case 'nested-cross-read':
      return [`${indent}l0 = l0 + p0;`, `${indent}l1 = l1 + l0;`];
    case 'read-before':
      return [`${indent}l1 = l1 + l0;`, `${indent}l0 = l0 + p0;`];
    case 'nested-outer-read':
      return [`${indent}l0 = l0 + p0;`];
  }
}

function renderLoop(spec: LoopSpec, indent: string): string[] {
  const L: string[] = [];
  L.push(`${indent}for (let i: bigint = 0n; i < ${spec.outer}n; i++) {`);
  if (spec.inner === undefined) {
    L.push(...renderLoopBody(spec.style, `${indent}  `));
  } else {
    L.push(`${indent}  for (let j: bigint = 0n; j < ${spec.inner}n; j++) {`);
    L.push(...renderLoopBody(spec.style, `${indent}    `));
    L.push(`${indent}  }`);
    if (spec.style === 'nested-outer-read') L.push(`${indent}  l1 = l1 + l0;`);
  }
  L.push(`${indent}}`);
  return L;
}

function renderShape(o: RenderOptions): string {
  const all = [...o.slots, ...o.fields];
  const typeNames = new Set<string>();
  for (const m of all) if (m.type === 'ByteString' || m.type === 'PubKey') typeNames.add(m.type);
  for (const p of o.methodParams) if (p.type === 'ByteString' || p.type === 'PubKey') typeNames.add(p.type);

  const L: string[] = [];
  L.push(`import { StatefulSmartContract, assert } from 'runar-lang';`);
  if (typeNames.size > 0) {
    L.push(`import type { ${[...typeNames].sort().join(', ')} } from 'runar-lang';`);
  }
  L.push('');
  L.push(`class ${o.contractName} extends StatefulSmartContract {`);
  for (const s of o.slots) L.push(`  readonly ${s.name}: ${tsTypeName(s.type)};`);
  for (const f of o.fields) L.push(`  ${f.name}: ${tsTypeName(f.type)};`);
  L.push('');
  L.push(
    `  constructor(${all.map((m) => `${m.name}: ${tsTypeName(m.type)}`).join(', ')}) {`,
  );
  L.push(`    super(${all.map((m) => m.name).join(', ')});`);
  for (const m of all) L.push(`    this.${m.name} = ${m.name};`);
  L.push('  }');
  L.push('');
  L.push(
    `  public step(${o.methodParams.map((p) => `${p.name}: ${tsTypeName(p.type)}`).join(', ')}) {`,
  );

  // Guard assert. True by construction for accept-intent, false for reject.
  // Also the reason `assert` is always a used import.
  L.push(
    o.guardTrue
      ? `    assert(p0 >= ${o.guardValue}n);`
      : `    assert(p0 > ${o.guardValue}n);`,
  );

  // Constructor-slot asserts. Each compares the DEPLOYED spliced value against
  // the literal the generator baked, so an off-by-one slot offset or a wrong
  // push encoding is an on-chain REJECTION, not a silent byte difference.
  for (const s of o.slots) {
    if (s.type === 'boolean') {
      L.push(s.value ? `    assert(this.${s.name});` : `    assert(!this.${s.name});`);
    } else {
      L.push(`    assert(this.${s.name} == ${tsLiteral(s.type, s.value)});`);
    }
  }

  // Merged locals.
  o.fields.forEach((f, fi) => {
    L.push(`    let l${fi}: ${tsTypeName(f.type)} = this.${f.name};`);
  });

  const assignLines = (m: Map<number, { expr: string; value: ShapeValue }>, indent: string): string[] =>
    [...m.entries()].sort((a, b) => a[0] - b[0]).map(([fi, a]) => `${indent}l${fi} = ${a.expr};`);

  if (o.loop !== undefined) {
    L.push(...renderLoop(o.loop, '    '));
  } else if (o.arms === 'nested') {
    L.push('    if (p0 > 0n) {');
    L.push('      if (p0 > 2000n) {');
    L.push(...assignLines(o.innerThenAssign, '        '));
    L.push('      } else {');
    L.push(...assignLines(o.innerElseAssign, '        '));
    L.push('      }');
    L.push('    } else {');
    L.push(...assignLines(o.elseAssign, '      '));
    L.push('    }');
  } else if (o.arms === 'nested-sibling') {
    // Outer `if` with NO else; inner `if`/`else` rebinds only the prefix, so
    // the locals below it stay live and untouched inside the outer arm.
    L.push('    if (p0 > 0n) {');
    L.push('      if (p0 > 2000n) {');
    L.push(...assignLines(o.innerThenAssign, '        '));
    L.push('      } else {');
    L.push(...assignLines(o.innerElseAssign, '        '));
    L.push('      }');
    L.push('    }');
  } else if (o.arms === 'no-else' || o.elseAssign.size === 0) {
    L.push('    if (p0 > 0n) {');
    L.push(...assignLines(o.thenAssign, '      '));
    L.push('    }');
  } else if (o.thenAssign.size === 0) {
    // asymmetric with an empty THEN half — render the negated single-arm form
    L.push('    if (p0 <= 0n) {');
    L.push(...assignLines(o.elseAssign, '      '));
    L.push('    }');
  } else if (o.swapArms) {
    // E4 metamorphic: `if (c) A else B`  ==  `if (!c) B else A`.
    L.push('    if (p0 <= 0n) {');
    L.push(...assignLines(o.elseAssign, '      '));
    L.push('    } else {');
    L.push(...assignLines(o.thenAssign, '      '));
    L.push('    }');
  } else {
    L.push('    if (p0 > 0n) {');
    L.push(...assignLines(o.thenAssign, '      '));
    L.push('    } else {');
    L.push(...assignLines(o.elseAssign, '      '));
    L.push('    }');
  }

  L.push(
    `    this.addOutput(${o.continuationSatoshis}n, ${o.fields.map((_, fi) => `l${fi}`).join(', ')});`,
  );
  L.push('  }');
  L.push('}');
  L.push('');
  return L.join('\n');
}
