/**
 * GAP-002 — Property-based cross-tier canonicalJson (RFC 8785 / JCS)
 * differential fuzzer.
 *
 * canonicalJson is a WIRE-PROTOCOL primitive: the bytes it produces are
 * hashed and signed, and a signature produced by one SDK tier must verify
 * under every other tier (CLAUDE.md §"Seven SDKs Must Stay in Sync"). Two
 * tiers that disagree on a single byte for the same input silently break
 * every cross-tier signature. Until now that parity was only spot-checked by
 * the ~21 fixed vectors in `conformance/sdk-envelope/fixtures.json`; the
 * randomized surface (key ordering, float formatting, surrogate handling,
 * nesting) was unexplored.
 *
 * This harness generates random JSON-shaped values spanning the tricky
 * surface and asserts that ALL 7 tiers' canonicalJson produce **byte-identical
 * output**, OR an **identical typed rejection** (e.g. every tier rejects a lone
 * surrogate). The 7 implementations under test:
 *   - TS  (reference, in-process): packages/runar-ir-schema/src/canonical-json.ts
 *   - Go:     packages/runar-go/cmd/canonicalise        (go run)
 *   - Rust:   packages/runar-rs/examples/canonicalise.rs (cargo run --example)
 *   - Python: packages/runar-py/canonicalise_shim.py
 *   - Zig:    packages/runar-zig/src/canonicalise_cli.zig (zig-out/bin/runar-canonicalise)
 *   - Ruby:   packages/runar-rb/bin/canonicalise_shim.rb
 *   - Java:   packages/runar-java/.../CanonicaliseShim.java (gradle -q runCanonicalise)
 *
 * Each non-TS tier exposes a tiny `--canonicalise` CLI shim that reads a single
 * JSON *request* on stdin and writes the canonical bytes (or
 * `RUNAR_CANON_ERR:<message>`) to stdout. The request is one of:
 *   {"mode":"json","value":<any JSON>}
 *   {"mode":"utf16","key":"<string>","units":[<int>,...]}
 * The `utf16` mode carries an explicit UTF-16 code-unit array (mirroring the
 * fixture's `canonical_json_rejection_vectors`) so a lone surrogate is
 * constructed deterministically without relying on any JSON parser's
 * lone-surrogate handling (which diverges by tier).
 *
 * Determinism: a single Mulberry32 PRNG (same approach as `anf-differential.ts`)
 * seeded from `--seed` makes the generated corpus exactly reproducible.
 *
 * Per the GAP-002 audit, D1/D3/D5/D6 are already fixed in code, so a correct
 * tree should yield ZERO divergences. Any divergence found is a real latent
 * bug; the harness persists the input + per-tier outputs under
 * `conformance/fuzz-findings-canonical/<timestamp>/`.
 *
 * A MISSING TIER IS A FAILURE, NOT A SMALLER RUN. Every tier is discovered by
 * probing for its toolchain / shim binary, and a tier that is not there used to
 * be marked `skip`, dropped from the comparison, and neither warned about nor
 * counted — so `zig build canonicalise` silently not having run turned a
 * seven-tier gate into a six-tier gate that still printed "Mismatches: 0" and
 * exited 0. `requireTiers` (the `--require-tiers` CLI flag, defaulting to every
 * requested tier) makes that a hard failure before any case runs.
 */

import {
  writeFileSync,
  mkdirSync,
  existsSync,
} from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const ROOT = resolve(__dirname, '../..');

// ---------------------------------------------------------------------------
// Tier identifiers
// ---------------------------------------------------------------------------

export type CompilerName = 'ts' | 'go' | 'rust' | 'python' | 'zig' | 'ruby' | 'java';
export const ALL_TIERS: readonly CompilerName[] = [
  'ts', 'go', 'rust', 'python', 'zig', 'ruby', 'java',
];

export const REJECT_PREFIX = 'RUNAR_CANON_ERR:';

/**
 * Marker for a tier whose shim could not be run to completion at all.
 *
 * Deliberately NOT a REJECT_PREFIX string. A tier that dies — JVM stack
 * overflow, killed process, timeout — has told us nothing about what its
 * canonicalJson would have decided, and scoring that as agreement with a tier
 * that cleanly rejected is exactly the failure this harness exists to catch.
 * Because rejections normalise to `<REJECT>` and this does not, a crashed tier
 * always diverges and always reddens the run.
 */
export const CRASH_PREFIX = 'RUNAR_CANON_CRASH:';

/**
 * Collapse one tier's raw stdout to the token the cross-tier compare uses.
 *
 * Every REJECT_PREFIX string maps to a single `<REJECT>` token, so two tiers
 * that both reject with their own wording still count as agreeing — the
 * comparison is about accept-vs-reject, not about the message.
 *
 * A CRASH_PREFIX string is deliberately NOT collapsed. A tier whose process
 * died, or whose canonicalJson blew the native stack, has said nothing about
 * what it would have decided; folding it into `<REJECT>` would score it as
 * agreeing with a tier that rejected cleanly. Since the in-process TS reference
 * is always in the comparison and can never carry this prefix, a crashed tier
 * always diverges and always reddens the run.
 *
 * This lives here, exported, because `canonical-java-gate.ts` compares the same
 * way: a second, private copy of the rule is a second place for the two gates
 * to disagree about what "agreed" means.
 */
export function normaliseOutcome(s: string): string {
  if (s.startsWith(CRASH_PREFIX)) return s;
  return s.startsWith(REJECT_PREFIX) ? '<REJECT>' : s;
}

// ---------------------------------------------------------------------------
// Generated value model.
//
// We DON'T generate arbitrary JS values, because two things we want to stress
// can't survive a JSON round-trip: (a) the int-vs-float distinction (a JS
// `number` is always a double) and (b) lone surrogates. Instead we generate a
// typed `GenValue` tree and lower it two ways:
//   - to a JSON request string for the shims;
//   - to a native JS value for the TS in-process reference.
// ---------------------------------------------------------------------------

type GenValue =
  | { t: 'null' }
  | { t: 'bool'; v: boolean }
  | { t: 'int'; v: number } // integer-valued, |v| <= 2^53 (safe across tiers)
  | { t: 'float'; v: number } // non-integer / boundary double
  | { t: 'str'; v: string } // well-formed (no lone surrogates)
  | { t: 'array'; v: GenValue[] }
  | { t: 'object'; v: { key: string; val: GenValue }[] };

// A whole generated test case. Either a well-formed value (`json` mode), a
// lone-surrogate object (`utf16` mode — the only path that can carry an
// ill-formed string deterministically), or one of the two DoS-bound probes
// (`deep` / `bigstring`), which are built natively inside each shim.
//
// Why `deep` and `bigstring` cannot be expressed as `json` cases: the request
// itself is JSON, so a deep or huge value would have to survive each shim's
// own JSON *parser* before reaching canonicalJson. It does not. Measured:
// Ruby's `JSON.parse` caps at max_nesting 100 (depth 101 -> "nesting of 101 is
// too deep") and Rust's serde_json caps at 128 (value-depth 127 -> "recursion
// limit exceeded"), both failing on stderr with exit 1 and no REJECT_PREFIX —
// i.e. the harness's own TRANSPORT was imposing a limit far below the limit
// under test, and the resulting "rejection" looked like tier agreement while
// canonicalJson was never called at all. These two modes carry a *description*
// of the value (a depth, a byte count) and let each shim materialise it
// natively, so the transport stays ~50 bytes and the parser is never the thing
// being measured.
export type GenCase =
  | { mode: 'json'; value: GenValue }
  | { mode: 'utf16'; key: string; units: number[] }
  | { mode: 'deep'; depth: number; shape: 'array' | 'object' }
  | { mode: 'bigstring'; bytes: number; where: 'value' | 'key' };

// ---------------------------------------------------------------------------
// Deterministic RNG (Mulberry32 — mirrors anf-differential.ts).
// ---------------------------------------------------------------------------

export interface Rng {
  next(): number;
  nextInt(min: number, max: number): number;
  nextBool(): boolean;
  pick<T>(xs: readonly T[]): T;
}

export function mulberry32(a: number): Rng {
  let state = a >>> 0;
  function next(): number {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 0x100000000;
  }
  const rng: Rng = {
    next,
    nextInt(min, max) {
      return min + Math.floor(next() * (max - min + 1));
    },
    nextBool() {
      return next() < 0.5;
    },
    pick(xs) {
      return xs[rng.nextInt(0, xs.length - 1)]!;
    },
  };
  return rng;
}

// ---------------------------------------------------------------------------
// Generator — spans the tricky RFC 8785 surface.
// ---------------------------------------------------------------------------

// Numbers across ECMA-262 §6.1.6.1.13 boundaries: the integer/scientific
// crossover at 1e21, the decimal/scientific crossover at 1e-6 / 1e-7, very
// large and very small magnitudes, and -0. All are doubles so every tier's
// JSON parser lands them in its float branch and exercises the ECMA-262
// formatter (audit D5).
const FLOAT_BOUNDARIES: readonly number[] = [
  1e21, 9.999e20, 1e20, 1e-6, 1e-7, 1.5e-10, 1e100, 1e-300, 5e-324,
  -0, 0.5, 1.5, 123.456, -123.456, 3.141592653589793, 2.5e-8, 9.999999999999999e22,
  1e-1, 100.0001, 0.1, 0.2, 0.3,
];

// Object keys that stress UTF-16 code-unit ordering: astral (surrogate-pair)
// chars, BMP private-use just above the high-surrogate block, shared prefixes,
// the empty key, and plain ASCII. The astral-vs-BMP pairs reproduce audit D1.
const TRICKY_KEYS: readonly string[] = [
  '', 'a', 'b', 'aa', 'ab', 'a ', 'A', 'Z', 'z',
  '\u{1F600}', '\u{1F4A9}', '\u{10000}', '\u{10FFFF}',
  '', '�', '￿',
  'é', 'é', 'key', 'key2', 'naïve',
  '', '', 'ࠀ',
];

// Strings containing control chars (which must be \uXXXX-escaped) and the
// chars JSON must escape. NO lone surrogates here — those go through the utf16
// case.
const TRICKY_STRINGS: readonly string[] = [
  '', 'hello', 'a\tb', 'say "hi"', 'back\\slash', 'line\nfeed', 'cr\rlf',
  '\b\f', ' ', 'tab\tandbell', 'unicode é ñ 漢',
  '\u{1F600} astral', 'slash/here', 'mixed \t"\\',
];

function genValue(rng: Rng, depth: number): GenValue {
  // At max depth, only produce scalars.
  const maxDepth = 4;
  const r = rng.nextInt(0, depth >= maxDepth ? 5 : 7);
  switch (r) {
    case 0:
      return { t: 'null' };
    case 1:
      return { t: 'bool', v: rng.nextBool() };
    case 2: {
      // Integers within the cross-tier-safe range. Larger integer LITERALS
      // are parser-type-dependent (Go/Rust/Zig → float64, Python/Java →
      // bigint), which is a structural type difference, not a canonicalJson
      // bug, so we stay within +-2^53.
      const mag = rng.pick([0, 1, -1, 42, -7, 1000, -1000, 2 ** 31, -(2 ** 31), 9007199254740991, -9007199254740991]);
      return { t: 'int', v: mag };
    }
    case 3:
      return { t: 'float', v: rng.pick(FLOAT_BOUNDARIES) };
    case 4:
      return { t: 'str', v: rng.pick(TRICKY_STRINGS) };
    case 5:
      // At maxDepth this is the last scalar branch.
      return { t: 'str', v: rng.pick(TRICKY_KEYS) };
    case 6: {
      const len = rng.nextInt(0, 4);
      const v: GenValue[] = [];
      for (let i = 0; i < len; i++) v.push(genValue(rng, depth + 1));
      return { t: 'array', v };
    }
    default: {
      const len = rng.nextInt(0, 5);
      // Use a Set to avoid duplicate keys: duplicate object keys are a
      // SEPARATE conformance concern (audit D3) handled by the fixtures /
      // schema, and JS object construction would silently collapse them
      // anyway, so the differential here would be meaningless.
      const used = new Set<string>();
      const v: { key: string; val: GenValue }[] = [];
      for (let i = 0; i < len; i++) {
        const key = rng.pick(TRICKY_KEYS);
        if (used.has(key)) continue;
        used.add(key);
        v.push({ key, val: genValue(rng, depth + 1) });
      }
      return { t: 'object', v };
    }
  }
}

/** Generate one test case. ~8% of cases are the lone-surrogate utf16 case so
 *  the identical-rejection path is exercised regularly. */
export function genCase(rng: Rng): GenCase {
  if (rng.nextInt(0, 11) === 0) {
    // Lone-surrogate object: a high or low surrogate with no partner, or a
    // reversed pair (low then high), all of which are ill-formed Unicode.
    const variant = rng.nextInt(0, 3);
    let units: number[];
    if (variant === 0) units = [0xd800]; // lone high
    else if (variant === 1) units = [0xdc00]; // lone low
    else if (variant === 2) units = [0xdfff, 0xd800]; // reversed pair
    else units = [0x0041, 0xd83d, 0x0042]; // high surrogate between ASCII
    return { mode: 'utf16', key: rng.pick(TRICKY_KEYS), units };
  }
  return { mode: 'json', value: genValue(rng, 0) };
}

// ---------------------------------------------------------------------------
// Lowering: GenValue -> native JS value (for the TS reference) and -> JSON
// request string (for the shims).
// ---------------------------------------------------------------------------

function toJsValue(g: GenValue): unknown {
  switch (g.t) {
    case 'null':
      return null;
    case 'bool':
      return g.v;
    case 'int':
      return g.v;
    case 'float':
      return g.v;
    case 'str':
      return g.v;
    case 'array':
      return g.v.map(toJsValue);
    case 'object': {
      const o: Record<string, unknown> = {};
      for (const { key, val } of g.v) o[key] = toJsValue(val);
      return o;
    }
  }
}

/** Serialise a GenValue to a JSON value literal that every tier's JSON parser
 *  reads identically. We hand-emit numbers so a float boundary like `1e21`
 *  is delivered to each parser as a number token (not JS's re-stringified
 *  form), and so `-0` survives as `-0`. */
function genValueToJsonLiteral(g: GenValue): string {
  switch (g.t) {
    case 'null':
      return 'null';
    case 'bool':
      return g.v ? 'true' : 'false';
    case 'int':
      return String(g.v);
    case 'float': {
      if (Object.is(g.v, -0)) return '-0';
      // JSON has no NaN/Infinity; the generator never produces them.
      // JS number->string gives a valid JSON number token for every
      // FLOAT_BOUNDARIES entry (e.g. 1e21 -> "1e+21" which is valid JSON).
      return JSON.stringify(g.v);
    }
    case 'str':
      return JSON.stringify(g.v);
    case 'array':
      return '[' + g.v.map(genValueToJsonLiteral).join(',') + ']';
    case 'object':
      return (
        '{' +
        g.v
          .map(({ key, val }) => JSON.stringify(key) + ':' + genValueToJsonLiteral(val))
          .join(',') +
        '}'
      );
  }
}

export function caseToRequest(c: GenCase): string {
  if (c.mode === 'utf16') {
    return JSON.stringify({ mode: 'utf16', key: c.key, units: c.units });
  }
  if (c.mode === 'deep') {
    return JSON.stringify({ mode: 'deep', depth: c.depth, shape: c.shape });
  }
  if (c.mode === 'bigstring') {
    return JSON.stringify({ mode: 'bigstring', bytes: c.bytes, where: c.where });
  }
  // Embed `value` as a raw literal so number formatting reaches each parser
  // intact.
  return `{"mode":"json","value":${genValueToJsonLiteral(c.value)}}`;
}

// ---------------------------------------------------------------------------
// DoS-bound probe construction (shared by the TS reference and every shim).
// ---------------------------------------------------------------------------

/** Build `depth` nested containers around the integer leaf `1`. */
export function buildDeep(depth: number, shape: 'array' | 'object'): unknown {
  let v: unknown = 1;
  for (let i = 0; i < depth; i++) v = shape === 'array' ? [v] : { k: v };
  return v;
}

/** Build a one-entry object whose key or value is `bytes` ASCII 'a'. */
export function buildBigString(bytes: number, where: 'value' | 'key'): unknown {
  const s = 'a'.repeat(bytes);
  return where === 'value' ? { s } : { [s]: 1 };
}

/**
 * `bigstring` responses are the SHA-256 of the canonical bytes, not the bytes.
 *
 * The accept-side probe sits at exactly MAX_STRING_BYTES, so the raw response
 * would be ~4 MiB per tier per case — 28 MiB through seven pipes to establish
 * one bit of information. Hashing keeps the comparison exact (a single byte of
 * divergence still changes the digest) while holding the response to 64 hex
 * chars. Rejections are unaffected: they still travel as REJECT_PREFIX.
 */
export const DIGEST_PREFIX = 'RUNAR_CANON_SHA256:';

/** Build the native JS object for the TS reference's utf16 case. */
function utf16CaseToJs(c: Extract<GenCase, { mode: 'utf16' }>): Record<string, string> {
  let s = '';
  for (const u of c.units) s += String.fromCharCode(u);
  return { [c.key]: s };
}

// ---------------------------------------------------------------------------
// TS reference (in-process).
// ---------------------------------------------------------------------------

export type CanonicalJsonFn = (value: unknown) => string;
let _cachedCanon: CanonicalJsonFn | null = null;
export async function loadCanonical(): Promise<CanonicalJsonFn> {
  if (_cachedCanon) return _cachedCanon;
  const entry = resolve(ROOT, 'packages/runar-ir-schema/src/index.ts');
  const mod = (await import(pathToFileURL(entry).href)) as Record<string, unknown>;
  const fn = mod.canonicalJsonStringify;
  if (typeof fn !== 'function') {
    throw new Error('runar-ir-schema does not export canonicalJsonStringify');
  }
  _cachedCanon = fn as CanonicalJsonFn;
  return _cachedCanon;
}

/** Run the TS reference. Returns the canonical bytes, or a REJECT_PREFIX
 *  string if the reference throws (rejection). */
export function runTs(canon: CanonicalJsonFn, c: GenCase): string {
  try {
    let value: unknown;
    switch (c.mode) {
      case 'utf16':
        value = utf16CaseToJs(c);
        break;
      case 'deep':
        value = buildDeep(c.depth, c.shape);
        break;
      case 'bigstring':
        value = buildBigString(c.bytes, c.where);
        break;
      default:
        value = toJsValue(c.value);
    }
    const out = canon(value);
    // See DIGEST_PREFIX: bigstring responses travel as a digest, never raw.
    return c.mode === 'bigstring'
      ? DIGEST_PREFIX + createHash('sha256').update(out, 'utf8').digest('hex')
      : out;
  } catch (e) {
    return REJECT_PREFIX + (e as Error).message;
  }
}

// ---------------------------------------------------------------------------
// Guard boundary corpus.
// ---------------------------------------------------------------------------

/** The DoS bounds the guard probes are built around, read from the TS
 *  reference so the corpus tracks the shipped constants instead of
 *  duplicating them. */
export interface GuardLimits {
  maxNesting: number;
  maxStringBytes: number;
}

/**
 * Read the wire bounds from runar-ir-schema.
 *
 * Prefers `MAX_WIRE_NESTING` (the envelope/canonicalJson bound) and falls back
 * to `MAX_NESTING` (the compiler's IR-loader bound, which canonicalJson used
 * before the two were separated), so this harness stays correct whichever of
 * them is in the tree.
 */
export async function loadGuardLimits(): Promise<GuardLimits> {
  const entry = resolve(ROOT, 'packages/runar-ir-schema/src/index.ts');
  const mod = (await import(pathToFileURL(entry).href)) as Record<string, unknown>;
  const limits = mod.InputLimits as Record<string, number> | undefined;
  if (!limits) throw new Error('runar-ir-schema does not export InputLimits');
  const maxNesting = limits.MAX_WIRE_NESTING ?? limits.MAX_NESTING;
  const maxStringBytes = limits.MAX_STRING_BYTES;
  if (typeof maxNesting !== 'number' || typeof maxStringBytes !== 'number') {
    throw new Error('InputLimits is missing a nesting / string-byte bound');
  }
  return { maxNesting, maxStringBytes };
}

/**
 * The deterministic accept/reject probes that straddle each DoS bound.
 *
 * These are NOT randomly generated, deliberately: a boundary is one value wide,
 * and a generator that picked depths at random would essentially never land on
 * it. Ten cases, each earning its place — the accept side proves the guard is
 * not over-strict (a guard that rejected a legitimate payload would redden the
 * `limit` rows), the reject side proves it exists at all.
 *
 * Keys go through the same string guard as values in the TS reference, so the
 * `key` probes are not redundant with the `value` ones.
 */
export function guardBoundaryCases(limits: GuardLimits): GenCase[] {
  const { maxNesting, maxStringBytes } = limits;
  return [
    // Depth: at the bound (accept) and one past it (reject), both shapes.
    { mode: 'deep', depth: maxNesting, shape: 'array' },
    { mode: 'deep', depth: maxNesting, shape: 'object' },
    { mode: 'deep', depth: maxNesting + 1, shape: 'array' },
    { mode: 'deep', depth: maxNesting + 1, shape: 'object' },
    // Comfortably past the bound — catches a tier whose guard is present but
    // off by more than one.
    { mode: 'deep', depth: maxNesting * 2, shape: 'array' },
    // String bytes: at the bound (accept) and one past it (reject), as both a
    // value and a key.
    { mode: 'bigstring', bytes: maxStringBytes, where: 'value' },
    { mode: 'bigstring', bytes: maxStringBytes, where: 'key' },
    { mode: 'bigstring', bytes: maxStringBytes + 1, where: 'value' },
    { mode: 'bigstring', bytes: maxStringBytes + 1, where: 'key' },
    // An ordinary small string through the same path — a control that reddens
    // if the digest transport itself diverges between tiers.
    { mode: 'bigstring', bytes: 1024, where: 'value' },
  ];
}

// ---------------------------------------------------------------------------
// Native shim discovery + invocation.
// ---------------------------------------------------------------------------

function commandExists(cmd: string, versionArgs: string[] = ['--version']): boolean {
  try {
    execFileSync(cmd, versionArgs, { stdio: 'pipe', timeout: 5000 });
    return true;
  } catch {
    return false;
  }
}

interface TierRunner {
  cmd: string;
  args: string[];
  cwd: string;
}

interface ShimContext {
  runners: Partial<Record<CompilerName, TierRunner>>;
  available: Partial<Record<CompilerName, boolean>>;
}

function findZigBin(): string | null {
  const p = resolve(ROOT, 'packages/runar-zig/zig-out/bin/runar-canonicalise');
  return existsSync(p) ? p : null;
}

function findJavaProject(): string | null {
  // Require the gradle wrapper so the differential driver is hermetic.
  const wrapper = resolve(ROOT, 'packages/runar-java/gradlew');
  if (!existsSync(wrapper)) return null;
  try {
    execFileSync('java', ['-version'], { stdio: 'pipe', timeout: 5000 });
    return resolve(ROOT, 'packages/runar-java');
  } catch {
    return null;
  }
}

function initShimContext(tiers: readonly CompilerName[]): ShimContext {
  const runners: Partial<Record<CompilerName, TierRunner>> = {};
  const available: Partial<Record<CompilerName, boolean>> = {};

  if (tiers.includes('go') && commandExists('go', ['version'])) {
    runners.go = {
      cmd: 'go',
      args: ['run', './cmd/canonicalise'],
      cwd: resolve(ROOT, 'packages/runar-go'),
    };
  }
  if (tiers.includes('rust') && commandExists('cargo')) {
    runners.rust = {
      cmd: 'cargo',
      args: ['run', '--quiet', '--example', 'canonicalise'],
      cwd: resolve(ROOT, 'packages/runar-rs'),
    };
  }
  if (tiers.includes('python') && commandExists('python3')) {
    runners.python = {
      cmd: 'python3',
      args: [resolve(ROOT, 'packages/runar-py/canonicalise_shim.py')],
      cwd: resolve(ROOT, 'packages/runar-py'),
    };
  }
  if (tiers.includes('zig')) {
    const bin = findZigBin();
    if (bin) runners.zig = { cmd: bin, args: [], cwd: ROOT };
  }
  if (tiers.includes('ruby') && commandExists('ruby')) {
    runners.ruby = {
      cmd: 'ruby',
      args: [resolve(ROOT, 'packages/runar-rb/bin/canonicalise_shim.rb')],
      cwd: ROOT,
    };
  }
  if (tiers.includes('java')) {
    const proj = findJavaProject();
    if (proj) {
      runners.java = {
        cmd: resolve(proj, 'gradlew'),
        args: ['-q', 'runCanonicalise'],
        cwd: proj,
      };
    }
  }

  for (const t of ALL_TIERS) {
    if (t === 'ts') {
      available.ts = true;
    } else {
      available[t] = !!runners[t];
    }
  }
  return { runners, available };
}

/** Run one shim with the given stdin request. Returns the canonical bytes, a
 *  REJECT_PREFIX string (typed rejection), or null if the tier could not be
 *  invoked at all (toolchain/process error). */
function runShim(runner: TierRunner, request: string, timeoutMs: number): string | null {
  const r = spawnSync(runner.cmd, runner.args, {
    cwd: runner.cwd,
    input: request,
    encoding: 'utf-8',
    timeout: timeoutMs,
    stdio: ['pipe', 'pipe', 'pipe'],
    maxBuffer: 64 * 1024 * 1024,
  });
  if (r.error) return null;
  const stdout = (r.stdout ?? '').trim();
  // A rejection is signalled by the REJECT_PREFIX on stdout (the exit code is
  // unreliable through wrappers like gradle, which remaps process exit 3 to
  // its own build-failure exit 1).
  if (stdout.startsWith(REJECT_PREFIX)) return stdout;
  // A shim that caught its own native stack exhaustion reports it with the
  // CRASH prefix. Pass it through for the same reason: the exit code is
  // unreliable through wrappers like gradle, and `normaliseOutcome` needs the
  // prefix, not the status, to keep the crash out of `<REJECT>`.
  if (stdout.startsWith(CRASH_PREFIX)) return stdout;
  // Non-zero exit WITHOUT the prefix = the tier genuinely failed to run.
  if (r.status !== 0 && stdout.length === 0) return null;
  return stdout;
}

// ---------------------------------------------------------------------------
// Findings persistence.
// ---------------------------------------------------------------------------

interface Finding {
  seed: number | undefined;
  /** Case label: the corpus index, or `guard:<n>` for a boundary probe. */
  index: string;
  request: string;
  outputs: Partial<Record<CompilerName, string>>;
  reason: string;
}

function saveFinding(dir: string, f: Finding): string {
  const ts = new Date().toISOString().replace(/[:.]/g, '-');
  // The label may carry a `:` (guard probes), which is not portable in a path.
  const out = join(dir, `${ts}-${f.index.replace(/[^A-Za-z0-9_-]/g, '-')}`);
  mkdirSync(out, { recursive: true });
  writeFileSync(join(out, 'request.json'), f.request + '\n', 'utf-8');
  for (const [tier, val] of Object.entries(f.outputs)) {
    if (val !== undefined) writeFileSync(join(out, `out-${tier}.txt`), val + '\n', 'utf-8');
  }
  writeFileSync(
    join(out, 'finding.json'),
    JSON.stringify({ seed: f.seed, index: f.index, reason: f.reason, request: f.request, outputs: f.outputs }, null, 2) + '\n',
    'utf-8',
  );
  return out;
}

// ---------------------------------------------------------------------------
// Public harness.
// ---------------------------------------------------------------------------

export interface CanonicalDifferentialOptions {
  numCases: number;
  seed?: number;
  tiers?: readonly CompilerName[];
  findingsDir?: string;
  timeoutMs?: number;
  verbose?: boolean;
  /**
   * Tiers whose shim MUST be runnable. If any of them is missing the run is a
   * FAILURE, not a smaller run.
   *
   * Without this the harness degrades silently: a tier whose shim binary is
   * absent is marked `skip`, dropped from the comparison, and the run reports
   * "Mismatches: 0" and exits 0 — a gate meant to establish SEVEN-tier parity
   * reporting success having established six. `canonicalJson` is a wire
   * primitive; one divergent byte breaks every cross-tier signature, so
   * "we did not check that tier" must never read as "that tier agrees".
   *
   * Defaults (in the CLI) to the requested `tiers`: every tier you asked to
   * compare must actually have been compared. Pass an empty array to opt out
   * for an exploratory local run.
   */
  requireTiers?: readonly CompilerName[];
}

export interface CanonicalDifferentialReport {
  totalCases: number;
  casesRun: number;
  mismatchCount: number;
  perTierAvailable: Partial<Record<CompilerName, boolean>>;
  findings: string[];
  durationMs: number;
  /** Requested tiers whose shim could not be invoked — excluded from the compare. */
  skippedTiers: CompilerName[];
  /** The tiers this run was required to cover. */
  requiredTiers: CompilerName[];
  /**
   * Required tiers that were skipped. Non-empty means the run PROVED NOTHING
   * about those tiers and the caller must fail.
   */
  missingRequiredTiers: CompilerName[];
}

export async function runCanonicalDifferential(
  opts: CanonicalDifferentialOptions,
): Promise<CanonicalDifferentialReport> {
  const tiers = (opts.tiers ?? ALL_TIERS).filter((t): t is CompilerName =>
    (ALL_TIERS as readonly string[]).includes(t),
  );
  const findingsDir = opts.findingsDir ?? join(__dirname, '..', 'fuzz-findings-canonical');
  const timeoutMs = opts.timeoutMs ?? 120_000;

  const canon = await loadCanonical();
  const ctx = initShimContext(tiers);
  const perTierAvailable = ctx.available;

  const skippedTiers = tiers.filter((t) => !perTierAvailable[t]);
  const requiredTiers = [...(opts.requireTiers ?? tiers)];
  // "Not compared" has two causes and both must fail: the tier's shim is
  // missing, or the tier was never requested at all. Checking only the first
  // would let `--compilers ts,go --require-tiers all` claim seven-tier parity
  // from a two-tier run.
  const missingRequiredTiers = requiredTiers.filter(
    (t) => !tiers.includes(t) || !perTierAvailable[t],
  );

  // Fail BEFORE the expensive pre-warm and the case loop. A run missing a
  // required tier cannot establish the parity it exists to establish, so
  // there is nothing to learn from continuing.
  if (missingRequiredTiers.length > 0) {
    return {
      totalCases: opts.numCases,
      casesRun: 0,
      mismatchCount: 0,
      perTierAvailable,
      findings: [],
      durationMs: 0,
      skippedTiers,
      requiredTiers,
      missingRequiredTiers,
    };
  }

  // Pre-warm cargo / gradle so the first-case timeout isn't hit by a cold
  // compile (the shim binaries are cached after the first invocation).
  const warmReq = '{"mode":"json","value":1}';
  if (ctx.runners.rust) runShim(ctx.runners.rust, warmReq, Math.max(timeoutMs, 300_000));
  if (ctx.runners.java) runShim(ctx.runners.java, warmReq, Math.max(timeoutMs, 300_000));
  if (ctx.runners.go) runShim(ctx.runners.go, warmReq, Math.max(timeoutMs, 120_000));

  const seedBase = opts.seed ?? (Math.random() * 2 ** 31) | 0;

  const start = Date.now();
  let mismatchCount = 0;
  let casesRun = 0;
  const findings: string[] = [];

  // The deterministic guard-boundary probes run FIRST, before the randomized
  // corpus. They are the only cases that can reach the DoS guards at all (see
  // the `deep` / `bigstring` note on GenCase), and running them first means a
  // missing guard is reported in the first second of the run rather than after
  // the full random corpus.
  const guardCases = guardBoundaryCases(await loadGuardLimits());
  const allCases: { c: GenCase; label: string; seed: number | undefined }[] = [
    ...guardCases.map((c, n) => ({ c, label: `guard:${n}`, seed: undefined })),
  ];
  for (let i = 0; i < opts.numCases; i++) {
    // Per-case PRNG seeded from seedBase + i so each case is independently
    // reproducible.
    const rng = mulberry32((seedBase + i) >>> 0);
    allCases.push({ c: genCase(rng), label: String(i), seed: seedBase + i });
  }

  for (const { c: testCase, label: i, seed: caseSeed } of allCases) {
    const request = caseToRequest(testCase);
    casesRun += 1;

    const outputs: Partial<Record<CompilerName, string>> = {};

    for (const tier of tiers) {
      if (tier === 'ts') {
        outputs.ts = runTs(canon, testCase);
        continue;
      }
      const runner = ctx.runners[tier];
      // Skipped tiers are reported (and, when required, already fatal above).
      if (!runner) continue;
      const res = runShim(runner, request, timeoutMs);
      if (res === null) {
        // Tier present but crashed/timed out on this input. See CRASH_PREFIX:
        // this must NOT be a REJECT_PREFIX string, or a tier that died would
        // be scored as agreeing with a tier that rejected cleanly.
        outputs[tier] = CRASH_PREFIX + '<tier failed to run>';
      } else {
        outputs[tier] = res;
      }
    }

    // Compare every available tier's output. They must ALL be byte-identical
    // — whether that's an accepted canonical string or an (any-message)
    // rejection. We normalise rejections to a single token so two tiers that
    // both reject with different wording still count as agreeing.
    //
    // LIMITATION, and it is a real one: `<REJECT>` normalisation buys parity of
    // OUTCOME, not parity of REASON. Two tiers that both reject agree here even
    // if one rejected for a completely unrelated cause. That is not
    // hypothetical — Ruby's lone-surrogate interop test passes because the key
    // SORT raises `Encoding::InvalidByteSequenceError`, not because
    // canonical_json checks for surrogates; refactor the sort and the guard
    // vanishes while both this harness and that test stay green. This
    // differential proves tiers agree on accept-vs-reject; only a per-tier
    // TYPED assertion proves they agree on why.
    const keys = Object.keys(outputs) as CompilerName[];
    const ref = normaliseOutcome(outputs[keys[0]!]!);
    const divergent: CompilerName[] = [];
    for (let j = 1; j < keys.length; j++) {
      if (normaliseOutcome(outputs[keys[j]!]!) !== ref) divergent.push(keys[j]!);
    }

    if (divergent.length > 0) {
      mismatchCount += 1;
      const dir = saveFinding(findingsDir, {
        seed: caseSeed,
        index: i,
        request,
        outputs,
        reason: `divergence: ${keys[0]} vs ${divergent.join(',')}`,
      });
      findings.push(dir);
      console.log(
        `  [${i}] MISMATCH (${keys[0]} vs ${divergent.join(',')})` +
          (caseSeed === undefined ? '' : ` seed=${caseSeed}`),
      );
      for (const k of keys) {
        console.log(`        ${k.padEnd(7)} = ${JSON.stringify(outputs[k])}`);
      }
      console.log(`        request = ${request}`);
      console.log(`        saved   = ${dir}`);
    } else if (opts.verbose) {
      console.log(`  [${i}] OK (${keys.join(',')})  ${ref === '<REJECT>' ? 'rejected' : JSON.stringify(ref).slice(0, 60)}`);
    }
  }

  return {
    totalCases: allCases.length,
    casesRun,
    mismatchCount,
    perTierAvailable,
    findings,
    durationMs: Date.now() - start,
    skippedTiers,
    requiredTiers,
    missingRequiredTiers,
  };
}

// Re-export for any caller wanting the discovery list without running.
export { initShimContext };
