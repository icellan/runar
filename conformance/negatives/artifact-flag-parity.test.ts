import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { ALL_TIER_IDS, BrokenTier, REPO, Tier, buildSourceTiers } from './tier-harness.js';
import { isCiEnv } from '../env.js';

/**
 * N-139 — artifact `abi.methods[].isTerminal` and top-level `anf` presence
 * follow `parentClass`, identically in all seven tiers.
 *
 * Every tier derived "is this contract stateful?" for the artifact from
 * `stateFields.length > 0` (TS only for `anf`; Go, Ruby and Java for both;
 * Rust for `isTerminal` while always emitting `anf`; Zig emitted no
 * `isTerminal` at all and always emitted `anf`). For a StatefulSmartContract
 * with ZERO mutable fields (the issue-#44 `all-readonly-cleanstack` shape) the
 * tiers therefore disagreed on what the SDK is told about the contract, even
 * though the locking script is byte-identical. F-192 fixed Python alone.
 *
 * The rule, set by the TS reference: a public method of a
 * `StatefulSmartContract` that builds no continuation is terminal, and a
 * `StatefulSmartContract` artifact carries its ANF; a `SmartContract` artifact
 * carries neither.
 *
 * Proves: for the three contracts below (zero-mutable-field stateful,
 * ordinary stateful counter, stateless P2PKH control) each tier's
 * source-compiled artifact carries the expected parentClass, per-method
 * isTerminal, and presence/absence of top-level `anf`, and so all seven agree.
 * Does not prove: anything about the `--ir` path's artifact, the debug-only
 * `ir` snapshot, or that the SDKs act correctly on the flags.
 *
 * N-147 extends this file with a full top-level (and per-method ABI) KEY SET
 * comparison against TS - see the second describe block below. That found
 * the `stateFields: []` / `codeSeparatorIndex: 0` divergence this header used
 * to call out (now fixed in `compilers/zig/src/codegen/emit.zig`, alongside
 * the same "emit the empty/default value instead of omitting the key" bug on
 * Zig's `constructorSlots`). N-152 then aligned the leftovers that were
 * allow-listed there (Java `asm`, Zig `buildTimestamp`, Go/Java `sourceMap`,
 * Rust's default `ir` snapshot) and shrank `KNOWN_KEY_EXCEPTIONS` to the
 * documented TS-only metadata: `templateDigest` and the enriched
 * `constructorSlots[]` descriptors. (`rawScriptSpans`, once never emitted by
 * Go/Java/Zig, was fixed by N-151 - see the third describe block below.)
 */

type Flags = {
  parentClass: string | undefined;
  methods: Array<[string, boolean | null]>;
  hasAnf: boolean;
};

const CASES: Array<{ fixture: string; expected: Flags }> = [
  {
    fixture: 'all-readonly-cleanstack',
    expected: {
      parentClass: 'StatefulSmartContract',
      methods: [['claim', true]],
      hasAnf: true,
    },
  },
  {
    fixture: 'stateful-counter',
    expected: {
      parentClass: 'StatefulSmartContract',
      methods: [
        ['increment', null],
        ['decrement', null],
      ],
      hasAnf: true,
    },
  },
  {
    fixture: 'basic-p2pkh',
    expected: {
      parentClass: 'SmartContract',
      methods: [['unlock', null]],
      hasAnf: false,
    },
  },
];

function tsSource(fixture: string): string {
  const dir = join(REPO, 'conformance/tests', fixture);
  const cfg = JSON.parse(readFileSync(join(dir, 'source.json'), 'utf8')) as {
    sources: Record<string, string>;
  };
  return resolve(dir, cfg.sources['.runar.ts']!);
}

const OUT = mkdtempSync(join(tmpdir(), 'n139-artifact-flags-'));

/** Per-tier argv that writes the full artifact JSON (not `--hex`). */
function artifactArgs(tier: Tier, src: string): { args: string[]; file: string | null } {
  switch (tier.id) {
    case 'ts': {
      const dir = mkdtempSync(join(OUT, 'ts-'));
      return { args: [src, '-o', dir], file: dir };
    }
    case 'zig':
      return { args: ['compile', src], file: null };
    case 'java': {
      const file = join(mkdtempSync(join(OUT, 'java-')), 'artifact.json');
      return { args: ['--source', src, '--emit-artifact', file], file };
    }
    default:
      return { args: ['--source', src], file: null };
  }
}

function compileArtifact(
  tier: Tier,
  src: string,
  env?: Record<string, string>,
): Record<string, any> {
  if (tier.cmd === null) throw new BrokenTier(`${tier.id}: no toolchain`);
  const { args, file } = artifactArgs(tier, src);
  const argv = [...tier.prefix, ...args];
  const res = spawnSync(tier.cmd, argv, {
    cwd: tier.cwd,
    encoding: 'utf-8',
    timeout: tier.timeoutMs,
    maxBuffer: 64 * 1024 * 1024,
    ...(env ? { env: { ...process.env, ...env } } : {}),
  });
  const where = `${tier.id} (${tier.cmd} ${argv.join(' ')})`;
  if (res.error) throw new BrokenTier(`${where} could not run: ${res.error.message}`);
  if (res.signal !== null) throw new BrokenTier(`${where} killed by ${res.signal}`);
  if (res.status !== 0) {
    throw new BrokenTier(`${where} exited ${res.status}: ${`${res.stderr}\n${res.stdout}`.slice(0, 600)}`);
  }
  let text: string;
  if (file === null) {
    text = res.stdout ?? '';
  } else if (tier.id === 'ts') {
    const jsons = readdirSync(file).filter((f) => f.endsWith('.json'));
    if (jsons.length !== 1) throw new BrokenTier(`${where} wrote ${jsons.length} artifacts`);
    text = readFileSync(join(file, jsons[0]!), 'utf8');
  } else {
    text = readFileSync(file, 'utf8');
  }
  return JSON.parse(text) as Record<string, any>;
}

function flags(artifact: Record<string, any>): Flags {
  return {
    parentClass: artifact.parentClass,
    methods: (artifact.abi.methods as Array<Record<string, any>>)
      .filter((m) => m.isPublic)
      .map((m) => [m.name as string, (m.isTerminal as boolean | undefined) ?? null]),
    hasAnf: artifact.anf !== undefined && artifact.anf !== null,
  };
}

const TIERS = buildSourceTiers();
const available = TIERS.filter((t) => t.cmd !== null);

describe('N-139: artifact isTerminal + anf presence follow parentClass (7 tiers)', () => {
  it('the matrix names all seven tiers', () => {
    expect(TIERS.map((t) => t.id).sort()).toEqual([...ALL_TIER_IDS].sort());
  });

  it('every tier is built (strict in CI, ">=2" locally)', () => {
    const missing = TIERS.filter((t) => t.cmd === null).map((t) => t.id);
    if (isCiEnv(process.env)) expect(missing).toEqual([]);
    expect(available.length).toBeGreaterThanOrEqual(2);
  });

  for (const tier of available) {
    for (const c of CASES) {
      it(`${tier.id}: ${c.fixture} artifact flags`, () => {
        expect(flags(compileArtifact(tier, tsSource(c.fixture)))).toEqual(c.expected);
      });
    }
  }
});

/**
 * N-147 — full artifact-shape key-set parity against TS, all 7 tiers.
 *
 * N-139 (above) checked three specific flags. This checks the WHOLE
 * top-level key set (and, per public method, the whole ABI method key set)
 * of every tier's source-compiled artifact against TS's, for the same three
 * fixtures. It is deliberately NOT a bare `toEqual` on the raw key sets:
 * several tiers carry pre-existing, documented, OUT-OF-SCOPE differences
 * that are not instances of the "emit the empty/default value instead of
 * omitting the key" bug this item fixes — see `KNOWN_KEY_EXCEPTIONS` below
 * for what each one is and why it is not fixed here. Any OTHER divergence —
 * in particular a tier gaining or losing a key for a reason not on that
 * allowlist — fails loudly, including a regression of the N-147 bug itself.
 *
 * Proves: for basic-p2pkh (stateless), stateful-counter (stateful, empty
 * constructor), and all-readonly-cleanstack (stateful, zero mutable
 * fields), every available tier's top-level artifact key set, and every
 * public method's ABI key set, matches TS's, modulo the documented
 * exceptions. In particular, Zig no longer emits `stateFields: []`,
 * `codeSeparatorIndex: 0`, or `constructorSlots: []` where TS omits the key
 * (N-147's finding — the latter was the identical bug class on the same
 * key-omission mechanism, found while extending this test).
 * Does not prove: anything about NESTED field shape (e.g. TS's enriched
 * `constructorSlots[].name/type/valueEncoding` vs. other tiers' bare
 * `{paramIndex,byteOffset}` — a real, separate, pre-existing gap this test
 * does not check), the `--ir` path, or that the SDKs act correctly on any of
 * these keys.
 */
type KeyException = { missing?: string[]; extra?: string[] };

/**
 * Top-level artifact keys that only the TS reference emits, with the reason
 * they are NOT part of the cross-tier artifact contract (N-152).
 *
 * `templateDigest` (spec/artifact-format.md section 3.13) is a recipe for
 * recomputing the slot-excised template hash. Nothing reads it from an
 * artifact: the TS SDK's `computeTemplateHash` recomputes the hash from the
 * ABI and the constructor args, and the six native SDKs derive each slot's
 * encoding from the ABI parameter type (`abi_value_encoding` in every
 * `script_utils`). It is additive verification metadata, so it is documented
 * as TS-only rather than ported to six compilers.
 */
const TS_ONLY_TOP_LEVEL_KEYS = ['templateDigest'];

/**
 * `constructorSlots[]` keys beyond `{paramIndex, byteOffset}` that only the TS
 * reference emits (N-152). They are the verification descriptors of
 * `ConstructorSlot` in packages/runar-ir-schema/src/artifact.ts. The TS SDK's
 * `resolveSlotLayout` reads `slot.name` only as an optional cross-check against
 * `abi.constructor.params`, and every SDK recomputes the encoding from the ABI
 * parameter type, so no consumer needs them from a non-TS artifact.
 */
const TS_ONLY_SLOT_KEYS = ['name', 'type', 'valueEncoding', 'fixedValueByteLength', 'fixedPushHeaderBytes'];

/**
 * Per-tier top-level-key divergences from TS. After N-152 the only entries are
 * the documented TS-only keys above: `asm` (Java), `buildTimestamp` (Zig),
 * `sourceMap` (Go, Java) and Rust's default `ir` snapshot were aligned, not
 * allow-listed. A new entry here must cite why it is a distinct, separately
 * tracked gap, not a place to silence this test.
 */
const KNOWN_KEY_EXCEPTIONS: Record<string, KeyException> = {
  go: { missing: TS_ONLY_TOP_LEVEL_KEYS },
  rust: { missing: TS_ONLY_TOP_LEVEL_KEYS },
  python: { missing: TS_ONLY_TOP_LEVEL_KEYS },
  ruby: { missing: TS_ONLY_TOP_LEVEL_KEYS },
  java: { missing: TS_ONLY_TOP_LEVEL_KEYS },
  zig: { missing: TS_ONLY_TOP_LEVEL_KEYS },
};

/**
 * Per-tier ABI-method-level key exceptions. None known today — kept as an
 * explicit empty allowlist so a future divergence fails loudly rather than
 * silently matching an implicit "anything goes".
 */
const KNOWN_METHOD_KEY_EXCEPTIONS: Record<string, KeyException> = {};

function assertKeysMatch(
  label: string,
  tierKeys: string[],
  tsKeys: string[],
  exceptions: KeyException,
): void {
  const tierSet = new Set(tierKeys);
  const tsSet = new Set(tsKeys);
  const allowedMissing = new Set(exceptions.missing ?? []);
  const allowedExtra = new Set(exceptions.extra ?? []);
  const unexplainedMissing = tsKeys.filter((k) => !tierSet.has(k) && !allowedMissing.has(k));
  const unexplainedExtra = tierKeys.filter((k) => !tsSet.has(k) && !allowedExtra.has(k));
  expect({ label, unexplainedMissing, unexplainedExtra }).toEqual({
    label,
    unexplainedMissing: [],
    unexplainedExtra: [],
  });
}

const TS_TIER = TIERS.find((t) => t.id === 'ts')!;
const tsArtifactCache = new Map<string, Record<string, any>>();
function tsArtifactFor(fixture: string): Record<string, any> {
  let art = tsArtifactCache.get(fixture);
  if (!art) {
    art = compileArtifact(TS_TIER, tsSource(fixture));
    tsArtifactCache.set(fixture, art);
  }
  return art;
}

describe('N-147: artifact top-level + per-method key set matches TS (7 tiers)', () => {
  for (const tier of available.filter((t) => t.id !== 'ts')) {
    for (const c of CASES) {
      it(`${tier.id}: ${c.fixture} top-level + method key sets`, () => {
        const tsArtifact = tsArtifactFor(c.fixture);
        const tierArtifact = compileArtifact(tier, tsSource(c.fixture));
        const exceptions = KNOWN_KEY_EXCEPTIONS[tier.id] ?? {};

        assertKeysMatch(
          `${tier.id}/${c.fixture} top-level`,
          Object.keys(tierArtifact),
          Object.keys(tsArtifact),
          exceptions,
        );

        // N-152: the constructorSlots[] element key set, modulo TS_ONLY_SLOT_KEYS.
        const tsSlots = (tsArtifact.constructorSlots ?? []) as Array<Record<string, any>>;
        const tierSlots = (tierArtifact.constructorSlots ?? []) as Array<Record<string, any>>;
        expect(tierSlots.length, `${tier.id}/${c.fixture}: constructorSlots length`).toBe(tsSlots.length);
        tsSlots.forEach((tsSlot, i) => {
          assertKeysMatch(
            `${tier.id}/${c.fixture}/constructorSlots[${i}]`,
            Object.keys(tierSlots[i]!),
            Object.keys(tsSlot),
            { missing: TS_ONLY_SLOT_KEYS },
          );
        });

        const tsMethods = tsArtifact.abi.methods as Array<Record<string, any>>;
        const tierMethods = tierArtifact.abi.methods as Array<Record<string, any>>;
        const methodExceptions = KNOWN_METHOD_KEY_EXCEPTIONS[tier.id] ?? {};
        for (const tsMethod of tsMethods) {
          const tierMethod = tierMethods.find((m) => m.name === tsMethod.name);
          expect(tierMethod, `${tier.id}/${c.fixture}: missing method '${tsMethod.name}'`).toBeDefined();
          assertKeysMatch(
            `${tier.id}/${c.fixture}/${tsMethod.name} method`,
            Object.keys(tierMethod!),
            Object.keys(tsMethod),
            methodExceptions,
          );
        }
      });
    }
  }
});

/**
 * N-151 — `rawScriptSpans` VALUE parity against TS, all 7 tiers.
 *
 * Go, Java and Zig recorded a span per asm() raw-bytes op in their emitters
 * but never wrote them into the artifact, so the key was missing even for
 * real raw-script contracts (data loss for the analyzer / SDKs). The
 * key-set check above could not see it: none of its fixtures uses asm().
 *
 * Proves: for the asm-raw-script, stateful-counter and all-readonly-cleanstack
 * conformance fixtures and the four TS
 * reference shapes (packages/runar-compiler/src/__tests__/raw-script-spans.test.ts:
 * single span, consecutive spans, non-default arities, multi-byte body),
 * every available tier's `rawScriptSpans` array is deep-equal to TS's, TS's
 * is non-empty (so the comparison is not vacuous), and the asm-raw-script
 * top-level key set matches TS's under the exceptions above. Does not prove
 * how any SDK or analyzer consumes the spans, or the `--ir` path.
 */
const RAW_SHAPES: Array<{ name: string; params: string; body: string }> = [
  { name: 'single', params: '', body: "asm({ body: '51', in_arity: 0, out_arity: 1 });" },
  {
    name: 'consecutive',
    params: '',
    body: "asm({ body: '51', in_arity: 0, out_arity: 1 });\n    asm({ body: '6151', in_arity: 1, out_arity: 1 });",
  },
  { name: 'arity', params: 'a: bigint, b: bigint', body: "asm({ body: '87', in_arity: 2, out_arity: 1 });" },
  { name: 'multibyte', params: '', body: "asm({ body: '76a90051', in_arity: 0, out_arity: 1 });" },
];

const RAW_SRC_DIR = mkdtempSync(join(OUT, 'raw-shapes-'));
const RAW_CASES: Array<{ label: string; src: string }> = [
  { label: 'asm-raw-script', src: tsSource('asm-raw-script') },
  // Stateful contracts carry compiler-emitted raw spans too (TS records two
  // 428-byte spans for stateful-counter, one for all-readonly-cleanstack).
  { label: 'stateful-counter', src: tsSource('stateful-counter') },
  { label: 'all-readonly-cleanstack', src: tsSource('all-readonly-cleanstack') },
  ...RAW_SHAPES.map((s) => {
    const src = join(RAW_SRC_DIR, s.name, 'WithAsm.runar.ts');
    mkdirSync(join(RAW_SRC_DIR, s.name));
    writeFileSync(
      src,
      `import { UnsafeSmartContract, asm } from 'runar-lang';

class WithAsm extends UnsafeSmartContract {
  constructor() {
    super();
  }

  public unlock(${s.params}) {
    ${s.body}
  }
}
`,
    );
    return { label: `shape:${s.name}`, src };
  }),
];

const tsRawCache = new Map<string, Record<string, any>>();
function tsRawArtifact(src: string): Record<string, any> {
  let art = tsRawCache.get(src);
  if (!art) {
    art = compileArtifact(TS_TIER, src);
    tsRawCache.set(src, art);
  }
  return art;
}

describe('N-151: rawScriptSpans values match TS (7 tiers)', () => {
  for (const c of RAW_CASES) {
    it(`ts: ${c.label} emits a non-empty rawScriptSpans`, () => {
      const spans = tsRawArtifact(c.src).rawScriptSpans as unknown[] | undefined;
      expect(Array.isArray(spans) && spans.length > 0).toBe(true);
    });
  }

  for (const tier of available.filter((t) => t.id !== 'ts')) {
    for (const c of RAW_CASES) {
      it(`${tier.id}: ${c.label} rawScriptSpans`, () => {
        const tsArtifact = tsRawArtifact(c.src);
        const tierArtifact = compileArtifact(tier, c.src);
        expect(tierArtifact.script).toBe(tsArtifact.script);
        expect(tierArtifact.rawScriptSpans).toEqual(tsArtifact.rawScriptSpans);
        if (c.label === 'asm-raw-script') {
          assertKeysMatch(
            `${tier.id}/asm-raw-script top-level`,
            Object.keys(tierArtifact),
            Object.keys(tsArtifact),
            KNOWN_KEY_EXCEPTIONS[tier.id] ?? {},
          );
        }
      });
    }
  }
});

/**
 * N-152 - artifact shape VALUE parity: the keys the key-set check above can
 * only see the presence of.
 *
 * Proves: for the three CASES, every available tier (a) emits an `asm` string
 * equal to TS's (spec section 3.6, Required: Yes; Java used to omit it),
 * (b) emits a parseable `buildTimestamp` (section 3.19, Required: Yes; Zig used
 * to omit it) and Zig stamps the SOURCE_DATE_EPOCH instant when it is set,
 * (c) emits a non-empty `sourceMap.mappings` (Go and Java used to omit the key
 * unless `--emit-source-map` was passed), and (d) carries no top-level `ir`
 * debug snapshot on the default path (spec section 3.8: written only on
 * request; Rust embedded one by default).
 * Does not prove: that any tier's sourceMap mappings equal TS's (source paths
 * and line attribution are checked by conformance/source-map), the `--ir`
 * input path, or that the TS-only keys documented above are unused outside the
 * repo.
 */
describe('N-152: artifact asm / buildTimestamp / sourceMap / ir (7 tiers)', () => {
  for (const tier of available) {
    for (const c of CASES) {
      it(`${tier.id}: ${c.fixture} asm, buildTimestamp, sourceMap, no ir`, () => {
        const tsArtifact = tsArtifactFor(c.fixture);
        const a = tier.id === 'ts' ? tsArtifact : compileArtifact(tier, tsSource(c.fixture));
        expect(typeof a.asm, `${tier.id}: asm`).toBe('string');
        expect(a.asm, `${tier.id}: asm differs from TS`).toBe(tsArtifact.asm);
        expect(typeof a.buildTimestamp, `${tier.id}: buildTimestamp`).toBe('string');
        expect(Number.isNaN(Date.parse(a.buildTimestamp)), `${tier.id}: "${a.buildTimestamp}"`).toBe(false);
        const mappings = a.sourceMap?.mappings as unknown[] | undefined;
        expect(Array.isArray(mappings) && mappings.length > 0, `${tier.id}: sourceMap.mappings`).toBe(true);
        expect(a.ir, `${tier.id}: default artifact carries an ir snapshot`).toBeUndefined();
      });
    }
  }

  // R-212 listed every tier that stamps a time and left Zig out because Zig
  // stamped nothing. Zig now stamps, so it inherits the requirement here.
  const zig = available.find((t) => t.id === 'zig');
  if (zig) {
    it('zig: buildTimestamp is the SOURCE_DATE_EPOCH instant when set', () => {
      const a = compileArtifact(zig, tsSource('basic-p2pkh'), { SOURCE_DATE_EPOCH: '1700000000' });
      expect(Math.floor(Date.parse(a.buildTimestamp) / 1000)).toBe(1700000000);
    });

    it('zig: two builds at the same SOURCE_DATE_EPOCH are identical', () => {
      const env = { SOURCE_DATE_EPOCH: '1700000000' };
      const first = compileArtifact(zig, tsSource('stateful-counter'), env);
      const second = compileArtifact(zig, tsSource('stateful-counter'), env);
      expect(second).toEqual(first);
    });
  }
});
