import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { ALL_TIER_IDS, BrokenTier, REPO, Tier, buildSourceTiers } from './tier-harness.js';

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
 * comparison against TS — see the second describe block below. That found
 * the `stateFields: []` / `codeSeparatorIndex: 0` divergence this header used
 * to call out (now fixed in `compilers/zig/src/codegen/emit.zig`, alongside
 * the same "emit the empty/default value instead of omitting the key" bug on
 * Zig's `constructorSlots`), plus several PRE-EXISTING, OUT-OF-SCOPE gaps
 * that are not this bug class and are deliberately allow-listed rather than
 * fixed here (see `KNOWN_KEY_EXCEPTIONS`): `templateDigest` and the enriched
 * `constructorSlots.{name,type,valueEncoding,...}` fields are TS-only
 * (feature not ported to any other tier); `sourceMap` is omitted by Go/Java
 * unless their CLI's `--emit-source-map` flag is passed (a CLI-default
 * difference, not an artifact-shape bug); `ir` is Rust-only (its CLI embeds a
 * debug IR snapshot by default); and Zig never emits `buildTimestamp` at all.
 * (`rawScriptSpans`, once never emitted by Go/Java/Zig, was fixed by N-151 —
 * see the third describe block below.)
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

function compileArtifact(tier: Tier, src: string): Record<string, any> {
  if (tier.cmd === null) throw new BrokenTier(`${tier.id}: no toolchain`);
  const { args, file } = artifactArgs(tier, src);
  const argv = [...tier.prefix, ...args];
  const res = spawnSync(tier.cmd, argv, {
    cwd: tier.cwd,
    encoding: 'utf-8',
    timeout: tier.timeoutMs,
    maxBuffer: 64 * 1024 * 1024,
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
    if (process.env.CI === 'true') expect(missing).toEqual([]);
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
 * Per-tier, pre-existing top-level-key divergences from TS that are NOT the
 * N-147 bug class: the tier either lacks a whole feature, gates one behind a
 * CLI flag not passed by `artifactArgs`, or never emits a field even when it
 * is non-empty (data loss, not an omit-when-empty shape bug). Keep this list
 * narrow and justified — a new entry here should cite why it is a distinct,
 * separately-tracked gap, not a place to silence this test.
 */
const KNOWN_KEY_EXCEPTIONS: Record<string, KeyException> = {
  go: {
    missing: [
      'sourceMap', // written only via --emit-source-map, not passed here
      'templateDigest', // TS-only enrichment of constructorSlots; not ported
    ],
  },
  rust: {
    missing: ['templateDigest'],
    extra: ['ir'], // rust's --source CLI embeds a debug IR snapshot by default
  },
  python: {
    missing: ['templateDigest'],
  },
  ruby: {
    missing: ['templateDigest'],
  },
  java: {
    missing: [
      'sourceMap',
      'templateDigest',
      'asm', // Java's artifact JSON never includes a human-readable ASM field
    ],
  },
  zig: {
    missing: [
      'templateDigest',
      'buildTimestamp', // not emitted by compilers/zig/src/codegen/emit.zig at all
    ],
  },
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
