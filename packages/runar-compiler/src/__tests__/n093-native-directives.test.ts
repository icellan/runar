/**
 * N-093 (user decisions R37/R38) — `@embedAlways` and `@sighash` on the eight
 * non-TS surfaces, each spelled as a native modifier that mirrors the surface's
 * readonly idiom:
 *
 *   .runar.sol   `ByteString immutable embedAlways x;`   `function f(..) public sighash(SINGLE | FORKID)`
 *   .runar.move  `#[embed_always] x: T,`                  `#[sighash(SINGLE | FORKID)] public fun f`
 *   .runar.go    `runar:"readonly,embedAlways"`            `//runar:sighash SINGLE|FORKID` above the func
 *   .runar.rs    `#[embed_always]`                         `#[sighash(SINGLE | FORKID)] pub fn f`
 *   .runar.py    `x: EmbedAlways[T]`                       `@public(sighash="SINGLE|FORKID")`
 *   .runar.zig   `x: runar.EmbedAlways(T)`                 `pub fn f(..) runar.Sighash("SINGLE|FORKID")`
 *   .runar.rb    `prop :x, T, embed_always: true`          `runar_sighash 'SINGLE|FORKID'` before the def
 *   .runar.java  `@EmbedAlways`                            `@Sighash("SINGLE|FORKID")`
 *
 * What this proves (TypeScript reference tier):
 *   - each surface's port of `examples/ts/compiler-directives/Directives` and
 *     `EmbedTags` compiles to the SAME script hex as the `.runar.ts` original,
 *     keeps `deployTag` in `constructorSlots` (the observable `@embedAlways`
 *     exists for), and carries `sigHashType` 0x43 on `spendSingle` only;
 *   - every malformed native spelling is REFUSED with the shared diagnostics
 *     the `.runar.ts` comment directive uses (non-public method, two
 *     spellings, malformed argument, bad flag set, directive on the wrong
 *     member kind) — none falls back to ALL|FORKID or to DCE silently;
 *   - a COMMENT directive on a non-TS surface is still refused (its parser
 *     drops comments), and the message now names the native spelling.
 * What it does NOT prove:
 *   - anything about the six other compiler tiers (each has its own port and
 *     test; cross-tier byte parity is the conformance fixtures
 *     `compiler-directives` and `embed-always-fixed-array`);
 *   - on-chain behaviour of the bytes (the real-crypto witnesses do that);
 *   - that the examples build natively in their host languages (the example
 *     suites do that).
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { compile } from '../index.js';
import { parse } from '../passes/01-parse.js';

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '../../../..');
const EX = join(REPO, 'examples');

const SINGLE_FORKID = 0x43;

interface Surface {
  ext: string;
  dir: string;
  /** Directives source, as checked in. */
  directives: string;
  /** EmbedTags source (absent for Java: FixedArray cannot be spelled there). */
  embedTags?: string;
}

function read(p: string): string {
  return readFileSync(join(EX, p), 'utf8');
}

const SURFACES: Surface[] = [
  { ext: '.runar.sol', dir: 'sol', directives: read('sol/compiler-directives/Directives.runar.sol'), embedTags: read('sol/compiler-directives/EmbedTags.runar.sol') },
  { ext: '.runar.move', dir: 'move', directives: read('move/compiler-directives/Directives.runar.move'), embedTags: read('move/compiler-directives/EmbedTags.runar.move') },
  { ext: '.runar.go', dir: 'go', directives: read('go/compiler-directives/Directives.runar.go'), embedTags: read('go/compiler-directives/EmbedTags.runar.go') },
  { ext: '.runar.rs', dir: 'rust', directives: read('rust/compiler-directives/Directives.runar.rs'), embedTags: read('rust/compiler-directives/EmbedTags.runar.rs') },
  { ext: '.runar.py', dir: 'python', directives: read('python/compiler-directives/Directives.runar.py'), embedTags: read('python/compiler-directives/EmbedTags.runar.py') },
  { ext: '.runar.zig', dir: 'zig', directives: read('zig/compiler-directives/Directives.runar.zig'), embedTags: read('zig/compiler-directives/EmbedTags.runar.zig') },
  { ext: '.runar.rb', dir: 'ruby', directives: read('ruby/compiler-directives/Directives.runar.rb'), embedTags: read('ruby/compiler-directives/EmbedTags.runar.rb') },
  { ext: '.runar.java', dir: 'java', directives: read('java/src/main/java/runar/examples/compiler-directives/Directives.runar.java') },
];

function build(src: string, fileName: string) {
  const r = compile(src, { fileName, disableConstantFolding: true });
  const errs = r.diagnostics.filter((d) => d.severity === 'error').map((d) => d.message);
  expect(errs, `${fileName} did not compile`).toEqual([]);
  return r;
}

const TS_DIRECTIVES = build(read('ts/compiler-directives/Directives.runar.ts'), 'Directives.runar.ts');
const TS_EMBED_TAGS = build(read('ts/compiler-directives/EmbedTags.runar.ts'), 'EmbedTags.runar.ts');

/** The ANF IR without source locations (which name the surface file). */
function canonicalAnf(anf: unknown): string {
  return JSON.stringify(anf, (k, v) => (k === 'sourceLoc' ? undefined : v));
}

function errorsOf(src: string, fileName: string): string[] {
  return parse(src, fileName).errors.filter((e) => e.severity === 'error').map((e) => e.message);
}

/** Replace exactly one occurrence, so a stale needle fails loudly. */
function swap(src: string, from: string, to: string): string {
  expect(src.split(from).length, `needle not found exactly once: ${from}`).toBe(2);
  return src.replace(from, to);
}

describe('N-093: native directive spellings compile like the .runar.ts comment directives', () => {
  it('the TS reference pins the expected bytes', () => {
    expect(TS_EMBED_TAGS.scriptHex).toBe('57595b537a59a2695379a90088547a547aac777777');
    expect(TS_DIRECTIVES.artifact!.abi.methods.find((m) => m.name === 'spendSingle')!.sigHashType).toBe(SINGLE_FORKID);
  });

  for (const s of SURFACES) {
    it(`${s.ext}: Directives matches the TS hex, keeps deployTag, sets SINGLE|FORKID on spendSingle only`, () => {
      const r = build(s.directives, `Directives${s.ext}`);
      expect(r.scriptHex).toBe(TS_DIRECTIVES.scriptHex);
      expect((r.artifact!.constructorSlots ?? []).map((x) => x.name)).toContain('deployTag');
      const byName = new Map(r.artifact!.abi.methods.map((m) => [m.name, m.sigHashType]));
      expect(byName.get('spendSingle')).toBe(SINGLE_FORKID);
      expect(byName.get('spendAll')).toBeUndefined();
      expect(canonicalAnf(r.anf)).toBe(canonicalAnf(TS_DIRECTIVES.anf));
    });

    if (s.embedTags !== undefined) {
      it(`${s.ext}: EmbedTags keeps every FixedArray slot (same hex as TS)`, () => {
        const r = build(s.embedTags!, `EmbedTags${s.ext}`);
        expect(r.scriptHex).toBe(TS_EMBED_TAGS.scriptHex);
      });
    }
  }
});

const NON_PUBLIC = "@sighash directive on non-public method";
const MULTIPLE = 'more than one @sighash directive on this method';
const MALFORMED = '@sighash: malformed directive';
const NO_FORKID = 'FORKID is mandatory on BSV';
const LOST_SIGHASH = '@sighash directive is not attached to any method';
const LOST_EMBED = '@embedAlways directive is not attached to any property';

type Case = readonly [label: string, mutate: (src: string) => string, expected: string];

const NEGATIVES: Record<string, Case[]> = {
  '.runar.sol': [
    ['no FORKID', (x) => swap(x, 'sighash(SINGLE | FORKID)', 'sighash(SINGLE)'), NO_FORKID],
    ['comma-separated', (x) => swap(x, 'sighash(SINGLE | FORKID)', 'sighash(SINGLE, FORKID)'), MALFORMED],
    ['two modifiers', (x) => swap(x, 'sighash(SINGLE | FORKID)', 'sighash(SINGLE | FORKID) sighash(ALL | FORKID)'), MULTIPLE],
    ['private method', (x) => swap(x, 'public sighash(SINGLE | FORKID)', 'private sighash(SINGLE | FORKID)'), NON_PUBLIC],
  ],
  '.runar.move': [
    ['no FORKID', (x) => swap(x, '#[sighash(SINGLE | FORKID)]', '#[sighash(SINGLE)]'), NO_FORKID],
    ['comma-separated', (x) => swap(x, '#[sighash(SINGLE | FORKID)]', '#[sighash(SINGLE, FORKID)]'), MALFORMED],
    ['two attributes', (x) => swap(x, '#[sighash(SINGLE | FORKID)]', '#[sighash(SINGLE | FORKID)]\n    #[sighash(ALL | FORKID)]'), MULTIPLE],
    ['private fun', (x) => swap(x, 'public fun spend_single', 'fun spend_single'), NON_PUBLIC],
    ['sighash on a field', (x) => swap(x, '#[embed_always]', '#[sighash(SINGLE | FORKID)]'), LOST_SIGHASH],
    ['embed_always on a fun', (x) => swap(x, '#[sighash(SINGLE | FORKID)]', '#[embed_always]'), LOST_EMBED],
    ['unknown attribute', (x) => swap(x, '#[sighash(SINGLE | FORKID)]', '#[test]'), 'unsupported Move attribute #[test]'],
  ],
  '.runar.go': [
    ['no FORKID', (x) => swap(x, '//runar:sighash SINGLE|FORKID', '//runar:sighash SINGLE'), NO_FORKID],
    ['comma-separated', (x) => swap(x, '//runar:sighash SINGLE|FORKID', '//runar:sighash SINGLE,FORKID'), MALFORMED],
    ['glued', (x) => swap(x, '//runar:sighash SINGLE|FORKID', '//runar:sighashSINGLE|FORKID'), "unknown Go DSL directive '//runar:sighashSINGLE|FORKID'"],
    ['two directives', (x) => swap(x, '//runar:sighash SINGLE|FORKID', '//runar:sighash SINGLE|FORKID\n//runar:sighash ALL|FORKID'), MULTIPLE],
    ['unexported method', (x) => swap(x, '//runar:sighash SINGLE|FORKID\nfunc (c *Directives) SpendSingle', '//runar:sighash SINGLE|FORKID\nfunc (c *Directives) spendSingleHelper() {}\n\nfunc (c *Directives) SpendSingle'), NON_PUBLIC],
    ['not above a func', (x) => swap(x, 'type Directives struct', '//runar:sighash SINGLE|FORKID\ntype Directives struct'), LOST_SIGHASH],
    ['unknown directive', (x) => swap(x, '//runar:sighash SINGLE|FORKID', '//runar:inline'), "unknown Go DSL directive '//runar:inline'"],
  ],
  '.runar.rs': [
    ['no FORKID', (x) => swap(x, '#[sighash(SINGLE | FORKID)]', '#[sighash(SINGLE)]'), NO_FORKID],
    ['comma-separated', (x) => swap(x, '#[sighash(SINGLE | FORKID)]', '#[sighash(SINGLE, FORKID)]'), MALFORMED],
    ['two attributes', (x) => swap(x, '#[sighash(SINGLE | FORKID)]', '#[sighash(SINGLE | FORKID)]\n    #[sighash(ALL | FORKID)]'), MULTIPLE],
    ['private fn', (x) => swap(x, 'pub fn spend_single', 'fn spend_single'), NON_PUBLIC],
    ['sighash on a field', (x) => swap(x, '#[embed_always]', '#[sighash(SINGLE | FORKID)]'), LOST_SIGHASH],
    ['embed_always on a fn', (x) => swap(x, '#[sighash(SINGLE | FORKID)]', '#[embed_always]'), LOST_EMBED],
  ],
  '.runar.py': [
    ['no FORKID', (x) => swap(x, '@public(sighash="SINGLE|FORKID")', '@public(sighash="SINGLE")'), NO_FORKID],
    ['non-string argument', (x) => swap(x, '@public(sighash="SINGLE|FORKID")', '@public(sighash=SINGLE)'), MALFORMED],
    ['unknown keyword', (x) => swap(x, '@public(sighash="SINGLE|FORKID")', '@public(mode="SINGLE|FORKID")'), MALFORMED],
    ['two decorators', (x) => swap(x, '@public(sighash="SINGLE|FORKID")', '@public(sighash="SINGLE|FORKID")\n    @public(sighash="ALL|FORKID")'), MULTIPLE],
  ],
  '.runar.zig': [
    ['no FORKID', (x) => swap(x, 'runar.Sighash("SINGLE|FORKID")', 'runar.Sighash("SINGLE")'), NO_FORKID],
    ['non-string argument', (x) => swap(x, 'runar.Sighash("SINGLE|FORKID")', 'runar.Sighash(SINGLE)'), MALFORMED],
    ['private fn', (x) => swap(x, 'pub fn spendSingle', 'fn spendSingle'), NON_PUBLIC],
  ],
  '.runar.rb': [
    ['no FORKID', (x) => swap(x, "runar_sighash 'SINGLE|FORKID'", "runar_sighash 'SINGLE'"), NO_FORKID],
    ['symbol argument', (x) => swap(x, "runar_sighash 'SINGLE|FORKID'", 'runar_sighash :single'), MALFORMED],
    ['two macros', (x) => swap(x, "runar_sighash 'SINGLE|FORKID'", "runar_sighash 'SINGLE|FORKID'\n  runar_sighash 'ALL|FORKID'"), MULTIPLE],
    ['private method', (x) => swap(x, "runar_sighash 'SINGLE|FORKID'\n  runar_public sig: Sig, pub_key: PubKey\n", "runar_sighash 'SINGLE|FORKID'\n"), NON_PUBLIC],
    ['no following def', (x) => swap(x, "\nend\n", "\n\n  runar_sighash 'ALL|FORKID'\nend\n"), LOST_SIGHASH],
  ],
  '.runar.java': [
    ['no FORKID', (x) => swap(x, '@Sighash("SINGLE|FORKID")', '@Sighash("SINGLE")'), NO_FORKID],
    ['non-string argument', (x) => swap(x, '@Sighash("SINGLE|FORKID")', '@Sighash(1)'), MALFORMED],
    ['two annotations', (x) => swap(x, '@Sighash("SINGLE|FORKID")', '@Sighash("SINGLE|FORKID")\n    @Sighash("ALL|FORKID")'), MULTIPLE],
    ['no @Public', (x) => swap(x, '    @Public\n    @Sighash', '    @Sighash'), NON_PUBLIC],
    ['@Sighash on a field', (x) => swap(x, '@Readonly @EmbedAlways ByteString', '@Readonly @Sighash("ALL|FORKID") ByteString'), LOST_SIGHASH],
    ['@EmbedAlways on a method', (x) => swap(x, '@Sighash("SINGLE|FORKID")', '@EmbedAlways'), LOST_EMBED],
  ],
};

describe('N-093: a malformed native spelling is refused, never ignored', () => {
  for (const s of SURFACES) {
    for (const [label, mutate, expected] of NEGATIVES[s.ext]!) {
      it(`${s.ext}: ${label} -> ${expected}`, () => {
        const errs = errorsOf(mutate(s.directives), `Directives${s.ext}`);
        expect(errs.join('\n')).toContain(expected);
      });
    }
  }
});

describe('N-093: a native directive on the constructor is refused, never dropped', () => {
  const CASES: ReadonlyArray<readonly [ext: string, from: string, to: string, expected: string]> = [
    ['.runar.rs', '    pub fn spend_all', '    #[sighash(ALL | FORKID)]\n    pub fn init(&mut self) {}\n\n    pub fn spend_all', LOST_SIGHASH],
    ['.runar.zig', ', deployTag: runar.ByteString) Directives {', ', deployTag: runar.ByteString) runar.Sighash("ALL|FORKID") {', LOST_SIGHASH],
    ['.runar.py', '    def __init__', '    @public(sighash="ALL|FORKID")\n    def __init__', LOST_SIGHASH],
    ['.runar.rb', '  def initialize', "  runar_sighash 'ALL|FORKID'\n  def initialize", LOST_SIGHASH],
    ['.runar.java', '    Directives(Addr', '    @Sighash("ALL|FORKID")\n    Directives(Addr', LOST_SIGHASH],
    ['.runar.java', '    Directives(Addr', '    @EmbedAlways\n    Directives(Addr', LOST_EMBED],
  ];
  for (const [ext, from, to, expected] of CASES) {
    it(`${ext}: ${to.trim().split('\n')[0]} -> ${expected}`, () => {
      const s = SURFACES.find((x) => x.ext === ext)!;
      expect(errorsOf(swap(s.directives, from, to), `Directives${ext}`).join('\n')).toContain(expected);
    });
  }
});

describe('N-093: the native spellings compose with readonly in either order', () => {
  it('.runar.rs: #[embed_always] before #[readonly]', () => {
    const s = SURFACES.find((x) => x.ext === '.runar.rs')!;
    const r = build(swap(s.directives, '#[readonly]\n    #[embed_always]', '#[embed_always]\n    #[readonly]'), 'Directives.runar.rs');
    expect(r.scriptHex).toBe(TS_DIRECTIVES.scriptHex);
  });
  it('.runar.rs: #[runar::sighash(...)] is the same attribute', () => {
    const s = SURFACES.find((x) => x.ext === '.runar.rs')!;
    const r = build(swap(s.directives, '#[sighash(', '#[runar::sighash('), 'Directives.runar.rs');
    expect(r.artifact!.abi.methods.find((m) => m.name === 'spendSingle')!.sigHashType).toBe(SINGLE_FORKID);
  });
  it('.runar.py: Readonly[EmbedAlways[T]] equals EmbedAlways[T]', () => {
    const s = SURFACES.find((x) => x.ext === '.runar.py')!;
    const r = build(swap(s.directives, 'EmbedAlways[ByteString]', 'Readonly[EmbedAlways[ByteString]]'), 'Directives.runar.py');
    expect(r.scriptHex).toBe(TS_DIRECTIVES.scriptHex);
  });
  it('.runar.zig: runar.Readonly(runar.EmbedAlways(T)) equals runar.EmbedAlways(T)', () => {
    const s = SURFACES.find((x) => x.ext === '.runar.zig')!;
    const r = build(swap(s.directives, 'runar.EmbedAlways(runar.ByteString)', 'runar.Readonly(runar.EmbedAlways(runar.ByteString))'), 'Directives.runar.zig');
    expect(r.scriptHex).toBe(TS_DIRECTIVES.scriptHex);
  });
  it('.runar.sol: embedAlways before immutable', () => {
    const s = SURFACES.find((x) => x.ext === '.runar.sol')!;
    const r = build(swap(s.directives, 'ByteString immutable embedAlways deployTag', 'ByteString embedAlways immutable deployTag'), 'Directives.runar.sol');
    expect(r.scriptHex).toBe(TS_DIRECTIVES.scriptHex);
  });
  it('.runar.rb: runar_sighash after the runar_public line', () => {
    const s = SURFACES.find((x) => x.ext === '.runar.rb')!;
    const r = build(swap(s.directives, "runar_sighash 'SINGLE|FORKID'\n  runar_public sig: Sig, pub_key: PubKey\n", "runar_public sig: Sig, pub_key: PubKey\n  runar_sighash 'SINGLE|FORKID'\n"), 'Directives.runar.rb');
    expect(r.artifact!.abi.methods.find((m) => m.name === 'spendSingle')!.sigHashType).toBe(SINGLE_FORKID);
  });
  it('.runar.go: a doc comment between the directive and the func is allowed', () => {
    const s = SURFACES.find((x) => x.ext === '.runar.go')!;
    const r = build(swap(s.directives, '//runar:sighash SINGLE|FORKID\n', '//runar:sighash SINGLE|FORKID\n// SpendSingle commits to one output.\n'), 'Directives.runar.go');
    expect(r.artifact!.abi.methods.find((m) => m.name === 'spendSingle')!.sigHashType).toBe(SINGLE_FORKID);
  });
  it('.runar.go: a field without embedAlways in its tag is not embedded', () => {
    const s = SURFACES.find((x) => x.ext === '.runar.go')!;
    const r = build(swap(s.directives, '`runar:"readonly,embedAlways"`', '`runar:"readonly"`'), 'Directives.runar.go');
    expect((r.artifact!.constructorSlots ?? []).map((x) => x.name)).not.toContain('deployTag');
  });
});

describe('N-093: a COMMENT directive on a non-TS surface is still refused, naming the native spelling', () => {
  const NAMES: Record<string, [string, string, string, string]> = {
    '.runar.sol': ['Solidity', 'solidity', 'the function modifier sighash(<FLAGS>)', 'the property modifier embedAlways'],
    '.runar.move': ['Move', 'move', 'the attribute #[sighash(<FLAGS>)]', 'the attribute #[embed_always]'],
    '.runar.go': ['Go DSL', 'go', 'the directive //runar:sighash <FLAGS>', 'the struct tag option runar:"readonly,embedAlways"'],
    '.runar.rs': ['Rust', 'rust', 'the attribute #[sighash(<FLAGS>)]', 'the attribute #[embed_always]'],
    '.runar.py': ['Python', 'python', '@public(sighash="<FLAGS>")', 'the wrapper type EmbedAlways[T]'],
    '.runar.zig': ['Zig', 'zig', 'the return type runar.Sighash("<FLAGS>")', 'the type function runar.EmbedAlways(T)'],
    '.runar.rb': ['Ruby', 'ruby', "runar_sighash '<FLAGS>'", 'the prop option embed_always: true'],
    '.runar.java': ['Java', 'java', 'the annotation @Sighash("<FLAGS>")', 'the annotation @EmbedAlways'],
  };
  for (const s of SURFACES) {
    const [surface, doc, sig, emb] = NAMES[s.ext]!;
    const comment = s.ext === '.runar.py' || s.ext === '.runar.rb' ? '#' : '//';
    it(`${s.ext}: a @sighash comment`, () => {
      const errs = errorsOf(`${comment} @sighash SINGLE|FORKID\n${s.directives}`, `Directives${s.ext}`);
      expect(errs).toEqual([
        `@sighash directive (issue #123) is not supported as a comment by the ${surface} surface parser; write it as ${sig} (see docs/formats/${doc}.md)`,
      ]);
    });
    it(`${s.ext}: an @embedAlways comment`, () => {
      const errs = errorsOf(`${comment} @embedAlways\n${s.directives}`, `Directives${s.ext}`);
      expect(errs).toEqual([
        `@embedAlways directive (issue #109) is not supported as a comment by the ${surface} surface parser; write it as ${emb} (see docs/formats/${doc}.md)`,
      ]);
    });
  }
});
