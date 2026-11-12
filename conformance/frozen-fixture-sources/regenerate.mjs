#!/usr/bin/env node
// Rebuild the 31 compiled-artifact fixtures that live OUTSIDE conformance/tests and
// conformance/sdk-output (those two have their own generators). See README.md here
// for the fixture -> source -> compiler -> options -> stripping table.
//
//   node conformance/frozen-fixture-sources/regenerate.mjs           # rewrite fixtures
//   node conformance/frozen-fixture-sources/regenerate.mjs --check   # rebuild + diff, write nothing
//   ... [--only <substring of fixture path>]
//
// Why `--check` exists: these fixtures embed a compiled artifact, and nothing tied
// them to the compiler. When #187 changed the OP_PUSH_TX binding blob they kept the
// old one, and most had already missed two earlier codegen changes. The same
// argument as `conformance/sdk-output/generate-inputs.ts --check`.
//
// Each fixture is rebuilt by the compiler TIER that originally produced it (the
// Zig/Go/Java fixtures carry that tier's artifact shape and compilerVersion), so
// the script needs every one of these, built from this checkout:
//   - TS:   pnpm build                     (packages/runar-compiler/dist, packages/runar-sdk/dist)
//   - Zig:  cd compilers/zig && zig build   (compilers/zig/zig-out/bin/runar-zig)
//   - Java: cd conformance/sdk-output/tools/java-driver && gradle fatJar
//           (composite-builds compilers/java/build/libs/runar-java-compiler-*.jar)
//   - Go:   a Go toolchain; the compiler is built into a temp dir on each run.
//
// `buildTimestamp` is the only field compared loosely: --check ignores it, and a
// rewrite keeps the existing timestamp when nothing else changed.

import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '../..');
const args = process.argv.slice(2);
const CHECK = args.includes('--check');
const ONLY = args.includes('--only') ? args[args.indexOf('--only') + 1] : null;

function need(path, how) {
  if (!existsSync(path)) {
    console.error(`missing ${path}\n  build it with: ${how}`);
    process.exit(2);
  }
  return path;
}

const { compile } = await import(
  need(join(ROOT, 'packages/runar-compiler/dist/index.js'), 'pnpm build')
);
const { RunarContract } = await import(need(join(ROOT, 'packages/runar-sdk/dist/index.js'), 'pnpm build'));
const ZIG = need(join(ROOT, 'compilers/zig/zig-out/bin/runar-zig'), 'cd compilers/zig && zig build');
const JAVA_LIBS = join(ROOT, 'compilers/java/build/libs');
const JAVA_JAR = existsSync(JAVA_LIBS)
  ? readdirSync(JAVA_LIBS).find((f) => /^runar-java-compiler-.*\.jar$/.test(f))
  : undefined;
need(JAVA_JAR ? join(JAVA_LIBS, JAVA_JAR) : join(JAVA_LIBS, 'runar-java-compiler-*.jar'),
  'cd conformance/sdk-output/tools/java-driver && gradle fatJar');
const TMP = mkdtempSync(join(tmpdir(), 'runar-frozen-fixtures-'));
process.on('exit', () => rmSync(TMP, { recursive: true, force: true }));
let goBin = null;
function go() {
  if (!goBin) {
    goBin = join(TMP, 'runar-go');
    execFileSync('go', ['build', '-o', goBin, '.'], { cwd: join(ROOT, 'compilers/go'), stdio: 'pipe' });
  }
  return goBin;
}

// ---------------------------------------------------------------------------
// compilers

const SRC = (p) => join(HERE, p);
const REPO = (p) => join(ROOT, p);
const bigintN = (k, v) => (typeof v === 'bigint' ? `${v}n` : v); // CLI / artifact convention
const bigintPlain = (k, v) => (typeof v === 'bigint' ? String(v) : v); // matches-artifact convention

/** TS compiler API, bare fileName (so sourceMap/sourceLoc name the basename), default options. */
function ts(srcPath, opts = {}, replacer = bigintN) {
  const fileName = srcPath.split('/').pop();
  const r = compile(readFileSync(srcPath, 'utf8'), { fileName, ...opts });
  if (!r.success) throw new Error(`${srcPath}: ${JSON.stringify(r.diagnostics).slice(0, 400)}`);
  return JSON.parse(JSON.stringify(r.artifact, replacer));
}
const cli = (bin, argv, cwd) =>
  JSON.parse(execFileSync(bin, argv, { cwd, encoding: 'utf8', maxBuffer: 1 << 28, stdio: ['ignore', 'pipe', 'pipe'] }));
function javaCompile(srcRel) {
  const out = join(TMP, 'java-artifact.json');
  execFileSync('java', ['-cp', join(JAVA_LIBS, JAVA_JAR), 'runar.compiler.Cli', '--source', srcRel,
    '--disable-constant-folding', '--emit-artifact', out], { cwd: ROOT, stdio: 'pipe' });
  const a = JSON.parse(readFileSync(out, 'utf8'));
  // bump-version.sh --check expects the bare version in this fixture (N-157).
  a.compilerVersion = a.compilerVersion.replace(/-java$/, '');
  return a;
}
const drop = (a, ...keys) => { for (const k of keys) delete a[k]; return a; };
const stripSourceLoc = (a) => JSON.parse(JSON.stringify(a, (k, v) => (k === 'sourceLoc' ? undefined : v)));

// ---------------------------------------------------------------------------
// conformance/sdk-matches-artifact recipes

const put = (hex, byteOff, oldBytes, newBytes) => {
  const at = byteOff * 2;
  if (hex.slice(at, at + oldBytes.length) !== oldBytes)
    throw new Error(`expected ${oldBytes} at byte ${byteOff}, found ${hex.slice(at, at + oldBytes.length)}`);
  return hex.slice(0, at) + newBytes + hex.slice(at + oldBytes.length);
};
const le4 = (n) => [0, 8, 16, 24].map((s) => ((n >>> s) & 0xff).toString(16).padStart(2, '0')).join('');
const rdle = (h) => parseInt(h.match(/../g).reverse().join(''), 16);
function honest(artifact, ctorArgs, state) {
  const c = new RunarContract(artifact, ctorArgs);
  if (state) c.setState(state);
  return c.getLockingScript();
}
/** Offset in a deployed script of a template byte offset: every earlier constructor slot grew from its 1-byte placeholder. */
function candOffset(artifact, hex, tOff) {
  let shift = 0;
  for (const s of [...(artifact.constructorSlots ?? [])].sort((a, b) => a.byteOffset - b.byteOffset)) {
    if (s.byteOffset >= tOff) break;
    const p = (s.byteOffset + shift) * 2;
    const op = parseInt(hex.slice(p, p + 2), 16);
    let len = 1;
    if (op >= 0x01 && op <= 0x4b) len = 1 + op;
    else if (op === 0x4c) len = 2 + parseInt(hex.slice(p + 2, p + 4), 16);
    else if (op === 0x4d) len = 3 + rdle(hex.slice(p + 2, p + 6));
    shift += len - 1;
  }
  return tOff + shift;
}
/** Replace the element at codeSep slot(s) {templateOffset: bytes}; re-patch every code-part length pin. */
function forgeCodesep(artifact, hex, repl) {
  const edits = [];
  let delta = 0;
  for (const [tOff, bytes] of Object.entries(repl)) {
    const c = candOffset(artifact, hex, Number(tOff));
    edits.push({ at: c, old: hex.slice(c * 2, c * 2 + 2), neu: bytes });
    delta += bytes.length / 2 - 1;
  }
  for (const p of artifact.codePartLenSlots ?? []) {
    const c = candOffset(artifact, hex, p.byteOffset); // the slot names the 4-byte LE value itself
    const cur = hex.slice(c * 2, c * 2 + 8);
    edits.push({ at: c, old: cur, neu: le4(rdle(cur) + delta) });
  }
  edits.sort((a, b) => b.at - a.at);
  return edits.reduce((h, e) => put(h, e.at, e.old, e.neu), hex);
}

/** N-316. Artifact 1 = InitLog (all four InitLog cases share it); LenOnly cases are synthetic and kept. */
function matchesFixtures(current) {
  const art = ts(SRC('InitLog.runar.ts'), {}, bigintPlain);
  const slot = art.codeSepIndexSlots[0].byteOffset;
  const h0 = honest(art, []);
  const hex = {
    'codesep-only-honest-deployment': h0,
    'codesep-only-honest-deployment-other-state': honest(art, [], { log: 'abcdef' }),
    // one code byte flipped 40 bytes after / before the codeSep slot
    'codesep-only-tampered-after-slot': put(h0, slot + 40, '7f', '7e'),
    'codesep-only-tampered-before-slot': put(h0, slot - 40, '02', '03'),
  };
  return {
    ...current,
    cases: current.cases.map((c) =>
      c.artifact.contractName === 'InitLog' ? { ...c, artifact: art, script_hex: hex[c.name] } : c),
  };
}

/** N-318. "real" = TaggedLog (sourceMap/anf dropped); "shift" is synthetic and kept. */
function matchesCodesep(current) {
  const art = drop(ts(SRC('TaggedLog.runar.ts'), {}, bigintPlain), 'sourceMap', 'anf');
  const ctor = { cap0: [0n, ''], cap5: [5n, 'abcd'], cap1000: [1000n, ''], cap2pow200: [2n ** 200n + 7n, '00'] };
  const oldOffs = current.artifacts.real.codeSepIndexSlots.map((s) => s.byteOffset);
  const newOffs = art.codeSepIndexSlots.map((s) => s.byteOffset);
  const elems = (h) => Object.fromEntries(newOffs.map((o) => {
    const c = candOffset(art, h, o);
    return [String(o), h.slice(c * 2, c * 2 + 2)];
  }));
  const cases = current.cases.map((c) => {
    if (c.artifact !== 'real') return c;
    const m = c.name.match(/^real-(cap\w+?)-(honest|forged)/);
    const h = honest(art, ctor[m[1]]);
    if (m[2] === 'honest')
      return { ...c, script_hex: h, why: `RunarContract.getLockingScript(); codeSep slot elements ${Object.values(elems(h)).join(',')}` };
    // the case's own `why` names {templateOffset: element}; map onto this artifact's slots
    const named = JSON.parse(c.why.match(/element\(s\) (\{[^}]*\})/)[1]);
    const repl = Object.fromEntries(Object.entries(named).map(([k, v]) => [String(newOffs[oldOffs.indexOf(Number(k))]), v]));
    return {
      ...c,
      script_hex: forgeCodesep(art, h, repl),
      why: `honest real-${m[1]} with codeSep slot element(s) ${JSON.stringify(repl)} (honest ${JSON.stringify(elems(h))}); code-part length pins re-patched`,
    };
  });
  return { ...current, artifacts: { ...current.artifacts, real: art }, cases };
}

// ---------------------------------------------------------------------------
// fixture table (keep README.md in step)

const arraywrite = () =>
  stripSourceLoc(drop(ts(REPO('examples/ts/fixed-array-write/ArrayWrite.runar.ts'), { includeIR: true }),
    'asm', 'buildTimestamp', 'sourceMap', 'ir'));

const JOBS = {
  'packages/runar-go/testdata/arraywrite-artifact.json': arraywrite,
  'packages/runar-py/tests/testdata/arraywrite-artifact.json': arraywrite,
  'packages/runar-rb/spec/fixtures/arraywrite-artifact.json': arraywrite,
  'packages/runar-rs/tests/fixtures/arraywrite-artifact.json': arraywrite,
  'packages/runar-zig/src/fixtures/arraywrite-artifact.json': arraywrite,
  'packages/runar-java/src/test/resources/artifacts/arraywrite.runar.json': arraywrite,
  'packages/runar-java/src/test/resources/artifacts/fund-acp.runar.json': () => ts(SRC('fund-acp/Fund.runar.ts')),
  'packages/runar-java/src/test/resources/artifacts/fund-default.runar.json': () => ts(SRC('fund-default/Fund.runar.ts')),
  'packages/runar-java/src/test/resources/artifacts/sat-counter.runar.json': () => ts(SRC('SatCounter.runar.ts')),
  'packages/runar-java/src/test/resources/artifacts/token-ft.runar.json': () =>
    ts(REPO('examples/ts/token-ft/FungibleTokenExample.runar.ts')), // fold ON (API default)
  'packages/runar-java/src/test/resources/artifacts/raw-output.runar.json': () =>
    cli(go(), ['--source', '../../examples/ts/add-raw-output/RawOutputTest.runar.ts'], REPO('packages/runar-java')),
  'packages/runar-java/src/test/resources/artifacts/stateful-counter.runar.json': () =>
    javaCompile('examples/java/src/main/java/runar/examples/stateful-counter/Counter.runar.java'),
  'packages/runar-zig/src/fixtures/satcounter-artifact.json': () =>
    stripSourceLoc(drop(cli(ZIG, ['--source', 'SatCounter.runar.ts'], HERE), 'sourceMap')),
  'packages/runar-zig/src/fixtures/g1-raw-output-artifact.json': () =>
    drop(cli(ZIG, ['--source', 'examples/zig/add-raw-output/RawOutputTest.runar.zig'], ROOT), 'sourceMap'),
  'packages/runar-zig/src/fixtures/n189-sclen-artifact.json': () => cli(ZIG, ['--source', 'ScLen.runar.ts'], HERE),
  'packages/runar-zig/src/fixtures/n227-all-readonly-cleanstack-artifact.json': () =>
    cli(ZIG, ['--source', '../../examples/ts/all-readonly-cleanstack/AllReadonlyCleanstack.runar.ts'], REPO('packages/runar-zig')),
  'packages/runar-zig/src/fixtures/f024-tip-artifact.json': () => cli(ZIG, ['--source', 'Tip.runar.ts'], HERE),
  'conformance/sdk-matches-artifact/fixtures.json': matchesFixtures,
  'conformance/sdk-matches-artifact/codesep.json': matchesCodesep,
};

// ---------------------------------------------------------------------------

const maskTs = (x) => JSON.parse(JSON.stringify(x, (k, v) => (k === 'buildTimestamp' ? '<ts>' : v)));
function render(obj, like) {
  const indent = like.startsWith('{\n  "') ? 2 : like.startsWith('{\n "') ? 1 : 0;
  return (indent ? JSON.stringify(obj, null, indent) : JSON.stringify(obj)) + '\n';
}
function firstDiff(a, b) {
  let i = 0;
  while (i < a.length && a[i] === b[i]) i++;
  return `char ${i}: on disk …${a.slice(Math.max(0, i - 40), i + 40)}… vs fresh …${b.slice(Math.max(0, i - 40), i + 40)}…`;
}

const drifted = [];
const failed = [];
for (const [rel, build] of Object.entries(JOBS)) {
  if (ONLY && !rel.includes(ONLY)) continue;
  const path = REPO(rel);
  const onDiskText = readFileSync(path, 'utf8');
  let fresh;
  try {
    fresh = build(JSON.parse(onDiskText));
  } catch (err) {
    failed.push(`${rel}: ${String(err.stderr || err.message || err).slice(0, 300)}`);
    console.error(`  FAILED ${rel}`);
    continue;
  }
  const a = render(maskTs(JSON.parse(onDiskText)), onDiskText);
  const b = render(maskTs(fresh), onDiskText);
  if (a === b) {
    console.log(`  ok ${rel}`);
    continue;
  }
  if (CHECK) {
    drifted.push(`${rel} (${firstDiff(a, b)})`);
    console.error(`  DRIFT ${rel}`);
  } else {
    writeFileSync(path, render(fresh, onDiskText));
    console.log(`  wrote ${rel}`);
  }
}

if (failed.length) {
  console.error(`\n✗ ${failed.length} fixture(s) could not be rebuilt:\n` + failed.map((f) => `    - ${f}`).join('\n'));
  process.exit(1);
}
if (drifted.length) {
  console.error(
    `\n✗ ${drifted.length} fixture(s) differ from what the current compilers produce:\n` +
      drifted.map((d) => `    - ${d}`).join('\n') +
      `\n\n  Fix: node conformance/frozen-fixture-sources/regenerate.mjs, then review the diff.\n`,
  );
  process.exit(1);
}
console.log(CHECK ? '\n✓ frozen fixtures match the current compilers.' : '\nDone.');
