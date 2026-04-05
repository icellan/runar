import { execFileSync } from 'child_process';
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'fs';
import { join, basename, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '../..');
const TESTS_DIR = join(__dirname, 'tests');

interface TestSpec {
  name: string;
  source: string; // relative to ROOT
  constructorArgs: Array<{ type: string; value: string }>;
}

const TEST_SPECS: TestSpec[] = [
  {
    name: 'stateful-bytestring',
    source: 'conformance/tests/stateful-bytestring/stateful-bytestring.runar.ts',
    constructorArgs: [
      { type: 'ByteString', value: '48656c6c6f' },  // "Hello"
      { type: 'PubKey', value: '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798' },
    ],
  },
  {
    name: 'stateful-counter',
    source: 'conformance/tests/stateful-counter/stateful-counter.runar.ts',
    constructorArgs: [
      { type: 'bigint', value: '42' },
    ],
  },
  {
    name: 'basic-p2pkh',
    source: 'conformance/tests/basic-p2pkh/basic-p2pkh.runar.ts',
    constructorArgs: [
      { type: 'Addr', value: '89abcdefabbaabbaabbaabbaabbaabbaabbaabba' },
    ],
  },
];

const TMP_DIR = join(__dirname, '.tmp');
if (!existsSync(TMP_DIR)) mkdirSync(TMP_DIR, { recursive: true });

for (const spec of TEST_SPECS) {
  const sourcePath = join(ROOT, spec.source);
  console.log(`Compiling ${spec.name}...`);
  execFileSync(
    'npx',
    ['tsx', 'packages/runar-cli/src/bin.ts', 'compile', sourcePath, '-o', TMP_DIR],
    { cwd: ROOT, stdio: 'pipe' },
  );

  const sourceBase = basename(spec.source, '.ts');
  const artifactPath = join(TMP_DIR, `${sourceBase}.json`);
  const artifact = JSON.parse(readFileSync(artifactPath, 'utf-8'));

  // Strip fields not needed by SDK tools
  delete artifact.ir;
  delete artifact.anf;
  delete artifact.asm;
  delete artifact.sourceMap;
  delete artifact.buildTimestamp;

  const input = { artifact, constructorArgs: spec.constructorArgs };
  const testDir = join(TESTS_DIR, spec.name);
  if (!existsSync(testDir)) mkdirSync(testDir, { recursive: true });
  writeFileSync(join(testDir, 'input.json'), JSON.stringify(input, null, 2) + '\n');
  console.log(`  Wrote ${spec.name}/input.json`);
}

console.log('\nDone. Run the TS SDK tool on each to generate expected-locking.hex.');
