/**
 * N-247 (user decision R107): the issue-#109 readonly-field DCE warning
 * claimed elimination as settled fact ("...was eliminated by DCE...") even
 * though the "referenced" probe it is gated on is a PREDICTION about what
 * the real (EC-optimizer-gated) pipeline will drop, not an observation of
 * what it actually did. Repro: remediation-logs/N-200/DeadChain.runar.ts
 * warns "field 'b' ... was eliminated by DCE" while the compiled artifact's
 * `constructorSlots` still carries a slot for 'b'. User decision R107:
 * reword only (no detection-logic change), to the hedged "may be eliminated
 * by DCE", byte-identical text in all 7 tiers.
 *
 * This test proves two things:
 *   1. The TS reference's message text no longer overclaims (it hedges with
 *      "may be eliminated", not "was eliminated").
 *   2. For a readonly field that every tier's own "is this prop referenced"
 *      detection agrees is dead (never mentioned anywhere in the method
 *      body, not even in a dead local the way N-200/DeadChain's `b` is), so
 *      a text mismatch below cannot be masked by a per-tier detection
 *      disagreement, every peer-tier CLI that is BUILT in the current
 *      environment emits the byte-identical message body as the TS
 *      reference.
 *
 * It does NOT prove: that all 7 tiers agree on WHICH fields count as
 * "referenced" for a trickier case like DeadChain's dead local read (that
 * is N-200/R-162/R-237 territory); that the probe's prediction matches the
 * real pipeline's actual DCE decision (R107 explicitly deferred that fix);
 * or anything about a tier whose binary is not built in this run — such a
 * tier is simply left out of the peer loop below. That omission does not
 * use the vitest conditional-skip helpers, so it carries no
 * docs/test-skips.md obligation: this test always executes and always
 * asserts on the in-process TS reference regardless of which peer binaries
 * exist, and logs which peers it actually checked so a run with zero peer
 * binaries built is visible in the test output rather than quietly passing
 * having verified only TS.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import { execFileSync, spawnSync } from 'child_process';
import { mkdtempSync, rmSync, writeFileSync, existsSync, readdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { tmpdir } from 'os';
import { compile } from '../index.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = join(__dirname, '..', '..', '..', '..');

beforeEach(() => {
  expect.hasAssertions();
});

// A readonly field with no initializer that NO method mentions anywhere —
// every tier's own DCE-reference probe agrees it is dead, so none of the
// per-tier detection divergence this item deliberately does not fix can
// hide behind a mismatch in the assertions below.
const META_SOURCE = `import { SmartContract, assert, Addr, PubKey, Sig, ByteString, hash160, checkSig } from 'runar-lang';

class Meta extends SmartContract {
  readonly pubKeyHash: Addr;
  readonly metadataId: ByteString;

  constructor(pubKeyHash: Addr, metadataId: ByteString) {
    super(pubKeyHash, metadataId);
    this.pubKeyHash = pubKeyHash;
    this.metadataId = metadataId;
  }

  public unlock(sig: Sig, pubKey: PubKey) {
    assert(hash160(pubKey) === this.pubKeyHash);
    assert(checkSig(sig, pubKey));
  }
}
`;

// Matches the warning body under EITHER the pre-fix ("was") or post-fix
// ("may be") wording, so the same regex extracts the comparable text no
// matter which side of the fix a given tier's binary is on.
const MESSAGE_RE =
  /readonly field 'metadataId' is not referenced in any method body and (?:was|may be) eliminated by DCE; annotate it \/\*\* @embedAlways \*\/ to preserve it in the on-chain script/;

function extract(text: string): string | null {
  const m = MESSAGE_RE.exec(text);
  return m ? m[0] : null;
}

// `execFileSync`'s return value is stdout ONLY on a zero exit — stderr (where
// every tier prints this warning) is discarded on the success path, not just
// swallowed on error. A warning-only compile exits 0, so `execFileSync` would
// silently drop the very text this test exists to check. `spawnSync` captures
// both streams regardless of exit code.
function tryRun(cmd: string, args: string[], cwd?: string): string {
  const r = spawnSync(cmd, args, { cwd, encoding: 'utf8', timeout: 60_000 });
  return `${r.stdout ?? ''}${r.stderr ?? ''}`;
}

function findJavaJar(): string | null {
  const libsDir = join(REPO_ROOT, 'compilers', 'java', 'build', 'libs');
  if (!existsSync(libsDir)) return null;
  for (const entry of readdirSync(libsDir)) {
    if (entry.startsWith('runar-java-compiler-') && entry.endsWith('.jar')) return join(libsDir, entry);
  }
  return null;
}

describe('N-247: readonly-field DCE warning wording', () => {
  it('TS reference hedges ("may be eliminated"), and every built peer-tier CLI matches its exact text', () => {
    const tmp = mkdtempSync(join(tmpdir(), 'n247-dce-wording-'));
    const sourcePath = join(tmp, 'Meta.runar.ts');
    writeFileSync(sourcePath, META_SOURCE);

    try {
      // 1. TS reference (in-process, always available).
      const tsResult = compile(META_SOURCE, { fileName: 'Meta.runar.ts' });
      const tsWarning = tsResult.diagnostics.find(
        (d) => d.severity === 'warning' && d.message.includes("readonly field 'metadataId'"),
      );
      expect(tsWarning, JSON.stringify(tsResult.diagnostics)).toBeDefined();
      const tsMessage = extract(tsWarning!.message);
      expect(tsMessage, tsWarning!.message).not.toBeNull();
      expect(tsMessage).toContain('may be eliminated by DCE');
      expect(tsMessage).not.toContain('was eliminated by DCE');

      // 2. Every peer-tier CLI that is BUILT in this environment must emit
      // the byte-identical message body. A tier whose binary/runtime is not
      // available is simply left out of this loop.
      const peers: { name: string; output: string }[] = [];

      const goBin = join(REPO_ROOT, 'compilers', 'go', 'runar-go');
      if (existsSync(goBin)) {
        peers.push({ name: 'go', output: tryRun(goBin, ['-source', sourcePath, '-output', '/dev/null']) });
      }

      const rustBin = join(REPO_ROOT, 'compilers', 'rust', 'target', 'release', 'runar-compiler-rust');
      if (existsSync(rustBin)) {
        peers.push({ name: 'rust', output: tryRun(rustBin, ['--source', sourcePath, '-o', '/dev/null']) });
      }

      try {
        execFileSync('python3', ['-c', 'import runar_compiler'], {
          cwd: join(REPO_ROOT, 'compilers', 'python'),
          stdio: 'pipe',
        });
        peers.push({
          name: 'python',
          output: tryRun(
            'python3',
            ['-m', 'runar_compiler', '--source', sourcePath, '--output', '/dev/null'],
            join(REPO_ROOT, 'compilers', 'python'),
          ),
        });
      } catch {
        // python3 or the runar_compiler package not available locally.
      }

      const zigBin = join(REPO_ROOT, 'compilers', 'zig', 'zig-out', 'bin', 'runar-zig');
      if (existsSync(zigBin)) {
        peers.push({ name: 'zig', output: tryRun(zigBin, ['compile', sourcePath]) });
      }

      const rubyScript = join(REPO_ROOT, 'compilers', 'ruby', 'bin', 'runar-compiler-ruby');
      if (existsSync(rubyScript)) {
        try {
          execFileSync('ruby', ['--version'], { stdio: 'pipe' });
          peers.push({
            name: 'ruby',
            output: tryRun('ruby', [rubyScript, '--source', sourcePath, '--output', '/dev/null']),
          });
        } catch {
          // ruby not installed.
        }
      }

      const javaJar = findJavaJar();
      if (javaJar) {
        try {
          execFileSync('java', ['-version'], { stdio: 'pipe' });
          peers.push({ name: 'java', output: tryRun('java', ['-jar', javaJar, '--source', sourcePath, '--hex']) });
        } catch {
          // java runtime not installed.
        }
      }

      const seen: string[] = [];
      for (const peer of peers) {
        const msg = extract(peer.output);
        expect(msg, `${peer.name} produced no matching DCE warning:\n${peer.output}`).not.toBeNull();
        expect(msg, `${peer.name} wording diverges from TS`).toBe(tsMessage);
        seen.push(peer.name);
      }

      // Visibility, not an assertion: a run with zero peer binaries built
      // still passed (on the TS assertions above), but should look that
      // way in the log, not like a verified 7-tier run.
      // eslint-disable-next-line no-console
      console.log(`N-247 wording parity checked against peers: ${seen.join(', ') || '(none built)'}`);
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });
});
