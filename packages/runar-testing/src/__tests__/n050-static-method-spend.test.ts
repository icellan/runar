/**
 * N-050 (external StaticSiphon) — execution proof and seven-tier refusal.
 *
 *     public static requirePositive(amount: bigint) { assert(amount > 0n); }
 *     public withdraw(sig: Sig) { assert(checkSig(sig, this.owner)); }
 *
 * Pre-fix, the TS reference (and Go and Rust) compiled the static helper into
 * the ABI as a public entry point. Its locking script was BYTE-IDENTICAL to the
 * one compiled from the non-static spelling `public requirePositive(...)`
 * (remediation-logs/EXT-2/probes/staticsiphon.out), so the Vault could be spent
 * by anyone pushing `<1>` and the requirePositive selector — no signature.
 * The `.runar.java` `@Public static` spelling had the same effect in six tiers,
 * the `.runar.py` `@public @staticmethod` spelling in three, and a receiver-less
 * `pub fn` on `.runar.rs` / `.runar.zig` in all seven
 * (remediation-logs/N-050/probe/pre-fix.out).
 *
 * Oracle: the real `@bsv/sdk` Spend engine (`runStatelessSigned`). The spend
 * verdicts are derived BY HAND from the source above, never from compiler
 * output.
 *
 * What this proves:
 *   1. The script that the static spelling compiled to pre-fix — reproduced
 *      here from its byte-identical non-static twin — is an UNSIGNED spend
 *      path: `requirePositive(1)` with no signature is ACCEPTED by Spend, so
 *      the refusal below is what stands between the author and a drained
 *      Vault. `requirePositive(0)` is rejected by the same engine (the guard
 *      ran; the acceptance is not vacuous).
 *   2. Every tier's CLI refuses every static spelling in
 *      conformance/negatives/N104-N111 with the one shared diagnostic
 *      `static methods are not allowed in Rúnar contracts; method '<m>' is
 *      declared static` — not merely a non-zero exit (the rejection-parity
 *      gate checks that) but the same text, so no tier refuses by accident.
 * What it does NOT prove: that the pre-fix static artifact itself is still
 * producible (it is not — that is the fix); byte identity of the twin with the
 * pre-fix static artifact is the recorded triage measurement, not re-measured
 * here. It proves nothing about `.sol` / `.move`, which cannot spell a static
 * method (see packages/runar-compiler/src/__tests__/n050-static-methods.test.ts).
 */

import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { compile } from 'runar-compiler';
import { runStatelessSigned, testKey } from '../oracle/real-crypto-execution.js';

const REPO = join(__dirname, '..', '..', '..', '..');
const NEG = join(REPO, 'conformance', 'negatives');

const TWIN = `import { SmartContract, Sig, PubKey, assert, checkSig } from 'runar-lang';

export class Vault extends SmartContract {
  readonly owner: PubKey;

  constructor(owner: PubKey) {
    super(owner);
    this.owner = owner;
  }

  public requirePositive(amount: bigint) {
    assert(amount > 0n);
  }

  public withdraw(sig: Sig) {
    assert(checkSig(sig, this.owner));
  }
}
`;

const MSG = (m: string) =>
  `static methods are not allowed in Rúnar contracts; method '${m}' is declared static`;

/** Fixture -> the method name as written in its source. */
const FIXTURES: [string, string][] = [
  ['N104-ts-public-static-method.runar.ts', 'requirePositive'],
  ['N105-ts-private-static-method.runar.ts', 'requirePositive'],
  ['N106-java-static-method.runar.java', 'requirePositive'],
  ['N107-py-staticmethod.runar.py', 'require_positive'],
  ['N108-py-classmethod.runar.py', 'require_positive'],
  ['N109-rb-singleton-method.runar.rb', 'require_positive'],
  ['N110-rs-pub-fn-without-self.runar.rs', 'require_positive'],
  ['N111-zig-pub-fn-without-self.runar.zig', 'requirePositive'],
];

function requireBin(p: string, how: string): string {
  if (!existsSync(p)) throw new Error(`missing compiler binary ${p} — build it with: ${how}`);
  return p;
}

function javaJar(): string {
  const libs = join(REPO, 'compilers', 'java', 'build', 'libs');
  const jar = existsSync(libs) ? readdirSync(libs).find((f) => f.endsWith('.jar')) : undefined;
  if (!jar) throw new Error('Java jar missing — run `gradle jar` in compilers/java');
  return join(libs, jar);
}

/** Every refusal diagnostic a tier emits for `file`, or throws if it ACCEPTED. */
function refusal(cmd: string, args: string[], cwd?: string): string {
  const r = spawnSync(cmd, args, { cwd, encoding: 'utf8', timeout: 120_000 });
  if (r.error) throw new Error(`${cmd} failed to start: ${r.error.message}`);
  if (r.status === 0) throw new Error(`${cmd} ${args.join(' ')} ACCEPTED a static method`);
  return `${r.stderr}\n${r.stdout}`;
}

const TIERS: { name: string; diagnostics: (file: string) => string }[] = [
  {
    name: 'ts',
    diagnostics: (file) => {
      const r = compile(readFileSync(file, 'utf8'), { fileName: file });
      if (r.success) throw new Error(`ts ACCEPTED ${file}`);
      return r.diagnostics.map((d) => d.message).join('\n');
    },
  },
  {
    name: 'go',
    diagnostics: (file) => refusal(
      requireBin(join(REPO, 'compilers', 'go', 'runar-go'), 'cd compilers/go && go build -o runar-go .'),
      ['--source', file, '--hex'],
    ),
  },
  {
    name: 'rust',
    diagnostics: (file) => refusal(
      requireBin(join(REPO, 'compilers', 'rust', 'target', 'release', 'runar-compiler-rust'), 'cd compilers/rust && cargo build --release'),
      ['--source', file, '--hex'],
    ),
  },
  {
    name: 'python',
    diagnostics: (file) => refusal('python3', ['-m', 'runar_compiler', '--source', file, '--hex'], join(REPO, 'compilers', 'python')),
  },
  {
    name: 'zig',
    diagnostics: (file) => refusal(
      requireBin(join(REPO, 'compilers', 'zig', 'zig-out', 'bin', 'runar-zig'), 'cd compilers/zig && zig build'),
      ['compile', file, '--hex'],
    ),
  },
  {
    name: 'ruby',
    diagnostics: (file) => refusal('ruby', [
      '-I', join(REPO, 'compilers', 'ruby', 'lib'),
      join(REPO, 'compilers', 'ruby', 'bin', 'runar-compiler-ruby'),
      '--source', file, '--hex',
    ]),
  },
  {
    name: 'java',
    diagnostics: (file) => refusal('java', ['-jar', javaJar(), '--source', file, '--hex']),
  },
];

describe('N-050 — the pre-fix static entry point was an unsigned spend path (Spend.validate)', () => {
  const owner = testKey('alice').pubKey;

  it('ATTACK requirePositive(1) with NO signature is ACCEPTED by the twin script', () => {
    const r = runStatelessSigned({
      source: TWIN,
      fileName: 'Vault.runar.ts',
      method: 'requirePositive',
      args: [1n],
      constructorArgs: { owner },
      checkInterpreter: false,
    });
    expect(r.vmAccepted, r.vmError).toBe(true);
  });

  it('control: requirePositive(0) is REJECTED by the same engine (the guard ran)', () => {
    const r = runStatelessSigned({
      source: TWIN,
      fileName: 'Vault.runar.ts',
      method: 'requirePositive',
      args: [0n],
      constructorArgs: { owner },
      checkInterpreter: false,
    });
    expect(r.vmAccepted).toBe(false);
  });
});

for (const tier of TIERS) {
  describe(`N-050 [${tier.name}] refuses every static spelling with the shared diagnostic`, () => {
    for (const [fixture, name] of FIXTURES) {
      it(fixture, () => {
        expect(tier.diagnostics(join(NEG, fixture))).toContain(MSG(name));
      });
    }
  });
}
