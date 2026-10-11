/**
 * R-213 (CL-GAP-053) — which secp256k1 implementation each tier actually uses.
 *
 * The finding: "Python, Ruby and Zig hand-roll EC math with ZERO
 * crypto-library dependency while TS, Go, Rust and Java use maintained
 * libraries — a direct cross-tier asymmetry in the most security-critical code
 * in the repo. Python's declared `coincurve` extra is dead: never imported."
 *
 * Measured, the picture is narrower than that and wrong in one place:
 *
 *   TS      @bsv/sdk                      required   package.json
 *   Go      bsv-blockchain/go-sdk         required   go.mod
 *   Rust    k256                          required   Cargo.toml
 *   Java    bouncycastle bcprov-jdk18on   required   build.gradle.kts
 *   Zig     bsvz (pinned commit)          required   build.zig.zon
 *   Python  bsv-sdk when importable, bundled pure-Python otherwise
 *   Ruby    bundled pure-Ruby (the bsv-sdk branch cannot be taken — see below)
 *
 * Zig is NOT hand-rolled: `builtins.zig` routes ecMul / ecMulGen through
 * `bsvz.crypto.Point`, and the envelope signer uses the Zig standard
 * library's `Secp256k1` / `EcdsaSecp256k1Sha256`. That is a declared,
 * version-pinned dependency like the other four.
 *
 * N-111 (commit 86a7e4aa) deliberately moved `ecAdd` / `ecNegate` /
 * `ecEncodeCompressed` OFF `bsvz.crypto.Point` and onto a direct affine-law
 * implementation against `std.crypto.ecc.Secp256k1.Fe` (Zig's own
 * standard-library secp256k1 field element). The reason is not a
 * regression: `bsvz`'s point decoder refuses off-curve operands and the
 * all-zero identity O, while the compiled script's ecAdd/ecNegate accept
 * both (R-053/R-117), so the on-chain gate and the off-chain one disagreed.
 * `Fe` is still a maintained library type doing the field arithmetic (mod
 * p add/sub/mul/invert) — the affine curve LAW (which coordinates to
 * combine, and when) is written here because no library offers one that
 * matches the script's off-curve/identity handling, not because the field
 * math itself was hand-rolled.
 *
 * The real asymmetry is Python and Ruby, and it is "optional library with a
 * hand-rolled fallback", not "zero dependency". Ruby's is the sharper case:
 * `local_signer.rb` prefers `require 'bsv-sdk'`, no such gem is declared in
 * the gemspec or Gemfile, and CLAUDE.md records that no `bsv-blockchain` Ruby
 * SDK exists at all — so that branch cannot be taken and the pure-Ruby ECDSA
 * is the only implementation that ever runs.
 *
 * The `coincurve` half of the finding is exactly right and is the one thing
 * here that was a live defect: `pyproject.toml` declared
 * `crypto = ["coincurve>=20.0"]` and the README sold it as an "Optional
 * secp256k1 backend", while nothing in the package imports coincurve. The
 * backend `LocalSigner` actually consults is `bsv-sdk`, so
 * `pip install runar[crypto]` installed a package that changed nothing.
 *
 * This file pins the table above to the manifests so the claim cannot drift,
 * and pins that every declared Python extra names something the package uses.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync, existsSync } from 'node:fs';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const read = (rel: string) => readFileSync(join(repoRoot, rel), 'utf8');

interface Backend {
  tier: string;
  manifest: string;
  /** Substring that must appear in the manifest, naming the crypto library. */
  declares: string;
}

const REQUIRED_BACKENDS: Backend[] = [
  { tier: 'ts', manifest: 'packages/runar-sdk/package.json', declares: '@bsv/sdk' },
  { tier: 'go', manifest: 'packages/runar-go/go.mod', declares: 'bsv-blockchain/go-sdk' },
  { tier: 'rust', manifest: 'packages/runar-rs/Cargo.toml', declares: 'k256' },
  { tier: 'java', manifest: 'packages/runar-java/build.gradle.kts', declares: 'bcprov-jdk18on' },
  { tier: 'zig', manifest: 'packages/runar-zig/build.zig.zon', declares: 'bsvz' },
];

describe('R-213: every tier with a required crypto library still declares it', () => {
  it.each(REQUIRED_BACKENDS.map(b => [b.tier, b] as const))(
    '%s declares its secp256k1 backend',
    (_tier, backend) => {
      expect(existsSync(join(repoRoot, backend.manifest)),
        `${backend.manifest} is missing`).toBe(true);
      expect(read(backend.manifest)).toContain(backend.declares);
    },
  );

  it('Zig routes EC through the library rather than hand-rolled field arithmetic', () => {
    // The finding claims Zig hand-rolls this. It does not: correcting the
    // record is only durable if something checks it.
    //
    // Checking that the file merely MENTIONS bsvz is not enough — a type
    // annotation would satisfy it while the arithmetic moved elsewhere. The
    // point conversions are the chokepoint every EC builtin goes through, so
    // assert on their bodies.
    const builtins = read('packages/runar-zig/src/builtins.zig');

    const bodyOf = (signature: string): string => {
      const start = builtins.indexOf(signature);
      expect(start, `${signature} is missing — this guard is checking nothing`)
        .toBeGreaterThan(-1);
      let depth = 0;
      for (let i = builtins.indexOf('{', start); i < builtins.length; i++) {
        if (builtins[i] === '{') depth++;
        else if (builtins[i] === '}') { depth--; if (depth === 0) return builtins.slice(start, i + 1); }
      }
      throw new Error(`${signature} is not brace-balanced`);
    };

    // Both directions of the conversion must go through the library type.
    expect(bodyOf('fn parsePoint(')).toMatch(/bsvz\.crypto\.Point\.(identity|fromRaw64)/);
    expect(bodyOf('fn serializePoint(')).toMatch(/point\.toRaw64\(\)/);

    // A builtin that merely forwards to a sibling `*Checked` helper (N-111
    // split the abort-vs-panic behaviour out that way) is checked through
    // that helper's body, not its own one-line wrapper — otherwise the
    // assertion below would read nothing but a function call.
    const effectiveBodyOf = (signature: string): string => {
      const body = bodyOf(signature);
      const checkedCall = /\b(ec\w+Checked)\(/.exec(body);
      return checkedCall ? bodyOf(`pub fn ${checkedCall[1]}(`) : body;
    };

    // ecMul and ecMulGen still delegate to the parsed bsvz library point —
    // none of them do field arithmetic inline.
    for (const fn of ['pub fn ecMul(', 'pub fn ecMulGen(']) {
      const body = effectiveBodyOf(fn);
      expect(body, `${fn} does not delegate to a library point`)
        .toMatch(/parsePoint|Secp256k1|basePoint|\.mul\(|\.add\(/);
      expect(body, `${fn} looks like it computes a modular inverse itself`)
        .not.toMatch(/modInverse|invMod|powMod/);
    }

    // N-111 (commit 86a7e4aa): ecAdd / ecNegate must delegate to their
    // *Checked helper (parsePoint's gate is wrong for them — see the header
    // comment), and that helper's own field arithmetic must go through
    // `Secp256k1Fe` (std.crypto.ecc.Secp256k1.Fe) rather than a private
    // modular-inverse routine. This still fails if the field math is ever
    // hand-rolled: inlining a from-scratch modInverse/invMod/powMod into
    // ecAddChecked/ecNegateChecked, or dropping the Secp256k1Fe-typed
    // decode, turns this assertion red (verified while writing this test by
    // temporarily replacing `.invert()` with an inline extended-Euclid
    // `modInverse` call, which failed exactly these two checks).
    for (const [fn, checkedFn] of [
      ['pub fn ecAdd(', 'ecAddChecked'],
      ['pub fn ecNegate(', 'ecNegateChecked'],
    ] as const) {
      const body = bodyOf(fn);
      expect(body, `${fn} does not delegate to ${checkedFn}`).toContain(`${checkedFn}(`);

      const checkedBody = effectiveBodyOf(fn);
      expect(checkedBody, `${checkedFn} does not use the Secp256k1Fe library field type`)
        .toMatch(/Secp256k1Fe|ecDecodeCanonical|ecEncodeFe/);
      expect(checkedBody, `${checkedFn} looks like it computes a modular inverse itself`)
        .not.toMatch(/modInverse|invMod|powMod/);
    }

    // The helpers that actually touch field elements must use Secp256k1Fe's
    // own methods for every field op, not a hand-rolled equivalent.
    for (const fn of ['fn ecDecodeCanonical(', 'fn ecEncodeFe(']) {
      const body = bodyOf(fn);
      expect(body, `${fn} does not use Secp256k1Fe`).toMatch(/Secp256k1Fe/);
      expect(body, `${fn} looks like it computes a modular inverse itself`)
        .not.toMatch(/modInverse|invMod|powMod/);
    }
  });
});

describe('R-213: Python declares no optional dependency it does not use', () => {
  const pyproject = read('packages/runar-py/pyproject.toml');
  const pkgRoot = join(repoRoot, 'packages/runar-py/runar');

  /** Extras as `name -> [distribution, ...]`, from the TOML table. */
  function parseExtras(): Record<string, string[]> {
    const section = pyproject.slice(pyproject.indexOf('[project.optional-dependencies]'));
    const body = section.slice(0, section.indexOf('[build-system]'));
    const out: Record<string, string[]> = {};
    for (const line of body.split('\n')) {
      const m = /^([A-Za-z0-9_-]+)\s*=\s*\[(.*)\]/.exec(line.trim());
      if (!m) continue;
      out[m[1]!] = [...m[2]!.matchAll(/"([^">=<~!]+)/g)].map(x => x[1]!.trim());
    }
    return out;
  }

  /** Import names the package actually references, from its own sources. */
  function importedModules(): Set<string> {
    const found = new Set<string>();
    const walk = (dir: string): void => {
      for (const entry of require('node:fs').readdirSync(dir, { withFileTypes: true })) {
        const p = join(dir, entry.name);
        if (entry.isDirectory()) { walk(p); continue; }
        if (!entry.name.endsWith('.py')) continue;
        const src = readFileSync(p, 'utf8');
        for (const m of src.matchAll(/^\s*(?:from|import)\s+([A-Za-z0-9_]+)/gm)) {
          found.add(m[1]!);
        }
      }
    };
    walk(pkgRoot);
    return found;
  }

  /** Distribution name -> the module name it installs. */
  const DISTRIBUTION_MODULE: Record<string, string> = {
    'bsv-sdk': 'bsv',
    coincurve: 'coincurve',
    pytest: 'pytest',
  };

  const extras = parseExtras();
  const imported = importedModules();

  it('parsed the extras and the imports (anti-vacuity)', () => {
    expect(Object.keys(extras).length).toBeGreaterThanOrEqual(2);
    expect(imported.size).toBeGreaterThan(10);
  });

  it.each(Object.keys(extras).filter(name => name !== 'dev').map(n => [n] as const))(
    'the %s extra installs something the package imports',
    name => {
      // `dev` is excluded by design: pytest is a runner, not something the
      // library imports. Every OTHER extra is a promise to the user that
      // installing it changes runtime behaviour.
      const dists = extras[name]!;
      expect(dists.length, `extra '${name}' is empty`).toBeGreaterThan(0);
      const useless = dists.filter(d => {
        const mod = DISTRIBUTION_MODULE[d];
        expect(mod, `no module mapping for distribution '${d}' — extend DISTRIBUTION_MODULE`)
          .toBeDefined();
        return !imported.has(mod!);
      });
      expect(useless,
        `extra '${name}' installs ${useless.join(', ')}, which the package never imports — ` +
        `installing it changes nothing`).toEqual([]);
    },
  );
});

describe('R-213: the Ruby signer does not imply a backend it cannot reach', () => {
  it('records that the bsv-sdk gem is not a declared dependency', () => {
    // `local_signer.rb` opens with `require 'bsv-sdk'`. No such gem is declared
    // in the gemspec or the Gemfile, and CLAUDE.md states no bsv-blockchain
    // Ruby SDK exists — so the branch is unreachable and the pure-Ruby ECDSA is
    // the only implementation that runs. If that ever changes, this fails and
    // whoever changed it has to revisit the spec context gated on it.
    const gemspec = read('packages/runar-rb/runar.gemspec');
    const gemfile = read('packages/runar-rb/Gemfile');
    expect(gemspec).not.toMatch(/bsv-sdk/);
    expect(gemfile).not.toMatch(/bsv-sdk/);
  });

  it('says so where a reader of the signer would look', () => {
    const signer = read('packages/runar-rb/lib/runar/sdk/local_signer.rb');
    expect(signer).toMatch(/no such gem is published|not a declared dependency|cannot be taken/i);
  });
});
