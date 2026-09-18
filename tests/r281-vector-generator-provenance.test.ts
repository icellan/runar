/**
 * R-281 (CL-GAP-068): `tests/generate-vectors/generate_koalabear_vectors.go`
 * was orphaned dead code that claimed to be the source of truth.
 *
 * Its header said:
 *
 *   CANONICAL vector generator for KoalaBear field arithmetic test vectors.
 *   ... Regenerate vectors with this Go program — the Rust generator is for
 *   independent verification only.
 *
 * The reverse is true. CI runs `verify-reproducible.sh`, whose RUST_BINS list
 * contains `generate_koalabear_vectors` — the Rust generator, built on Plonky3's
 * `p3-koala-bear`, the same library SP1 uses. The Go file used self-rolled field
 * math with no upstream reference and was invoked by nothing.
 *
 * A file that claims to be the source of truth and is not is worse than no
 * file: following its instructions would have replaced Plonky3-derived vectors
 * with self-rolled ones, and the KoalaBear vectors ARE the entire oracle for a
 * Go-only primitive — there is no cross-tier parity to catch it.
 *
 * The file is deleted. This test keeps the property that made it dangerous from
 * coming back: every generator in tests/generate-vectors must be reachable from
 * the script CI runs.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, existsSync, statSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const GEN_DIR = join(ROOT, 'tests', 'generate-vectors');

describe('R-281: every vector generator is reachable from the CI script', () => {
  it('has no orphaned Go generator sitting beside the Rust ones', () => {
    const script = readFileSync(join(GEN_DIR, 'verify-reproducible.sh'), 'utf8');

    // The script invokes its Rust generators by BINARY NAME (the RUST_BINS
    // list) and its Go generator by DIRECTORY (`cd "$GEN_DIR/bn254" && go run .`).
    // So a matching name proves nothing about a .go file — the deleted orphan
    // was named `generate_koalabear_vectors.go` while the script's
    // `generate_koalabear_vectors` is the Rust binary built from
    // src/generate_koalabear_vectors.rs. That near-collision is exactly how a
    // self-rolled generator passed as canonical.
    //
    // The check that holds: a Go generator must live in a subdirectory the
    // script `go run`s. A .go file loose in tests/generate-vectors/ is invoked
    // by nothing.
    const looseGo = readdirSync(GEN_DIR).filter(
      (e) => statSync(join(GEN_DIR, e)).isFile() && e.endsWith('.go'),
    );

    expect(
      looseGo,
      'a .go generator directly in tests/generate-vectors/ is run by nothing — ' +
        'verify-reproducible.sh invokes Go generators by directory (go run .) and ' +
        'Rust generators by binary name. A generator nothing runs cannot be the ' +
        'source of truth for the vectors it claims to produce',
    ).toEqual([]);

    // And the Go generator that IS real must still be reachable.
    expect(script).toMatch(/cd "\$GEN_DIR\/bn254" && GOWORK=off go run \./);
  });

  it('still finds the Rust generators, so the scan is not vacuous', () => {
    const script = readFileSync(join(GEN_DIR, 'verify-reproducible.sh'), 'utf8');
    const rustGenerators = readdirSync(join(GEN_DIR, 'src')).filter(
      (e) => e.startsWith('generate_') && e.endsWith('.rs'),
    );
    expect(rustGenerators.length).toBeGreaterThan(0);
    for (const g of rustGenerators) {
      expect(script, `${g} is not named in verify-reproducible.sh`).toContain(
        g.replace(/\.rs$/, ''),
      );
    }
  });
});
