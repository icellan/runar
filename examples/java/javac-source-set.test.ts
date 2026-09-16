import { describe, it, expect } from 'vitest';
import { readFileSync, existsSync } from 'node:fs';
import { join, resolve, normalize, dirname } from 'node:path';

/**
 * RATCHET — the javac exclusion list for `examples/java` is EXACTLY one entry.
 *
 * Every `.runar.java` example is compiled by gradle against the runar-java SDK;
 * that is the point of wiring the extension into the `main` source set. Exactly
 * one file is excluded, `byte-builtins`, and it is excluded for one reason:
 *
 *   Rúnar's `split` returns the RIGHT half as a single `ByteString` — no
 *   surface parser accepts array destructuring, so the left half is unnameable
 *   and the typechecker's own signature returns one value — while
 *   `runar.lang.Builtins.split` models it honestly as a `ByteString[]` pair.
 *   Everything else in that file is valid Java.
 *
 * That mismatch is one defect with three symptoms, not three defects: the
 * compiler orphans the left half, the Java SDK's signature disagrees with the
 * language, and the stack model carries a `push(null)` for a value nothing ever
 * drops. `substr` escapes only because it NIPs its left half. Whoever decides
 * what `split` actually returns resolves all three, and deleting the exclusion
 * below is how this file finds out.
 *
 * WHY A RATCHET AND NOT A COMMENT. An exclusion list with nothing watching it is
 * a guard that never runs — the exact pattern this branch keeps rediscovering. A
 * `length <= N` check is the same failure one step later: a bound that only has
 * to be "not worse" stops being read. So this asserts the SET with `toEqual`. A
 * second exclusion fails here and someone has to justify it in the same commit,
 * the way `STALE_PIN_BUDGET === 0` forces a justification for a stale pin.
 *
 * NON-VACUITY. The parse below is checked against the real file, and the
 * `byte-builtins` entry is checked to still name a real, still-excluded source
 * — so this cannot pass by matching nothing, and it cannot pass after the
 * exclusion is removed but its entry left behind.
 */

const HERE = dirname(new URL(import.meta.url).pathname);
const REPO = resolve(HERE, '../..');
const BUILD_FILE = join(HERE, 'build.gradle.kts');

/**
 * Every `exclude("…")` inside the `sourceSets { main { java { … } } }` block.
 *
 * Scoped to that block on purpose: `dependencyLocking` and the dependency
 * declarations further down may grow `exclude` calls of their own, and those
 * have nothing to do with which contracts javac sees.
 */
function javacExclusions(): string[] {
  const text = readFileSync(BUILD_FILE, 'utf8');
  const start = text.indexOf('sourceSets {');
  expect(start, `no sourceSets block in ${BUILD_FILE}`).toBeGreaterThanOrEqual(0);

  // Walk braces from `sourceSets {` to its matching close, so the scan cannot
  // run past the block and pick up an unrelated `exclude`.
  let depth = 0;
  let end = -1;
  for (let i = text.indexOf('{', start); i < text.length; i++) {
    if (text[i] === '{') depth++;
    else if (text[i] === '}') {
      depth--;
      if (depth === 0) {
        end = i;
        break;
      }
    }
  }
  expect(end, 'unbalanced braces in the sourceSets block').toBeGreaterThan(start);

  const block = text.slice(start, end);
  return [...block.matchAll(/(?<!\/\/[^\n]*)\bexclude\("([^"]+)"\)/g)].map((m) => m[1]!);
}

describe('examples/java javac source set', () => {
  it('excludes EXACTLY the one contract the Builtins.split signature blocks', () => {
    expect(
      javacExclusions(),
      'The javac exclusion list for examples/java changed. Every .runar.java ' +
        'example is meant to compile against the runar-java SDK; byte-builtins ' +
        'is the single exception, because Rúnar\'s `split` returns one ByteString ' +
        'and `runar.lang.Builtins.split` returns a ByteString[] pair. A second ' +
        'exclusion needs its own reason in the same commit — silently growing ' +
        'this list is how a compile gate stops gating.',
    ).toEqual(['**/byte-builtins/**']);
  });

  it('the excluded contract still exists and is still what the reason describes', () => {
    // Without this the assertion above survives the exclusion outliving its
    // cause: the file deleted, or `split` fixed and the entry left behind.
    const contract = join(
      HERE,
      'src/main/java/runar/examples/byte-builtins/ByteBuiltins.runar.java',
    );
    expect(existsSync(contract), `${contract} is gone — drop the exclusion`).toBe(true);
    expect(
      readFileSync(contract, 'utf8'),
      'the excluded contract no longer calls split(), so the exclusion has ' +
        'outlived its reason — remove it and let javac compile the file',
    ).toContain('split(data, idx)');
  });

  it('the exclusion is javac-only: conformance still reads the file for the .runar.java surface', () => {
    // The nine-surface frontend-parity invariant runs through conformance's
    // source.json + --parser-only matrix, not through gradle. If a future
    // exclusion ever reached the fixture's source-resolution path, the coverage
    // claim in build.gradle.kts and in the contract's javadoc would be false.
    const cfg = JSON.parse(
      readFileSync(join(REPO, 'conformance/tests/byte-builtins/source.json'), 'utf8'),
    ) as { sources: Record<string, string> };
    const rel = cfg.sources['.runar.java'];
    expect(rel, 'byte-builtins declares no .runar.java source').toBeTruthy();
    const resolved = normalize(join(REPO, 'conformance/tests/byte-builtins', rel!));
    expect(existsSync(resolved), `${resolved} does not exist`).toBe(true);
    expect(resolved).toContain(join('examples', 'java'));
  });
});
