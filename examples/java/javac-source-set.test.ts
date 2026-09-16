import { describe, it, expect } from 'vitest';
import { readFileSync, existsSync } from 'node:fs';
import { join, resolve, normalize, dirname } from 'node:path';

/**
 * RATCHET — the javac exclusion list for `examples/java` is EMPTY.
 *
 * Every `.runar.java` example is compiled by gradle against the runar-java SDK;
 * that is the point of wiring the extension into the `main` source set. There
 * used to be exactly one exclusion, `byte-builtins`, for exactly one reason:
 *
 *   `split` was specified as returning a PAIR, and the language had no way to
 *   name the left element. `runar.lang.Builtins.split` modelled the pair
 *   honestly as `ByteString[]`; the frontend's typechecker returned a single
 *   `ByteString`; no surface parser accepts array destructuring. javac believed
 *   the SDK and rejected `ByteString tail = split(data, idx);`.
 *
 * That was one defect with three symptoms: the compiler also ORPHANED the left
 * half (a `push(null)` stack slot nothing ever dropped, which desynced the model
 * and aborted the compile for any read after a split), and `substr` escaped only
 * because it NIPs its half away. `split` is now single-valued in the language,
 * in all seven compilers and in the Java SDK, and it lowers to
 * `OP_SPLIT OP_NIP` — so the file compiles and the exclusion is gone.
 *
 * WHY A RATCHET AND NOT A COMMENT. An exclusion list with nothing watching it is
 * a guard that never runs — the exact pattern this branch keeps rediscovering. A
 * `length <= N` check is the same failure one step later: a bound that only has
 * to be "not worse" stops being read. So this asserts the SET with `toEqual`.
 * Any exclusion fails here and has to justify itself in the same commit, the way
 * `STALE_PIN_BUDGET === 0` forces a justification for a stale pin.
 *
 * NON-VACUITY. An empty expectation is exactly the shape that can pass by
 * matching nothing, so the second test below feeds the parser a `sourceSets`
 * block that DOES carry exclusions and requires it to find them. The third keeps
 * the contract that used to be excluded in the javac source set, still calling
 * `split`, so this file notices if it is quietly dropped instead of compiled.
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
function parseJavacExclusions(text: string): string[] {
  const start = text.indexOf('sourceSets {');
  expect(start, 'no sourceSets block to scan').toBeGreaterThanOrEqual(0);

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

function javacExclusions(): string[] {
  return parseJavacExclusions(readFileSync(BUILD_FILE, 'utf8'));
}

describe('examples/java javac source set', () => {
  it('excludes NOTHING — every .runar.java example is compiled by javac', () => {
    expect(
      javacExclusions(),
      'The javac exclusion list for examples/java is no longer empty. Every ' +
        '.runar.java example is meant to compile against the runar-java SDK. The ' +
        'one exclusion this list ever carried, byte-builtins, existed because ' +
        "Runar's `split` returned one ByteString while `runar.lang.Builtins.split` " +
        'returned a ByteString[] pair; that disagreement is resolved. A new ' +
        'exclusion needs its own reason in the same commit — silently growing ' +
        'this list is how a compile gate stops gating.',
    ).toEqual([]);
  });

  it('the parser finds exclusions when they are there (non-vacuity)', () => {
    // An empty expectation passes on a parser that returns [] for everything —
    // a broken regex, the wrong block, a renamed source set. Feed it a block
    // that carries exclusions, including the one that used to be real, and
    // require them back. Also checks the two things the scan is scoped for: a
    // commented-out exclude is not an exclusion, and an `exclude` outside the
    // sourceSets block is not one either.
    const fixture = `
plugins { java }
configurations.all { exclude("outside-the-block") }
sourceSets {
    main {
        java {
            include("**/*.runar.java")
            // exclude("**/commented-out/**")
            exclude("**/byte-builtins/**")
            exclude("**/second/**")
        }
    }
}
dependencies { implementation("x:y:1") { exclude("also-outside") } }
`;
    expect(parseJavacExclusions(fixture)).toEqual(['**/byte-builtins/**', '**/second/**']);
  });

  it('byte-builtins is in the javac source set, still calling split', () => {
    // The file that used to be excluded has to still be there and still exercise
    // the builtin whose signature blocked it — otherwise "the exclusion is gone"
    // would be satisfied by deleting the contract instead of fixing `split`.
    const contract = join(
      HERE,
      'src/main/java/runar/examples/byte-builtins/ByteBuiltins.runar.java',
    );
    expect(existsSync(contract), `${contract} is gone`).toBe(true);
    const source = readFileSync(contract, 'utf8');
    expect(
      source,
      'byte-builtins no longer calls split(), so it no longer proves the ' +
        'SDK signature and the language agree',
    ).toContain('split(data, idx)');
    expect(
      source,
      'byte-builtins no longer binds split() to a single ByteString, which is ' +
        'the exact assignment javac used to reject',
    ).toContain('ByteString tail = split(data, idx);');
  });

  it('conformance reads the same file for the .runar.java surface', () => {
    // The nine-surface frontend-parity invariant runs through conformance's
    // source.json + --parser-only matrix, not through gradle. Both paths must
    // point at one file, or the javac compile and the cross-tier compile stop
    // being about the same contract.
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
