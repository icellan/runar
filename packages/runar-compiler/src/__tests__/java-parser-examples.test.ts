/**
 * Java surface: every example contract must survive the reference frontend.
 *
 * `examples/rust` and `examples/zig` have had a sweep like this for a while;
 * `examples/java` did not, and the cost of that was concrete. Two contracts —
 * `TicTacToe.v2.runar.java` and `Grid2x2.v2.runar.java` — declared a
 * `FixedArray` property, which no tier can parse on the Java surface (an
 * integer literal in a Java type-argument list is a javac *syntax* error, so
 * `FixedArray<T, N>` has no spelling the toolchain accepts). Both files were
 * rejected by all seven compilers from the day they landed, and the Java
 * example suite stayed green throughout, because its JUnit tests exercise the
 * contract classes as ordinary Java objects and only five of fifty-five call
 * `CompileCheck`.
 *
 * A `.runar.java` file that no compiler accepts is not an example — it is
 * documentation of a feature that does not exist. This sweep is what makes
 * that state fail.
 *
 * Scope: parse -> validate -> typecheck, the same frontend `CompileCheck`
 * runs. Codegen parity for the Java surface is the conformance suite's job.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { readdirSync, readFileSync, existsSync, statSync } from 'fs';
import { join } from 'path';
import { parse } from '../passes/01-parse.js';
import { validate } from '../passes/02-validate.js';
import { typecheck } from '../passes/03-typecheck.js';

// Every test here must assert: an empty corpus would otherwise generate zero
// cases and report green.
beforeEach(() => {
  expect.hasAssertions();
});

const EXAMPLES_DIR = join(__dirname, '..', '..', '..', '..', 'examples', 'java');

/** Recursive walk — Java sources nest under src/main/java/runar/examples/<dir>/. */
function findJavaExamples(dir: string): { name: string; path: string }[] {
  const out: { name: string; path: string }[] = [];
  for (const entry of readdirSync(dir)) {
    const p = join(dir, entry);
    if (statSync(p).isDirectory()) {
      out.push(...findJavaExamples(p));
    } else if (entry.endsWith('.runar.java')) {
      out.push({ name: entry, path: p });
    }
  }
  return out;
}

const JAVA_EXAMPLES = existsSync(EXAMPLES_DIR) ? findJavaExamples(EXAMPLES_DIR).sort((a, b) => a.path.localeCompare(b.path)) : [];

function errorText(errors: { message: string; loc?: { line: number } }[]): string {
  return errors.map((e) => `  line ${e.loc?.line ?? '?'}: ${e.message}`).join('\n');
}

describe('Java surface: example contracts', () => {
  it('discovers the examples/java corpus', () => {
    expect(existsSync(EXAMPLES_DIR), `examples dir missing: ${EXAMPLES_DIR}`).toBe(true);
    expect(JAVA_EXAMPLES.length).toBeGreaterThan(0);
  });

  for (const { name, path } of JAVA_EXAMPLES) {
    it(`${name} passes parse + validate + typecheck`, () => {
      const source = readFileSync(path, 'utf-8');

      const parsed = parse(source, name);
      const parseErrors = parsed.errors.filter((e) => e.severity === 'error');
      expect(
        parseErrors,
        `${path} does not parse on the Java surface:\n${errorText(parseErrors)}`,
      ).toEqual([]);
      expect(parsed.contract, `${path} parsed to no contract`).not.toBeNull();

      const validateErrors = validate(parsed.contract!).errors.filter((e) => e.severity === 'error');
      expect(
        validateErrors,
        `${path} fails validation:\n${errorText(validateErrors)}`,
      ).toEqual([]);

      const typeErrors = typecheck(parsed.contract!).errors.filter((e) => e.severity === 'error');
      expect(
        typeErrors,
        `${path} fails typecheck:\n${errorText(typeErrors)}`,
      ).toEqual([]);
    });
  }
});
