/**
 * R-279 (CL-GAP-066): `codegen/templates/*.mustache` is read from disk by the
 * TypeScript SDK at runtime, while the Go, Rust and Python SDKs each embed an
 * independently-maintained copy.
 *
 * The finding says those copies are "byte-identical today, unenforced". Half of
 * that was true. Measured:
 *
 *     go      embedded 5425 bytes, disk 5425   identical
 *     rust    embedded 6549 bytes, disk 6549   identical
 *     python  embedded 5049 bytes, disk 5082   DRIFTED
 *
 * The Python copy had already diverged — it dropped the newline after
 * `{{#hasTerminalMethods}}` and spelled an em dash as `--`. Not cosmetic: the
 * two SDKs generated DIFFERENT Python wrappers for the same artifact, 3343
 * chars from the TS SDK against 3317 from the Python SDK, differing in blank
 * lines and in a docstring.
 *
 * Nothing caught it because nothing gates it. `conformance/sdk-codegen/` has
 * runners for Java, Ruby and Zig only — its README says the TS/Go/Rust/Python
 * runners "will be added in follow-up PRs" — and `packages/runar-py` has no
 * codegen test at all.
 *
 * The finding's other claim, that `wrapper.zig.mustache` has "zero references
 * anywhere — a dead file", is WRONG, and the last case says why: `gen-all.ts`
 * builds the filename by interpolating an extension, so a grep for the literal
 * name finds nothing while the loader reads it on every `generateZig` call.
 */

import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { generatePython, generateZig } from '../packages/runar-sdk/src/codegen/gen-all.js';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

const disk = (ext: string) =>
  readFileSync(join(ROOT, `codegen/templates/wrapper.${ext}.mustache`), 'utf-8');

/**
 * Pull an embedded copy out of a tier's source. The extraction asserting its
 * own success is the point: if someone moves the literal, this fails loudly
 * instead of quietly comparing nothing.
 */
function between(file: string, open: string, close: string): string {
  const text = readFileSync(join(ROOT, file), 'utf-8');
  const start = text.indexOf(open);
  expect(start, `${file}: could not find the embedded template (opened by ${open.trim()})`).toBeGreaterThanOrEqual(0);
  const from = start + open.length;
  const end = text.indexOf(close, from);
  expect(end, `${file}: embedded template is not closed by ${close.trim()}`).toBeGreaterThan(from);
  return text.slice(from, end);
}

describe('R-279: every embedded copy of a codegen template matches the file on disk', () => {
  it('go', () => {
    expect(between('packages/runar-go/sdk_codegen.go', 'const goWrapperTemplate = `', '`\n')).toBe(
      disk('go'),
    );
  });

  it('rust', () => {
    // The Rust raw string closes with `"#`, and the template's own trailing
    // newline sits inside it, so the slice is the whole file.
    expect(
      between('packages/runar-rs/src/sdk/codegen.rs', 'const RUST_TEMPLATE: &str = r#"', '"#'),
    ).toBe(disk('rs'));
  });

  it('python', () => {
    // Read the constant from the module rather than re-parsing the literal:
    // it is a parenthesised concatenation, and the value is what matters.
    const res = spawnSync(
      'python3',
      [
        '-c',
        'import sys; sys.path.insert(0, "."); from runar.sdk import codegen; sys.stdout.write(codegen._PYTHON_TEMPLATE)',
      ],
      { cwd: join(ROOT, 'packages/runar-py'), encoding: 'utf-8', timeout: 60_000 },
    );
    expect(res.status, res.stderr?.slice(0, 500)).toBe(0);
    expect(res.stdout).toBe(disk('py'));
  });

  it('the two SDKs that generate a Python wrapper agree on its bytes', () => {
    // The property the byte-comparisons above exist to protect. A drifted copy
    // is only a problem because it changes what users get.
    const artifact = JSON.parse(
      readFileSync(join(ROOT, 'conformance/sdk-codegen/fixtures/counter.json'), 'utf-8'),
    );
    const fromTs = generatePython(artifact);

    const res = spawnSync(
      'python3',
      [
        '-c',
        'import sys, json; sys.path.insert(0, "."); ' +
          'from runar.sdk import codegen; from runar.sdk import RunarArtifact; ' +
          'a = RunarArtifact.from_dict(json.load(sys.stdin)); ' +
          'sys.stdout.write(codegen.generate_python(a))',
      ],
      {
        cwd: join(ROOT, 'packages/runar-py'),
        input: JSON.stringify(artifact),
        encoding: 'utf-8',
        timeout: 60_000,
      },
    );
    expect(res.status, res.stderr?.slice(0, 500)).toBe(0);
    expect(res.stdout.length, 'the Python SDK generated nothing').toBeGreaterThan(500);
    expect(res.stdout).toBe(fromTs);
  });

  it('wrapper.zig.mustache is READ, not dead — the finding got this one wrong', () => {
    // `gen-all.ts` interpolates the extension, so the literal filename appears
    // nowhere and a grep for it comes back empty. Reading it is the only way to
    // tell. `generateZig` throws if the file is missing, so a successful render
    // that contains the template's own marker text IS the reference.
    const artifact = JSON.parse(
      readFileSync(join(ROOT, 'conformance/sdk-codegen/fixtures/counter.json'), 'utf-8'),
    );
    const out = generateZig(artifact);
    expect(out.length).toBeGreaterThan(100);
    // A fragment that exists only in the template, so the assertion cannot be
    // satisfied by generic generated boilerplate.
    const marker = disk('zig').split('\n').find((l) => l.includes('{{') === false && l.trim().length > 20);
    expect(marker, 'no stable literal line in wrapper.zig.mustache to key on').toBeTruthy();
    expect(out).toContain(marker!.trim().replace(/\{\{.*?\}\}/g, ''));
  });
});
