import { describe, expect, it } from 'vitest';
import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';

const ROOT = resolve(__dirname, '..');

/**
 * `scripts/bump-version.sh --check` is a CI gate — it runs in the same
 * composite lint job as scripts/lint-no-silent-skips.sh. It failed on PR #153
 * with
 *
 *   ✗ packages/runar-rs/Cargo.toml dep runar-compiler-rust: 1.0.0-rc.1
 *   # `<0.3` keeps this crate on the same bsv-sdk as its `runar-compiler-rust`
 *
 * — reporting the version as WRONG while printing the RIGHT version. The
 * inter-crate dep check grepped the crate name unanchored, so a prose comment
 * that merely mentions `runar-compiler-rust` matched too; `$v` became two
 * lines and the equality test could never hold.
 *
 * The bug is in the gate, not in the manifest: a Cargo.toml is allowed to
 * mention a crate name in a comment. This pins that a passing tree passes,
 * and that the check reads dependency lines rather than any line containing
 * the name.
 */
describe('version consistency gate', () => {
  it('reports no drift on the current tree', () => {
    let stdout = '';
    let status = 0;
    try {
      stdout = execFileSync('bash', ['scripts/bump-version.sh', '--check'], {
        cwd: ROOT,
        encoding: 'utf8',
      });
    } catch (err) {
      const e = err as { status?: number; stdout?: string };
      status = e.status ?? 1;
      stdout = e.stdout ?? '';
    }
    expect(stdout, `gate reported drift:\n${stdout}`).not.toContain('✗');
    expect(status).toBe(0);
  });

  /**
   * CK17-FU4: on macOS's stock /bin/bash (3.2.57), `< <(...)` process
   * substitution never closes its pipe fd when the loop around it ends —
   * only when the enclosing shell exits. `--check` opens roughly 270 of
   * these over a single run (one per regex per file it reads), which is
   * past macOS's default per-process open-file soft limit (256), so a
   * fresh Terminal session hits "cannot make pipe for process substitution:
   * Too many open files" partway through and exits non-zero. N-172 fixed
   * two of these loops (the sdk-vertical ones) by reading into a variable
   * first and looping over a here-string instead, which reads from a temp
   * file rather than a long-lived pipe; the remaining four `< <(...)` sites
   * (check_exact's own loop, the sdk-output `input.json` sweep, the
   * Gemfile.lock loop, and the embedded-compiler-version sweep) still used
   * process substitution and still leaked. This pins a constrained fd
   * ulimit as a deterministic reproduction, since the default ulimit in
   * most dev/CI shells (including this test's) is high enough to mask it.
   */
  it('survives a constrained file-descriptor limit (bash 3.2 leaks process-substitution pipes)', () => {
    let stdout = '';
    let status = 0;
    try {
      stdout = execFileSync(
        'bash',
        ['-c', 'ulimit -n 64 && exec bash scripts/bump-version.sh --check'],
        { cwd: ROOT, encoding: 'utf8' },
      );
    } catch (err) {
      const e = err as { status?: number; stdout?: string };
      status = e.status ?? 1;
      stdout = e.stdout ?? '';
    }
    expect(stdout, `gate reported drift or an fd error:\n${stdout}`).not.toContain('✗');
    expect(stdout).not.toContain('Too many open files');
    expect(status).toBe(0);
  });

  it('does not mistake a comment mentioning a crate for that crate\'s dep line', () => {
    // The manifest genuinely carries such a comment (the bsv-sdk floor note
    // references runar-compiler-rust). Keep it — it is the regression input.
    const manifest = resolve(ROOT, 'packages/runar-rs/Cargo.toml');
    const text = execFileSync('cat', [manifest], { encoding: 'utf8' });
    const mentions = text
      .split('\n')
      .filter((l) => l.includes('runar-compiler-rust'));
    expect(
      mentions.some((l) => l.trimStart().startsWith('#')),
      'expected a comment mentioning runar-compiler-rust to remain as the regression input',
    ).toBe(true);
    expect(mentions.some((l) => /^runar-compiler-rust\s*=/.test(l))).toBe(true);
  });
});
