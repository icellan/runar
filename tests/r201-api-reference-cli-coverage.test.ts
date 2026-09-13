import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

/**
 * R-201 / CL-DOC-0xx — `docs/api-reference.md` omitted whole CLI subcommands.
 *
 * `packages/runar-cli/src/bin.ts` registers nine: init, compile, test, deploy,
 * verify, codegen, debug, analyze, decompile. The reference documented six.
 * `debug`, `analyze` and `decompile` appeared nowhere — not a stale flag or a
 * renamed option, three entire commands, one of which (`decompile`) is a
 * CI-gated 9,598-line package (R-132).
 *
 * The guard is wider than the finding, for the same reason R-132's was: the
 * next command to land must not be able to go missing the same way. It reads
 * the registrations out of `bin.ts` rather than hard-coding a list, so the two
 * cannot drift apart without this failing.
 */

const REPO = resolve(__dirname, '..');
const BIN = resolve(REPO, 'packages/runar-cli/src/bin.ts');
const DOC = resolve(REPO, 'docs/api-reference.md');

/** Every `.command('x')` registered by the CLI. */
function registeredCommands(): string[] {
  const src = readFileSync(BIN, 'utf8');
  return [...src.matchAll(/\.command\('([a-z-]+)'\)/g)].map((m) => m[1]!).sort();
}

describe('R-201 the API reference documents every CLI subcommand', () => {
  it('finds the CLI registrations (an empty scan would prove nothing)', () => {
    const cmds = registeredCommands();
    expect(cmds.length).toBeGreaterThanOrEqual(8);
    expect(cmds).toContain('compile');
  });

  it('every registered command has a section in the reference', () => {
    const doc = readFileSync(DOC, 'utf8');
    const missing = registeredCommands().filter(
      (c) => !new RegExp(`^###\\s+\`runar ${c}\``, 'm').test(doc),
    );
    expect(
      missing,
      `docs/api-reference.md has no "### \`runar <cmd>\`" section for: ${missing.join(', ')}. ` +
        `A shipped command the reference does not mention is one users do not find.`,
    ).toEqual([]);
  });

  it('the three that were missing are specifically present', () => {
    const doc = readFileSync(DOC, 'utf8');
    for (const c of ['debug', 'analyze', 'decompile']) {
      expect(doc, `${c} is missing again`).toMatch(new RegExp(`^###\\s+\`runar ${c}\``, 'm'));
    }
  });

  it('each documented command names its own flags', () => {
    // A heading with no options table is a section that satisfies the check
    // above while telling a reader nothing. Spot-check the three added here.
    const doc = readFileSync(DOC, 'utf8');
    const flags: Array<[string, string]> = [
      ['debug', '--break'],
      ['analyze', '--severity'],
      ['decompile', '--raw'],
    ];
    for (const [cmd, flag] of flags) {
      const start = doc.indexOf(`### \`runar ${cmd}\``);
      expect(start, `${cmd} section missing`).toBeGreaterThan(-1);
      const next = doc.indexOf('\n### ', start + 1);
      const section = next === -1 ? doc.slice(start) : doc.slice(start, next);
      expect(section, `${cmd} section does not mention ${flag}`).toContain(flag);
    }
  });
});
