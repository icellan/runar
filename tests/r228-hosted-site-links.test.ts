/**
 * R-228 (GK-DOC-005): the SDK READMEs point at `runar.build` and `runar.run` as
 * "the playground" and "the hosted contract gallery and playground". Neither
 * site is in this git tree. The in-repo app at
 * `examples/end2end-example/webapp/` is a PriceBet demo whose playground pane is
 * a textarea that returns script hex and ASM — no source maps, no debugger, no
 * gallery, no share links.
 *
 * Two different things with one name. A reader who follows the README to a
 * hosted IDE and then opens the in-repo webapp expecting the same thing finds a
 * textarea; a reader who reasons about the hosted site's behaviour from this
 * repository's source is reasoning about code that is not here.
 *
 * Nothing is being removed: linking a hosted site from a README is normal. What
 * the links did not say is that the site lives outside this repository, so its
 * behaviour is not something this tree can be checked against.
 *
 * The test requires every mention of those hosts to carry that disclosure
 * nearby, which is a property a future link inherits automatically.
 */

import { describe, it, expect } from 'vitest';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const HOSTS = /runar\.build|runar\.run/;

function trackedMarkdown(): string[] {
  return execFileSync('git', ['ls-files', '*.md'], { cwd: ROOT, encoding: 'utf-8' })
    .split('\n')
    .filter(Boolean)
    // This remediation's own working notes quote the finding; they are not docs.
    .filter((f) => !/^RECONCILED-|^REMEDIATION-/.test(f));
}

/** Lines mentioning a hosted host, with their file and line number. */
function hostMentions(): Array<{ file: string; line: number; text: string; near: string }> {
  const out: Array<{ file: string; line: number; text: string; near: string }> = [];
  for (const rel of trackedMarkdown()) {
    const lines = readFileSync(join(ROOT, rel), 'utf-8').split('\n');
    lines.forEach((text, i) => {
      if (HOSTS.test(text)) {
        out.push({ file: rel, line: i + 1, text, near: lines.slice(Math.max(0, i - 3), i + 4).join('\n') });
      }
    });
  }
  return out;
}

describe('R-228: a hosted site is labelled as one', () => {
  it('the scan finds the mentions it is about', () => {
    const mentions = hostMentions();
    expect(mentions.length, 'no runar.build / runar.run mentions found').toBeGreaterThan(0);
    expect(mentions.map((m) => m.file)).toContain('packages/runar-sdk/README.md');
  });

  it('every mention says the site is outside this repository', () => {
    const undisclosed = hostMentions()
      .filter((m) => !/(not in|outside) this (git tree|repo(sitory)?)|hosted separately|not part of this repo/i.test(m.near))
      .map((m) => `${m.file}:${m.line}`);
    expect(
      undisclosed,
      'these link a hosted site without saying it lives outside this repository, ' +
        'so a reader cannot tell it apart from the in-repo demo webapp',
    ).toEqual([]);
  });
});
