/**
 * R-154 (CL-BUG-083) — "Load Template" must load the template for the language
 * the user picked.
 *
 * `PLAYGROUND_TEMPLATES` carried source for two of the nine surfaces, and
 * `loadTemplate` ended with `|| PLAYGROUND_TEMPLATES.java`. Choose Ruby, click
 * the button, get Java — silently. The filename sent on to `/api/compile` was
 * still `P2PKH.runar.rb`, so the user saw a parse error against source they
 * never wrote.
 *
 * The backend half is covered by `examples/end2end-example/webapp/
 * playground_template_test.go`, which pins that `/api/template` serves a
 * distinct, compiling contract for each of the nine languages. This file
 * covers the browser: that `loadTemplate` asks for the selected language and
 * does NOT substitute anything when the answer is an error.
 *
 * The function is evaluated against stubs and CALLED. A source-text match
 * would pass on a function that never runs, and the bug being fixed was
 * precisely a fallback that ran.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const appJsPath = join(repoRoot, 'examples', 'end2end-example', 'webapp', 'static', 'app.js');
const appJs = readFileSync(appJsPath, 'utf8');

/** Strip line and block comments so prose cannot satisfy a code assertion. */
function codeOnly(source: string): string {
  return source
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .split('\n')
    .map(line => {
      const idx = line.indexOf('//');
      // Crude but sufficient here: app.js has no `//` inside a string literal
      // on any line this file inspects.
      return idx === -1 ? line : line.slice(0, idx);
    })
    .join('\n');
}

interface Harness {
  calls: string[];
  textarea: { value: string };
  result: { children: unknown[] };
  run: () => Promise<void>;
}

function makeHarness(opts: { lang: string; respond: (path: string) => Promise<unknown> }): Harness {
  const calls: string[] = [];
  const textarea = { value: 'ORIGINAL EDITOR CONTENT' };
  const result = {
    children: [] as unknown[],
    firstChild: null as unknown,
    appendChild(node: unknown) { this.children.push(node); return node; },
    removeChild(node: unknown) {
      this.children = this.children.filter(c => c !== node);
      return node;
    },
  };

  const document = {
    getElementById: (id: string) => (id === 'pg-source' ? textarea : result),
    createElement: (tag: string) => ({ tag, className: '', textContent: '' }),
  };

  const start = appJs.indexOf('async function loadTemplate(');
  if (start === -1) throw new Error('loadTemplate not found in app.js');
  let depth = 0;
  let end = -1;
  for (let i = appJs.indexOf('{', start); i < appJs.length; i++) {
    if (appJs[i] === '{') depth++;
    else if (appJs[i] === '}') { depth--; if (depth === 0) { end = i + 1; break; } }
  }
  if (end === -1) throw new Error('loadTemplate is not brace-balanced');

  const api = async (method: string, path: string) => {
    calls.push(`${method} ${path}`);
    return opts.respond(path);
  };
  const selectedPlaygroundLang = () => opts.lang;

  const factory = new Function(
    'document', 'api', 'selectedPlaygroundLang',
    `${appJs.slice(start, end)}; return loadTemplate;`,
  );
  const fn = factory(document, api, selectedPlaygroundLang) as () => Promise<void>;

  return { calls, textarea, result: result as unknown as { children: unknown[] }, run: fn };
}

describe('R-154: the playground asks for the language the user selected', () => {
  it('requests the selected language, not a default', async () => {
    for (const lang of ['rb', 'zig', 'move', 'py']) {
      const h = makeHarness({
        lang,
        respond: async () => ({ lang, filename: `PriceBet.runar.${lang}`, source: `SOURCE-${lang}` }),
      });
      await h.run();
      expect(h.calls).toEqual([`GET /api/template?lang=${lang}`]);
      expect(h.textarea.value).toBe(`SOURCE-${lang}`);
    }
  });

  it('leaves the editor alone when no template is available', async () => {
    // The bug was substituting another language's source. Refusing to write
    // anything is the correct failure: the user keeps what they had and is
    // told why.
    const h = makeHarness({
      lang: 'rb',
      respond: async () => { throw new Error('unknown lang "rb"'); },
    });
    await h.run();
    expect(h.textarea.value).toBe('ORIGINAL EDITOR CONTENT');
    expect(h.result.children.length).toBeGreaterThan(0);
  });

  it('carries no hardcoded template table any more', () => {
    // Seven missing entries in a nine-entry table is the bug; a table at all
    // is the shape that allows it back.
    expect(codeOnly(appJs)).not.toMatch(/PLAYGROUND_TEMPLATES/);
  });

  it('has no language fallback left in the load path', () => {
    const code = codeOnly(appJs);
    const start = code.indexOf('async function loadTemplate(');
    expect(start, 'loadTemplate is missing').toBeGreaterThan(-1);
    const body = code.slice(start, start + 1200);
    // `x || y` picking a substitute language is exactly what regressed here.
    expect(body).not.toMatch(/\|\|\s*[A-Za-z_$][\w$]*\.(java|ts)\b/);
  });
});
