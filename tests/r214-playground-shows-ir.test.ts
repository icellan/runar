/**
 * R-214 (CL-GAP-055) — the playground computed the IR and discarded it.
 *
 * The Go side is covered by `examples/end2end-example/webapp/
 * playground_ir_test.go`, which pins that `/api/compile` returns the ANF the
 * compiler already produced. This file covers the other half: the browser has
 * to render it, or the payload is just a longer thing to throw away.
 *
 * `static/app.js` is a plain script with no module system and the repo has no
 * DOM environment installed, so the render helper is evaluated against a
 * minimal `document` stub and CALLED. A source-text match would pass on a
 * function that never runs; this fails if the rendering is wrong.
 *
 * Stack IR is out of scope by design: no tier serialises it (CLAUDE.md,
 * invariant 2 — the claim that it is compared was removed under R-096), so
 * there is nothing canonical to display. The finding named both artifacts;
 * only the ANF exists to show.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const appJsPath = join(repoRoot, 'examples', 'end2end-example', 'webapp', 'static', 'app.js');

interface StubNode {
  tag: string;
  className: string;
  textContent: string;
  children: StubNode[];
}

function makeDocumentStub(): { document: unknown; create: (tag: string) => StubNode } {
  const create = (tag: string): StubNode => {
    const node: StubNode = {
      tag,
      className: '',
      textContent: '',
      children: [],
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      appendChild(child: StubNode) { (this as any).children.push(child); return child; },
    } as unknown as StubNode;
    return node;
  };
  return { document: { createElement: create }, create };
}

/** Extract and evaluate one top-level function from app.js. */
function loadAppFunction(name: string): (...args: unknown[]) => unknown {
  const source = readFileSync(appJsPath, 'utf8');
  const start = source.indexOf(`function ${name}(`);
  if (start === -1) throw new Error(`${name} not found in app.js`);

  // Walk braces from the signature to the function's closing brace.
  let depth = 0;
  let end = -1;
  for (let i = source.indexOf('{', start); i < source.length; i++) {
    if (source[i] === '{') depth++;
    else if (source[i] === '}') {
      depth--;
      if (depth === 0) { end = i + 1; break; }
    }
  }
  if (end === -1) throw new Error(`${name} is not brace-balanced in app.js`);

  const { document } = makeDocumentStub();
  const factory = new Function('document', `${source.slice(start, end)}; return ${name};`);
  return factory(document) as (...args: unknown[]) => unknown;
}

/** Depth-first flatten of the stub tree. */
function flatten(node: StubNode): StubNode[] {
  return [node, ...node.children.flatMap(flatten)];
}

describe('R-214: the playground renders the ANF IR it is sent', () => {
  let pgResultAppendAnf: (...args: unknown[]) => unknown;
  let create: (tag: string) => StubNode;

  beforeAll(() => {
    pgResultAppendAnf = loadAppFunction('pgResultAppendAnf');
    create = makeDocumentStub().create;
  });

  const sampleAnf = {
    contractName: 'IrProbe',
    properties: [{ name: 'target', type: 'bigint', readonly: true }],
    methods: [
      { name: 'constructor', body: [] },
      { name: 'verify', body: [{ name: 't0', value: { kind: 'load_param', name: 'x' } }] },
    ],
  };

  it('renders a collapsible panel carrying the IR', () => {
    const parent = create('div');
    pgResultAppendAnf(parent, sampleAnf);

    const nodes = flatten(parent);
    const details = nodes.find(n => n.tag === 'details');
    expect(details, 'no <details> panel was appended').toBeDefined();

    const summary = nodes.find(n => n.tag === 'summary');
    expect(summary?.textContent).toContain('ANF IR');
    // The count comes from the payload, so a hard-coded label would fail here.
    expect(summary?.textContent).toContain('2 method');

    const pre = nodes.find(n => n.tag === 'pre');
    expect(pre, 'no <pre> carrying the IR').toBeDefined();
    expect(pre!.textContent).toContain('"contractName": "IrProbe"');
    expect(pre!.textContent).toContain('load_param');
  });

  it('pluralises from the payload rather than assuming', () => {
    const parent = create('div');
    pgResultAppendAnf(parent, { contractName: 'One', methods: [{ name: 'only', body: [] }] });
    const summary = flatten(parent).find(n => n.tag === 'summary');
    expect(summary?.textContent).toContain('1 method');
    expect(summary?.textContent).not.toContain('1 methods');
  });

  it('appends nothing when the response carries no IR', () => {
    // A failed compile omits `anfIr` entirely. Rendering an empty panel would
    // tell the user the contract lowered to nothing, which is worse than silence.
    for (const missing of [undefined, null]) {
      const parent = create('div');
      pgResultAppendAnf(parent, missing);
      expect(parent.children).toEqual([]);
    }
  });

  it('is wired into the compile path, not merely defined', () => {
    // The helper could be perfect and never called. `compileSource` is the only
    // caller and it must pass the field the handler actually sends.
    const source = readFileSync(appJsPath, 'utf8');
    const body = source.slice(source.indexOf('async function compileSource('));
    expect(body).toMatch(/pgResultAppendAnf\(resultEl,\s*data\.anfIr\)/);
  });
});
