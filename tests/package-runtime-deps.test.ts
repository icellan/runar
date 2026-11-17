/**
 * Every bare import in a published package's non-test source must be declared
 * in that package's `dependencies` or `peerDependencies` (or be a node:
 * builtin / the package itself). A devDependency is not installed for
 * consumers, so `import 'pkg'` throws "Cannot find module" after `npm i pkg`
 * (issue #188: runar-testing imported fast-check but only devDepended on it).
 */
import { describe, it, expect } from 'vitest';
import { readdirSync, readFileSync, existsSync, statSync } from 'node:fs';
import { builtinModules } from 'node:module';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import ts from 'typescript';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const PACKAGES_DIR = join(ROOT, 'packages');
const BUILTINS = new Set(builtinModules.map((m) => m.replace(/^node:/, '').split('/')[0]));

function walk(dir: string, out: string[]): void {
  for (const name of readdirSync(dir)) {
    if (name === 'node_modules' || name === 'dist' || name === '__tests__' || name === 'tests') continue;
    const p = join(dir, name);
    if (statSync(p).isDirectory()) walk(p, out);
    else if (/\.(ts|tsx)$/.test(name) && !/\.(test|spec)\.tsx?$/.test(name) && !name.endsWith('.d.ts')) out.push(p);
  }
}

/**
 * Runtime module specifiers via the TS AST (so import-looking text inside
 * code-generation template strings is not counted). Type-only imports/exports
 * are erased at build time and need no runtime dependency.
 */
function bareImports(file: string, source: string): Set<string> {
  const specs = new Set<string>();
  const sf = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true);
  const visit = (n: ts.Node): void => {
    if (ts.isImportDeclaration(n) && ts.isStringLiteral(n.moduleSpecifier)) {
      const c = n.importClause;
      const typeOnly =
        !!c &&
        (c.isTypeOnly ||
          (!c.name &&
            !!c.namedBindings &&
            ts.isNamedImports(c.namedBindings) &&
            c.namedBindings.elements.length > 0 &&
            c.namedBindings.elements.every((e) => e.isTypeOnly)));
      if (!typeOnly) specs.add(n.moduleSpecifier.text);
    } else if (ts.isExportDeclaration(n) && n.moduleSpecifier && ts.isStringLiteral(n.moduleSpecifier)) {
      if (!n.isTypeOnly) specs.add(n.moduleSpecifier.text);
    } else if (ts.isCallExpression(n) && n.arguments.length === 1 && ts.isStringLiteralLike(n.arguments[0])) {
      const callee = n.expression;
      if (
        callee.kind === ts.SyntaxKind.ImportKeyword ||
        (ts.isIdentifier(callee) && callee.text === 'require')
      ) {
        specs.add((n.arguments[0] as ts.StringLiteralLike).text);
      }
    }
    ts.forEachChild(n, visit);
  };
  visit(sf);
  return specs;
}

function packageNameOf(spec: string): string {
  const parts = spec.split('/');
  return spec.startsWith('@') ? parts.slice(0, 2).join('/') : parts[0];
}

describe('published packages declare every runtime import', () => {
  const pkgDirs = readdirSync(PACKAGES_DIR)
    .map((n) => join(PACKAGES_DIR, n))
    .filter((d) => existsSync(join(d, 'package.json')) && existsSync(join(d, 'src')));

  it('finds the published TS packages', () => {
    expect(pkgDirs.length).toBeGreaterThanOrEqual(6);
  });

  for (const dir of pkgDirs) {
    const pkg = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8'));
    if (pkg.private) continue;
    it(`${pkg.name}`, () => {
      const declared = new Set([
        ...Object.keys(pkg.dependencies ?? {}),
        ...Object.keys(pkg.peerDependencies ?? {}),
      ]);
      const files: string[] = [];
      walk(join(dir, 'src'), files);
      const missing: string[] = [];
      for (const f of files) {
        for (const spec of bareImports(f, readFileSync(f, 'utf8'))) {
          if (spec.startsWith('.') || spec.startsWith('/')) continue;
          if (spec.startsWith('node:')) continue;
          const name = packageNameOf(spec);
          if (BUILTINS.has(name) || name === pkg.name || declared.has(name)) continue;
          missing.push(`${f.slice(ROOT.length + 1)} imports '${spec}' (not in dependencies/peerDependencies)`);
        }
      }
      expect(missing).toEqual([]);
    });
  }
});
