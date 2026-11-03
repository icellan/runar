// Copy the canonical codegen/templates/*.mustache (repo root) into
// dist/codegen/templates so the published package ships them (F-246).
// codegen/templates stays the single source of truth; this copy is a build
// output, never checked in.
import { copyFileSync, mkdirSync, readdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const pkg = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const src = resolve(pkg, '..', '..', 'codegen', 'templates');
const dest = join(pkg, 'dist', 'codegen', 'templates');

const templates = readdirSync(src).filter((f) => f.endsWith('.mustache'));
if (templates.length === 0) {
  throw new Error(`runar-sdk build: no *.mustache templates found in ${src}`);
}
mkdirSync(dest, { recursive: true });
for (const f of templates) copyFileSync(join(src, f), join(dest, f));
