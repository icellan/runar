// ---------------------------------------------------------------------------
// codegen/gen-all.ts — Template-based code generators for all languages
// ---------------------------------------------------------------------------

import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import type { RunarArtifact } from 'runar-ir-schema';
import { buildCodegenContext } from './common.js';
import { renderMustache } from './mustache.js';
import type { TargetLang } from './common.js';

// ---------------------------------------------------------------------------
// Template loading
// ---------------------------------------------------------------------------

let templateCache: Map<string, string> | undefined;

function loadTemplate(lang: TargetLang): string {
  if (!templateCache) {
    templateCache = new Map();
  }
  const cached = templateCache.get(lang);
  if (cached) return cached;

  // Built (dist/codegen/gen-all.js): the build copies the templates next to
  // this module, into dist/codegen/templates, and that copy is what npm
  // publishes. Source (src/codegen/gen-all.ts under tsx/vitest): read the
  // canonical repo-root codegen/templates directly. No fallback between the
  // two — a fixed '../../../../' from an installed package lands in the
  // consumer's project root (F-246).
  const thisFile = fileURLToPath(import.meta.url);
  const thisDir = path.dirname(thisFile);
  const templateDir = thisFile.endsWith('.ts')
    ? path.resolve(thisDir, '../../../../codegen/templates')
    : path.join(thisDir, 'templates');
  const ext = lang === 'python' ? 'py' : lang === 'rust' ? 'rs' : lang === 'zig' ? 'zig' : lang;
  const templatePath = path.join(templateDir, `wrapper.${ext}.mustache`);

  let content: string;
  try {
    content = fs.readFileSync(templatePath, 'utf8');
  } catch (e) {
    throw new Error(
      `runar-sdk: cannot load codegen template ${templatePath}: ${(e as Error).message}`,
    );
  }
  templateCache.set(lang, content);
  return content;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

function generate(artifact: RunarArtifact, lang: TargetLang): string {
  const context = buildCodegenContext(artifact, lang);
  const template = loadTemplate(lang);
  return renderMustache(template, context as unknown as Record<string, unknown>);
}

/** Generate a typed Go wrapper from a compiled Runar artifact. */
export function generateGo(artifact: RunarArtifact): string {
  return generate(artifact, 'go');
}

/** Generate a typed Rust wrapper from a compiled Runar artifact. */
export function generateRust(artifact: RunarArtifact): string {
  return generate(artifact, 'rust');
}

/** Generate a typed Python wrapper from a compiled Runar artifact. */
export function generatePython(artifact: RunarArtifact): string {
  return generate(artifact, 'python');
}

/** Generate a typed Zig wrapper from a compiled Runar artifact. */
export function generateZig(artifact: RunarArtifact): string {
  return generate(artifact, 'zig');
}

/**
 * Generate a typed TypeScript wrapper using the template-based approach.
 * (The original gen-typescript.ts imperative generator is still available.)
 */
export function generateTypescriptFromTemplate(artifact: RunarArtifact): string {
  return generate(artifact, 'ts');
}
