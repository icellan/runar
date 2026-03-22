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

  // Resolve template path relative to this file:
  // packages/runar-sdk/src/codegen/gen-all.ts → codegen/templates/
  const thisDir = path.dirname(fileURLToPath(import.meta.url));
  const templateDir = path.resolve(thisDir, '../../../../codegen/templates');
  const ext = lang === 'python' ? 'py' : lang === 'rust' ? 'rs' : lang === 'zig' ? 'zig' : lang;
  const templatePath = path.join(templateDir, `wrapper.${ext}.mustache`);

  const content = fs.readFileSync(templatePath, 'utf8');
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
