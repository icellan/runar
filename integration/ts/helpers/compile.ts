/**
 * Compile helper — compiles Runar contracts for integration tests.
 */

import { readFileSync } from 'fs';
import { resolve } from 'path';
import { compile } from 'runar-compiler';
import type { RunarArtifact } from 'runar-ir-schema';

const PROJECT_ROOT = resolve(import.meta.dirname, '..', '..', '..');

export function compileContract(sourcePath: string): RunarArtifact {
  const absPath = resolve(PROJECT_ROOT, sourcePath);
  const source = readFileSync(absPath, 'utf-8');
  const fileName = absPath.split('/').pop()!;
  const result = compile(source, { fileName });
  if (!result.artifact) {
    throw new Error(`Compile failed for ${sourcePath}: ${JSON.stringify(result.errors)}`);
  }
  return result.artifact;
}

export function compileSource(source: string, fileName: string): RunarArtifact {
  const result = compile(source, { fileName });
  if (!result.artifact) {
    throw new Error(`Compile failed: ${JSON.stringify(result.errors)}`);
  }
  return result.artifact;
}
