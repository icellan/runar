// ---------------------------------------------------------------------------
// runar-cli/commands/codegen.ts — Generate typed contract wrappers
// ---------------------------------------------------------------------------

import * as fs from 'node:fs';
import * as path from 'node:path';

interface CodegenOptions {
  output?: string;
  lang: string;
}

const SUPPORTED_LANGS = ['ts', 'go', 'rust', 'python'];

/**
 * Simple glob expansion for artifact file patterns.
 * Uses a basic directory scan + pattern match to avoid dependency on
 * fs.globSync (which vitest's SSR transform doesn't handle correctly).
 */
function expandGlob(pattern: string): string[] {
  const dir = path.dirname(pattern);
  const base = path.basename(pattern);

  // Convert glob pattern to regex: * → [^/]*, ? → [^/]
  const regexStr = '^' + base
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*/g, '[^/]*')
    .replace(/\?/g, '[^/]') + '$';
  const regex = new RegExp(regexStr);

  try {
    const resolvedDir = path.resolve(dir);
    const entries = fs.readdirSync(resolvedDir);
    return entries
      .filter((entry) => regex.test(entry))
      .map((entry) => path.join(resolvedDir, entry));
  } catch {
    return [];
  }
}

/** Convert camelCase/PascalCase to snake_case for file naming. */
function toSnakeCase(name: string): string {
  return name
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1_$2')
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .toLowerCase();
}

export async function codegenCommand(patterns: string[], options: CodegenOptions): Promise<void> {
  if (!SUPPORTED_LANGS.includes(options.lang)) {
    console.error(`Error: language '${options.lang}' is not supported. Available: ${SUPPORTED_LANGS.join(', ')}`);
    process.exit(1);
  }

  // Expand glob patterns (handles quoted globs on Windows / shells that don't expand)
  const files: string[] = [];
  for (const pattern of patterns) {
    if (pattern.includes('*') || pattern.includes('?')) {
      const matches = expandGlob(pattern);
      files.push(...matches);
    } else {
      files.push(pattern);
    }
  }

  if (files.length === 0) {
    console.error('Error: no artifact files matched.');
    process.exit(1);
  }

  // Dynamically import the codegen functions from runar-sdk
  const { generateTypescript, generateGo, generateRust, generatePython } = await import('runar-sdk/codegen');

  const generators: Record<string, { fn: (a: any) => string; ext: string; nameStyle: 'pascal' | 'snake' }> = {
    ts:     { fn: generateTypescript, ext: '.ts', nameStyle: 'pascal' },
    go:     { fn: generateGo,        ext: '.go', nameStyle: 'snake' },
    rust:   { fn: generateRust,      ext: '.rs', nameStyle: 'snake' },
    python: { fn: generatePython,    ext: '.py', nameStyle: 'snake' },
  };

  const { fn: generate, ext, nameStyle } = generators[options.lang]!;

  let generated = 0;
  for (const file of files) {
    const resolvedPath = path.resolve(file);
    if (!fs.existsSync(resolvedPath)) {
      console.error(`Error: artifact not found: ${resolvedPath}`);
      process.exit(1);
    }

    let artifact: Record<string, unknown>;
    try {
      const json = fs.readFileSync(resolvedPath, 'utf8');
      artifact = JSON.parse(json);
    } catch (err) {
      console.error(`Error: failed to parse ${resolvedPath}: ${(err as Error).message}`);
      process.exit(1);
    }

    const code = generate(artifact as any);

    const contractName = (artifact as any).contractName ?? 'Contract';
    const outputDir = options.output
      ? path.resolve(options.output)
      : path.dirname(resolvedPath);

    if (!fs.existsSync(outputDir)) {
      fs.mkdirSync(outputDir, { recursive: true });
    }

    const fileName = nameStyle === 'snake'
      ? `${toSnakeCase(contractName)}_contract${ext}`
      : `${contractName}Contract${ext}`;
    const outputPath = path.join(outputDir, fileName);
    fs.writeFileSync(outputPath, code, 'utf8');

    console.log(`Generated: ${outputPath}`);
    generated++;
  }

  if (generated > 1) {
    console.log(`\n${generated} wrappers generated.`);
  }
}
