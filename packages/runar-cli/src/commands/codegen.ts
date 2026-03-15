// ---------------------------------------------------------------------------
// runar-cli/commands/codegen.ts — Generate typed contract wrappers
// ---------------------------------------------------------------------------

import * as fs from 'node:fs';
import * as path from 'node:path';

interface CodegenOptions {
  output?: string;
  lang: string;
}

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

export async function codegenCommand(patterns: string[], options: CodegenOptions): Promise<void> {
  if (options.lang !== 'ts') {
    console.error(`Error: language '${options.lang}' is not yet supported. Only 'ts' is available.`);
    process.exit(1);
  }

  // Expand glob patterns (handles quoted globs on Windows / shells that don't expand)
  const files: string[] = [];
  for (const pattern of patterns) {
    if (pattern.includes('*') || pattern.includes('?')) {
      // fs.globSync is Node 22+; use dynamic import to avoid SSR transform issues
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

  // Dynamically import the codegen function from runar-sdk
  const { generateTypescript } = await import('runar-sdk');

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

    const code = generateTypescript(artifact as any);

    const contractName = (artifact as any).contractName ?? 'Contract';
    const outputDir = options.output
      ? path.resolve(options.output)
      : path.dirname(resolvedPath);

    if (!fs.existsSync(outputDir)) {
      fs.mkdirSync(outputDir, { recursive: true });
    }

    const outputPath = path.join(outputDir, `${contractName}Contract.ts`);
    fs.writeFileSync(outputPath, code, 'utf8');

    console.log(`Generated: ${outputPath}`);
    generated++;
  }

  if (generated > 1) {
    console.log(`\n${generated} wrappers generated.`);
  }
}
