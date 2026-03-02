// ---------------------------------------------------------------------------
// runar-cli/commands/test.ts — Run contract tests
// ---------------------------------------------------------------------------

import { execSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';

/**
 * Run contract tests.
 *
 * Discovers test files matching the given pattern (or defaults to
 * `tests/**\/*.test.ts`) and executes them using vitest.
 */
export async function testCommand(pattern?: string): Promise<void> {
  const defaultPattern = 'tests/**/*.test.ts';
  const testPattern = pattern ?? defaultPattern;

  console.log(`Running tests matching: ${testPattern}`);
  console.log('');

  // Verify that test files exist
  const cwd = process.cwd();
  const testsDir = path.join(cwd, 'tests');

  if (!fs.existsSync(testsDir) && !pattern) {
    console.error(
      'No tests/ directory found. Create test files in tests/ or specify a pattern.',
    );
    process.exitCode = 1;
    return;
  }

  // Determine which test runner to use. We prefer vitest (which is listed
  // as a dev dependency in runar projects), but fall back to a simple
  // node-based runner if vitest isn't available.
  const vitestPath = resolveExecutable('vitest', cwd);

  if (vitestPath) {
    runWithVitest(vitestPath, testPattern, cwd);
  } else {
    // Fall back: try npx vitest
    runWithNpxVitest(testPattern, cwd);
  }
}

/**
 * Resolve a node_modules/.bin executable, returning its path or null.
 */
function resolveExecutable(name: string, cwd: string): string | null {
  const localBin = path.join(cwd, 'node_modules', '.bin', name);
  if (fs.existsSync(localBin)) {
    return localBin;
  }
  return null;
}

/**
 * Run tests using a local vitest installation.
 */
function runWithVitest(
  vitestPath: string,
  pattern: string,
  cwd: string,
): void {
  try {
    execSync(`"${vitestPath}" run "${pattern}"`, {
      cwd,
      stdio: 'inherit',
      env: { ...process.env },
    });
  } catch {
    // vitest sets exit code on test failure; the error is already printed
    process.exitCode = 1;
  }
}

/**
 * Run tests via npx vitest as a fallback.
 */
function runWithNpxVitest(pattern: string, cwd: string): void {
  try {
    execSync(`npx vitest run "${pattern}"`, {
      cwd,
      stdio: 'inherit',
      env: { ...process.env },
    });
  } catch {
    process.exitCode = 1;
  }
}
