// ---------------------------------------------------------------------------
// conformance/sdk-vertical/runner/sdk-tools.ts
// ---------------------------------------------------------------------------
//
// Per-tier driver invocation for the seven deployment SDKs.
//
// The driver PROGRAMS are the ones conformance/sdk-output already ships
// (`../../sdk-output/tools/*`): each reads an `{artifact, constructorArgs}`
// JSON file and prints that tier's deployed locking-script hex on stdout.
// The sdk-vertical cases use the same input shape precisely so those drivers
// run unchanged.
//
// Only the tool LIST is duplicated here rather than imported: sdk-runner.ts
// executes its suite at module scope, so importing it would run the whole
// sdk-output suite as a side effect. Duplicating ~80 lines of process
// plumbing is the cheaper of the two, and it keeps the two trees independent
// (a change to sdk-output's runner cannot silently alter which binaries the
// vertical pins interrogate).
// ---------------------------------------------------------------------------

import { execFileSync } from 'child_process';
import { accessSync, constants, existsSync, readdirSync, statSync } from 'fs';
import { dirname, join, resolve } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
export const ROOT = resolve(join(__dirname, '..', '..', '..'));

export interface SdkTool {
  name: string;
  cmd: string;
  args: (inputPath: string) => string[];
  env?: Record<string, string>;
  preBuild?: () => void;
}

export interface SdkResult {
  sdk: string;
  hex: string;
  success: boolean;
  error?: string;
  durationMs: number;
}

function isExecutable(path: string): boolean {
  try {
    accessSync(path, constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

function resolveGradle(): string {
  try {
    const out = execFileSync('which', ['gradle'], { stdio: 'pipe' }).toString().trim();
    if (out) return out;
  } catch {
    /* fall through to the wrapper cache */
  }
  const cacheRoot = join(process.env.HOME ?? '', '.gradle', 'wrapper', 'dists');
  if (existsSync(cacheRoot)) {
    for (const dist of readdirSync(cacheRoot)) {
      const distRoot = join(cacheRoot, dist);
      try {
        if (!statSync(distRoot).isDirectory()) continue;
        for (const hashDir of readdirSync(distRoot)) {
          const bin = join(distRoot, hashDir, dist.replace('-bin', ''), 'bin', 'gradle');
          if (existsSync(bin) && isExecutable(bin)) return bin;
        }
      } catch {
        /* non-directory cache entries (CACHEDIR.TAG etc.) */
      }
    }
  }
  return 'gradle';
}

/**
 * `toolsDirOverride` lets tests point this at a scratch directory so the
 * "binary not yet built" fallback branches (go build / cargo build) can be
 * exercised deterministically, without depending on whether the real
 * tools/ directory happens to already contain a built driver. Mirrors
 * `sdk-output/runner/sdk-runner.ts`'s `buildSdkTools(toolsDirOverride?)`.
 */
export function buildSdkTools(toolsDirOverride?: string): SdkTool[] {
  const TOOLS_DIR = toolsDirOverride ?? join(ROOT, 'conformance', 'sdk-output', 'tools');
  const tools: SdkTool[] = [
    { name: 'typescript', cmd: 'npx', args: (i) => ['tsx', join(TOOLS_DIR, 'ts-sdk-tool.ts'), i] },
    {
      name: 'python',
      cmd: 'python3',
      args: (i) => [join(TOOLS_DIR, 'py-sdk-tool.py'), i],
      env: { PYTHONPATH: join(ROOT, 'packages', 'runar-py') },
    },
    { name: 'ruby', cmd: 'ruby', args: (i) => [join(TOOLS_DIR, 'rb-sdk-tool.rb'), i] },
  ];

  // Go: prefer a pre-built binary; otherwise build it once via a separate
  // `go build` step (preBuild) before ever invoking it — see the N-091 /
  // N-174 note on the Rust tool below for why the build and the run must
  // not share one invocation. Mirrors sdk-output/runner/sdk-runner.ts.
  const goBin = join(TOOLS_DIR, 'go-sdk-tool-bin');
  const goSrc = join(TOOLS_DIR, 'go-sdk-tool.go');
  if (isExecutable(goBin)) {
    tools.push({ name: 'go', cmd: goBin, args: (i) => [i] });
  } else {
    tools.push({
      name: 'go',
      cmd: goBin,
      args: (i) => [i],
      preBuild: () => {
        execFileSync('go', ['build', '-o', goBin, goSrc], {
          cwd: ROOT,
          stdio: 'pipe',
          timeout: 120_000,
        });
      },
    });
  }

  // Rust: prefer pre-built binary; otherwise build it once via a separate
  // `cargo build` step (preBuild) before ever invoking it, the same pattern
  // the zig/java tools below already use. N-091/N-174: the previous
  // fallback ran `cargo run`, which compiles AND runs in a single
  // invocation, so cargo's own build log ('Compiling ...', warnings) lands
  // in the SAME stderr stream `vertical-runner.ts` reports as
  // `result.error` and compares tiers by — build noise can stand in for, or
  // drown out, the driver's own diagnostic. Building separately (and
  // discarding that output unless it fails) means the stderr the runner
  // ever sees is the driver's own.
  const rsBin = join(TOOLS_DIR, 'rs-sdk-tool', 'target', 'release', 'rs-sdk-tool');
  if (isExecutable(rsBin)) {
    tools.push({ name: 'rust', cmd: rsBin, args: (i) => [i] });
  } else {
    tools.push({
      name: 'rust',
      cmd: rsBin,
      args: (i) => [i],
      preBuild: () => {
        execFileSync('cargo', [
          'build', '--release',
          '--manifest-path', join(TOOLS_DIR, 'rs-sdk-tool', 'Cargo.toml'),
        ], {
          cwd: ROOT,
          stdio: 'pipe',
          // A from-scratch build pulls in rs-sdk-tool's full dependency
          // tree; CI prebuilds rs-sdk-tool in its own step before invoking
          // this runner (see N-091), so this timeout only protects a cold
          // local dev run.
          timeout: 600_000,
        });
      },
    });
  }

  const zigBin = join(TOOLS_DIR, 'zig-sdk-tool', 'zig-out', 'bin', 'zig-sdk-tool');
  tools.push({
    name: 'zig',
    cmd: zigBin,
    args: (i) => [i],
    preBuild: isExecutable(zigBin)
      ? undefined
      : () => {
          execFileSync('zig', ['build'], {
            cwd: join(TOOLS_DIR, 'zig-sdk-tool'),
            stdio: 'pipe',
            timeout: 300_000,
          });
        },
  });

  const javaToolDir = join(TOOLS_DIR, 'java-driver');
  const javaJar = join(javaToolDir, 'build', 'libs', 'java-sdk-driver-1.0.0-rc.1-all.jar');
  tools.push({
    name: 'java',
    cmd: 'java',
    args: (i) => ['-jar', javaJar, i],
    preBuild: existsSync(javaJar)
      ? undefined
      : () => {
          execFileSync(resolveGradle(), ['fatJar', '--no-daemon', '-x', 'javadoc'], {
            cwd: javaToolDir,
            stdio: 'pipe',
            timeout: 600_000,
          });
        },
  });

  return tools;
}

export function runSdkTool(tool: SdkTool, inputPath: string): SdkResult {
  const start = Date.now();
  try {
    if (tool.preBuild) {
      tool.preBuild();
      tool.preBuild = undefined;
    }
    const output = execFileSync(tool.cmd, tool.args(inputPath), {
      cwd: ROOT,
      timeout: 120_000,
      maxBuffer: 32 * 1024 * 1024,
      env: { ...process.env, ...tool.env },
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    return { sdk: tool.name, hex: output.toString().trim().toLowerCase(), success: true, durationMs: Date.now() - start };
  } catch (err: unknown) {
    const e = err as { stderr?: Buffer; message?: string };
    return {
      sdk: tool.name,
      hex: '',
      success: false,
      error: e.stderr?.toString().slice(0, 600) || e.message || 'unknown error',
      durationMs: Date.now() - start,
    };
  }
}
