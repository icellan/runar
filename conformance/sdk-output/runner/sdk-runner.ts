import { execFileSync } from 'child_process';
import { readdirSync, readFileSync, writeFileSync, existsSync, accessSync, constants } from 'fs';
import { join, resolve } from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const ROOT = resolve(join(__dirname, '..', '..', '..'));

interface SdkResult {
  sdk: string;
  hex: string;
  success: boolean;
  error?: string;
  durationMs: number;
}

interface TestResult {
  testName: string;
  sdkResults: SdkResult[];
  allMatch: boolean;
  goldenMatch: boolean;
  errors: string[];
}

interface SdkTool {
  name: string;
  cmd: string;
  args: (inputPath: string) => string[];
  env?: Record<string, string>;
  cwd?: string;
  preBuild?: () => void;
}

function isExecutable(path: string): boolean {
  try {
    accessSync(path, constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

function buildSdkTools(): SdkTool[] {
  const toolsDir = join(ROOT, 'conformance', 'sdk-output', 'tools');
  const tools: SdkTool[] = [
    {
      name: 'typescript',
      cmd: 'npx',
      args: (input) => ['tsx', join(toolsDir, 'ts-sdk-tool.ts'), input],
    },
    {
      name: 'go',
      cmd: 'go',
      args: (input) => ['run', join(toolsDir, 'go-sdk-tool.go'), input],
    },
    {
      name: 'python',
      cmd: 'python3',
      args: (input) => [join(toolsDir, 'py-sdk-tool.py'), input],
      env: { PYTHONPATH: join(ROOT, 'packages', 'runar-py') },
    },
    {
      name: 'ruby',
      cmd: 'ruby',
      args: (input) => [join(toolsDir, 'rb-sdk-tool.rb'), input],
    },
  ];

  // Rust: prefer pre-built binary, fall back to cargo run
  const rsBin = join(toolsDir, 'rs-sdk-tool', 'target', 'release', 'rs-sdk-tool');
  if (isExecutable(rsBin)) {
    tools.push({
      name: 'rust',
      cmd: rsBin,
      args: (input) => [input],
    });
  } else {
    tools.push({
      name: 'rust',
      cmd: 'cargo',
      args: (input) => [
        'run', '--release',
        '--manifest-path', join(toolsDir, 'rs-sdk-tool', 'Cargo.toml'),
        '--', input,
      ],
    });
  }

  // Zig: prefer pre-built binary, fall back to zig build + run
  const zigBin = join(toolsDir, 'zig-sdk-tool', 'zig-out', 'bin', 'zig-sdk-tool');
  if (isExecutable(zigBin)) {
    tools.push({
      name: 'zig',
      cmd: zigBin,
      args: (input) => [input],
    });
  } else {
    const zigToolDir = join(toolsDir, 'zig-sdk-tool');
    tools.push({
      name: 'zig',
      cmd: zigBin,
      args: (input) => [input],
      preBuild: () => {
        execFileSync('zig', ['build'], {
          cwd: zigToolDir,
          stdio: 'pipe',
          timeout: 120_000,
        });
      },
    });
  }

  return tools;
}

function runSdkTool(tool: SdkTool, inputPath: string): SdkResult {
  const start = Date.now();
  try {
    if (tool.preBuild) {
      tool.preBuild();
      tool.preBuild = undefined;
    }
    const toolArgs = tool.args(inputPath);
    const env = { ...process.env, ...tool.env };
    const output = execFileSync(tool.cmd, toolArgs, {
      cwd: tool.cwd ?? ROOT,
      timeout: 30_000,
      maxBuffer: 10 * 1024 * 1024,
      env,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    return {
      sdk: tool.name,
      hex: output.toString().trim().toLowerCase(),
      success: true,
      durationMs: Date.now() - start,
    };
  } catch (err: unknown) {
    const e = err as { stderr?: Buffer; message?: string };
    return {
      sdk: tool.name,
      hex: '',
      success: false,
      error: e.stderr?.toString().slice(0, 500) || e.message || 'unknown error',
      durationMs: Date.now() - start,
    };
  }
}

function runTest(testDir: string, tools: SdkTool[]): TestResult {
  const testName = testDir.split('/').pop()!;
  const inputPath = join(testDir, 'input.json');
  const goldenPath = join(testDir, 'expected-locking.hex');

  const sdkResults = tools.map((tool) => runSdkTool(tool, inputPath));
  const errors: string[] = [];

  for (const r of sdkResults) {
    if (!r.success) {
      errors.push(`${r.sdk}: FAILED - ${r.error}`);
    }
  }

  const successful = sdkResults.filter((r) => r.success);
  let allMatch = true;
  if (successful.length >= 2) {
    const reference = successful[0]!.hex;
    for (let i = 1; i < successful.length; i++) {
      if (successful[i]!.hex !== reference) {
        allMatch = false;
        errors.push(
          `MISMATCH: ${successful[0]!.sdk} vs ${successful[i]!.sdk}` +
          ` (${reference.slice(0, 40)}... vs ${successful[i]!.hex.slice(0, 40)}...)`,
        );
      }
    }
  } else if (successful.length < 2) {
    allMatch = false;
  }

  let goldenMatch = true;
  if (existsSync(goldenPath)) {
    const golden = readFileSync(goldenPath, 'utf-8').trim().toLowerCase();
    for (const r of successful) {
      if (r.hex !== golden) {
        goldenMatch = false;
        errors.push(`${r.sdk}: does not match golden file`);
      }
    }
  } else {
    goldenMatch = false;
    errors.push('No expected-locking.hex golden file found');
  }

  return { testName, sdkResults, allMatch, goldenMatch, errors };
}

function parseArgs(argv: string[]): {
  testsDir: string;
  filter?: string;
  format: 'console' | 'json' | 'markdown';
  output?: string;
  updateGolden: boolean;
} {
  const args = argv.slice(2);
  let testsDir = join(ROOT, 'conformance', 'sdk-output', 'tests');
  let filter: string | undefined;
  let format: 'console' | 'json' | 'markdown' = 'console';
  let output: string | undefined;
  let updateGolden = false;

  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case '--tests-dir':
        testsDir = resolve(args[++i]!);
        break;
      case '--filter':
        filter = args[++i];
        break;
      case '--format':
        format = args[++i] as 'console' | 'json' | 'markdown';
        break;
      case '--output':
        output = args[++i];
        break;
      case '--update-golden':
        updateGolden = true;
        break;
    }
  }

  return { testsDir, filter, format, output, updateGolden };
}

function main(): void {
  const opts = parseArgs(process.argv);
  const tools = buildSdkTools();

  let testDirs = readdirSync(opts.testsDir, { withFileTypes: true })
    .filter((d) => d.isDirectory())
    .map((d) => join(opts.testsDir, d.name))
    .filter((d) => existsSync(join(d, 'input.json')));

  if (opts.filter) {
    testDirs = testDirs.filter((d) => d.includes(opts.filter!));
  }

  console.log(`Running SDK output conformance: ${testDirs.length} tests x ${tools.length} SDKs\n`);

  const results: TestResult[] = [];
  let anyFail = false;

  for (const dir of testDirs) {
    const result = runTest(dir, tools);
    results.push(result);

    if (!result.allMatch || !result.goldenMatch || result.errors.length > 0) {
      anyFail = true;
    }

    if (opts.format === 'console') {
      const status = result.allMatch && result.goldenMatch ? 'PASS' : 'FAIL';
      const icon = status === 'PASS' ? '+' : 'x';
      console.log(`[${icon}] ${result.testName}: ${status}`);
      for (const r of result.sdkResults) {
        const s = r.success ? `OK (${r.durationMs}ms)` : `FAIL: ${r.error}`;
        console.log(`    ${r.sdk}: ${s}`);
      }
      for (const e of result.errors) {
        console.log(`    ERROR: ${e}`);
      }
      console.log();
    }

    if (opts.updateGolden) {
      const tsResult = result.sdkResults.find((r) => r.sdk === 'typescript' && r.success);
      if (tsResult) {
        writeFileSync(join(dir, 'expected-locking.hex'), tsResult.hex + '\n');
        console.log(`  Updated golden: ${result.testName}/expected-locking.hex`);
      }
    }
  }

  if (opts.format === 'json') {
    const out = JSON.stringify(results, null, 2);
    if (opts.output) writeFileSync(opts.output, out);
    else console.log(out);
  } else if (opts.format === 'markdown') {
    let md = '# SDK Output Conformance Results\n\n';
    md += `| Test | ${tools.map((t) => t.name).join(' | ')} | Match |\n`;
    md += `|------|${tools.map(() => '---').join('|')}|-------|\n`;
    for (const r of results) {
      const cols = tools.map((t) => {
        const sr = r.sdkResults.find((s) => s.sdk === t.name);
        return sr?.success ? 'OK' : 'FAIL';
      });
      const match = r.allMatch && r.goldenMatch ? 'PASS' : 'FAIL';
      md += `| ${r.testName} | ${cols.join(' | ')} | ${match} |\n`;
    }
    if (opts.output) writeFileSync(opts.output, md);
    else console.log(md);
  }

  process.exit(anyFail ? 1 : 0);
}

main();
