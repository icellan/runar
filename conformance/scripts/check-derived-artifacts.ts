/**
 * Derived-artifact freshness orchestrator.
 *
 * Each corpus below is produced from compiler output (or from a generator
 * whose input is compiler output). A codegen change that moves bytes can
 * leave the children internally consistent — and every per-corpus job
 * green — while they no longer describe the compiler. `sdk-output`'s
 * `--check` closed that hole for one corpus; this script is the same
 * gate for all of them.
 *
 * Usage (from repo root):
 *   npx tsx conformance/scripts/check-derived-artifacts.ts --check
 *   npx tsx conformance/scripts/check-derived-artifacts.ts --check --dry-run
 *   npx tsx conformance/scripts/check-derived-artifacts.ts --check --only analyzer,script-size
 */
import { spawnSync } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, '..', '..');

export interface Corpus {
  id: string;
  argv: string[];
}

/**
 * One row per derived corpus. `argv` is spawned with `process.execPath`
 * and the current process's loader flags (`process.execArgv`) so a
 * `tsx`-launched parent does not need a second package-manager lookup.
 * pnpm-filter entries keep their pnpm wrapper because those scripts are
 * workspace-root package.json commands, not tsx files.
 */
export const CORPORA: Corpus[] = [
  {
    id: 'analyzer',
    argv: ['conformance/analyzer/scripts/generate-goldens.ts', '--check'],
  },
  {
    id: 'sdk-output',
    argv: ['conformance/sdk-output/generate-inputs.ts', '--check'],
  },
  {
    id: 'source-map',
    argv: ['conformance/source-map/run.ts'],
  },
  {
    id: 'decompiler-templates',
    argv: ['pnpm', 'run', 'decompiler:templates:check'],
  },
  {
    id: 'decompiler-coverage',
    argv: ['pnpm', '--filter', 'runar-decompiler', 'run', 'coverage', '--', '--check'],
  },
  {
    id: 'script-size',
    argv: ['conformance/runner/script-size-check.ts'],
  },
];

const TSX_CORPORA = new Set([
  'analyzer',
  'sdk-output',
  'source-map',
  'script-size',
]);

function parseArgs(argv: string[]): { dryRun: boolean; only: string[] | null } {
  let dryRun = false;
  let only: string[] | null = null;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === '--dry-run') dryRun = true;
    else if (a === '--only' && i + 1 < argv.length) {
      only = argv[++i]!.split(',').map((s) => s.trim()).filter(Boolean);
    } else if (a === '--check') {
      // default mode; accepted so callers can spell `--check` explicitly
    } else if (a === '--help' || a === '-h') {
      console.log(
        'Usage: check-derived-artifacts.ts [--check] [--dry-run] [--only a,b]',
      );
      console.log(`Corpora: ${CORPORA.map((c) => c.id).join(', ')}`);
      process.exit(0);
    } else {
      console.error(`unknown argument: ${a}`);
      process.exit(1);
    }
  }
  return { dryRun, only };
}

function runCorpus(c: Corpus): { status: number; out: string } {
  const isTsx = TSX_CORPORA.has(c.id);
  const file = isTsx ? process.execPath : c.argv[0]!;
  const args = isTsx
    ? [...process.execArgv, ...c.argv]
    : c.argv.slice(1);
  const r = spawnSync(file, args, {
    cwd: ROOT,
    encoding: 'utf8',
    env: process.env,
  });
  return { status: r.status ?? 1, out: `${r.stdout ?? ''}${r.stderr ?? ''}` };
}

function main(): void {
  const args = parseArgs(process.argv.slice(2));
  const known = new Set(CORPORA.map((c) => c.id));
  if (args.only) {
    const unknown = args.only.filter((id) => !known.has(id));
    if (unknown.length > 0) {
      console.error(`unknown corpus: ${unknown.join(', ')}`);
      console.error(`known: ${[...known].join(', ')}`);
      process.exit(1);
    }
  }
  const selected = args.only
    ? CORPORA.filter((c) => args.only!.includes(c.id))
    : CORPORA;

  if (args.dryRun) {
    for (const c of selected) {
      console.log(`${c.id}: ${c.argv.join(' ')}`);
    }
    return;
  }

  const failed: string[] = [];
  for (const c of selected) {
    console.log(`\n== ${c.id} ==`);
    const r = runCorpus(c);
    if (r.out) process.stdout.write(r.out);
    if (r.status !== 0) {
      console.error(`[${c.id}] failed (exit ${r.status})`);
      failed.push(c.id);
    } else {
      console.log(`[${c.id}] ok`);
    }
  }

  if (failed.length > 0) {
    console.error(`\nderived-artifact --check failed: ${failed.join(', ')}`);
    process.exit(1);
  }
  console.log(`\nderived-artifact --check: ${selected.length} corpus/corpora ok`);
}

main();
