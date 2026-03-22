#!/usr/bin/env node
// ---------------------------------------------------------------------------
// runar-cli/bin.ts — CLI entry point
// ---------------------------------------------------------------------------

import { program } from 'commander';
import { initCommand } from './commands/init.js';
import { compileCommand } from './commands/compile.js';
import { testCommand } from './commands/test.js';
import { deployCommand } from './commands/deploy.js';
import { verifyCommand } from './commands/verify.js';
import { codegenCommand } from './commands/codegen.js';
import { debugCommand } from './commands/debug.js';

program
  .name('runar')
  .description('Rúnar: TypeScript-to-Bitcoin Script compiler')
  .version('0.1.0');

program
  .command('init')
  .description('Initialize a new Rúnar project')
  .argument('[name]', 'project name')
  .option('-l, --lang <lang>', 'project language (ts, zig)', 'ts')
  .action(initCommand);

program
  .command('compile')
  .description('Compile Rúnar contracts')
  .argument('<files...>', 'contract files to compile')
  .option('-o, --output <dir>', 'output directory', './artifacts')
  .option('--ir', 'include IR in artifact')
  .option('--asm', 'print ASM to stdout')
  .option('--disable-constant-folding', 'disable ANF constant folding pass')
  .action(compileCommand);

program
  .command('test')
  .description('Run contract tests')
  .argument('[pattern]', 'test file pattern')
  .action(testCommand);

program
  .command('deploy')
  .description('Deploy a compiled contract')
  .argument('<artifact>', 'path to compiled artifact JSON')
  .requiredOption('--network <network>', 'network (mainnet/testnet)')
  .requiredOption('--key <key>', 'private key (WIF format)')
  .option('--satoshis <n>', 'satoshis to lock', '10000')
  .action(deployCommand);

program
  .command('verify')
  .description('Verify a deployed contract')
  .argument('<txid>', 'deployment transaction ID')
  .requiredOption('--artifact <path>', 'path to artifact')
  .requiredOption('--network <network>', 'network')
  .action(verifyCommand);

program
  .command('codegen')
  .description('Generate typed contract wrappers from compiled artifacts')
  .argument('<artifacts...>', 'artifact JSON files (supports globs)')
  .option('-o, --output <dir>', 'output directory (default: same as artifact)')
  .option('-l, --lang <lang>', 'target language (ts)', 'ts')
  .action(codegenCommand);

program
  .command('debug')
  .description('Interactive step-through Bitcoin Script debugger')
  .argument('<artifact>', 'path to compiled artifact JSON (with sourceMap)')
  .option('-m, --method <name>', 'public method to invoke')
  .option('-a, --args <json>', 'method arguments as JSON object')
  .option('-u, --unlock <hex>', 'raw unlocking script hex (alternative to --method)')
  .option('-b, --break <loc>', 'initial breakpoint (opcode# or file:line)')
  .action(debugCommand);

program.parse();
