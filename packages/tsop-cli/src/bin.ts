#!/usr/bin/env node
// ---------------------------------------------------------------------------
// tsop-cli/bin.ts — CLI entry point
// ---------------------------------------------------------------------------

import { program } from 'commander';
import { initCommand } from './commands/init.js';
import { compileCommand } from './commands/compile.js';
import { testCommand } from './commands/test.js';
import { deployCommand } from './commands/deploy.js';
import { verifyCommand } from './commands/verify.js';

program
  .name('tsop')
  .description('TSOP: TypeScript-to-Bitcoin Script compiler')
  .version('0.1.0');

program
  .command('init')
  .description('Initialize a new TSOP project')
  .argument('[name]', 'project name')
  .action(initCommand);

program
  .command('compile')
  .description('Compile TSOP contracts')
  .argument('<files...>', 'contract files to compile')
  .option('-o, --output <dir>', 'output directory', './artifacts')
  .option('--ir', 'include IR in artifact')
  .option('--asm', 'print ASM to stdout')
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

program.parse();
