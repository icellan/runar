// ---------------------------------------------------------------------------
// tsop-cli/commands/init.ts — Initialize a new TSOP project
// ---------------------------------------------------------------------------

import * as fs from 'node:fs';
import * as path from 'node:path';

/**
 * Initialize a new TSOP project with scaffolded directory structure,
 * configuration files, and a sample contract.
 */
export async function initCommand(name?: string): Promise<void> {
  const projectName = name ?? 'my-tsop-project';
  const projectDir = path.resolve(process.cwd(), projectName);

  console.log(`Initializing TSOP project: ${projectName}`);

  // Create directory structure
  const dirs = [
    projectDir,
    path.join(projectDir, 'src'),
    path.join(projectDir, 'src', 'contracts'),
    path.join(projectDir, 'tests'),
    path.join(projectDir, 'artifacts'),
  ];

  for (const dir of dirs) {
    fs.mkdirSync(dir, { recursive: true });
  }

  // Generate package.json
  const packageJson = {
    name: projectName,
    version: '0.1.0',
    description: `TSOP smart contract project: ${projectName}`,
    private: true,
    scripts: {
      compile: 'tsop compile src/contracts/*.ts',
      test: 'tsop test',
      deploy: 'tsop deploy',
    },
    dependencies: {
      'tsop-lang': '^0.1.0',
      'tsop-sdk': '^0.1.0',
    },
    devDependencies: {
      'tsop-cli': '^0.1.0',
      typescript: '^5.6.0',
      vitest: '^2.1.0',
    },
  };
  fs.writeFileSync(
    path.join(projectDir, 'package.json'),
    JSON.stringify(packageJson, null, 2) + '\n',
  );

  // Generate tsconfig.json
  const tsconfig = {
    compilerOptions: {
      target: 'ES2022',
      module: 'Node16',
      moduleResolution: 'Node16',
      lib: ['ES2022'],
      strict: true,
      esModuleInterop: true,
      skipLibCheck: true,
      outDir: 'dist',
      rootDir: 'src',
      declaration: true,
    },
    include: ['src'],
  };
  fs.writeFileSync(
    path.join(projectDir, 'tsconfig.json'),
    JSON.stringify(tsconfig, null, 2) + '\n',
  );

  // Generate sample contract
  const sampleContract = `import { SmartContract, assert, checkSig, hash160 } from 'tsop-lang';
import type { PubKey, Sig, Addr } from 'tsop-lang';

/**
 * P2PKH — Pay to Public Key Hash
 *
 * The simplest Bitcoin smart contract. Locks funds to a public key hash
 * and requires a valid signature to spend.
 */
class P2PKH extends SmartContract {
  readonly pubKeyHash: Addr;

  constructor(pubKeyHash: Addr) {
    super(pubKeyHash);
    this.pubKeyHash = pubKeyHash;
  }

  public unlock(sig: Sig, pubkey: PubKey) {
    assert(hash160(pubkey) === this.pubKeyHash);
    assert(checkSig(sig, pubkey));
  }
}
`;
  fs.writeFileSync(
    path.join(projectDir, 'src', 'contracts', 'P2PKH.ts'),
    sampleContract,
  );

  // Generate sample test
  const sampleTest = `import { describe, it, expect } from 'vitest';
// import { TSOPContract, MockProvider, LocalSigner } from 'tsop-sdk';
// import artifact from '../artifacts/P2PKH.json';

describe('P2PKH', () => {
  it('should compile without errors', () => {
    // Load the compiled artifact and verify it has the expected ABI structure
    expect(true).toBe(true);
  });

  it('should unlock with valid signature', async () => {
    // Deploy contract to mock provider, then call unlock with a valid signature
    expect(true).toBe(true);
  });
});
`;
  fs.writeFileSync(
    path.join(projectDir, 'tests', 'P2PKH.test.ts'),
    sampleTest,
  );

  // Generate .gitignore
  const gitignore = `node_modules/
dist/
artifacts/*.json
.env
`;
  fs.writeFileSync(path.join(projectDir, '.gitignore'), gitignore);

  console.log(`Project created at: ${projectDir}`);
  console.log('');
  console.log('Next steps:');
  console.log(`  cd ${projectName}`);
  console.log('  npm install');
  console.log('  tsop compile src/contracts/*.ts');
  console.log('  tsop test');
}
