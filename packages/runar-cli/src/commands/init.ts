// ---------------------------------------------------------------------------
// runar-cli/commands/init.ts — Initialize a new Rúnar project
// ---------------------------------------------------------------------------

import * as fs from 'node:fs';
import * as path from 'node:path';

/**
 * Initialize a new Rúnar project with scaffolded directory structure,
 * configuration files, and a sample contract.
 */
export async function initCommand(name?: string): Promise<void> {
  const projectName = name ?? 'my-runar-project';
  const projectDir = path.resolve(process.cwd(), projectName);

  console.log(`Initializing Rúnar project: ${projectName}`);

  // Create directory structure
  const dirs = [
    projectDir,
    path.join(projectDir, 'contract'),
    path.join(projectDir, 'contract', 'integration'),
    path.join(projectDir, 'src'),
    path.join(projectDir, 'src', 'generated'),
  ];

  for (const dir of dirs) {
    fs.mkdirSync(dir, { recursive: true });
  }

  // -------------------------------------------------------------------------
  // contract/package.json
  // -------------------------------------------------------------------------
  const contractPackageJson = {
    name: `${projectName}-contract`,
    version: '0.1.0',
    private: true,
    type: 'module',
    scripts: {
      compile: 'runar compile P2PKH.runar.ts -o .',
      test: 'vitest run',
      'test:watch': 'vitest',
      typecheck: 'tsc --noEmit',
      debug: 'runar debug P2PKH.runar.json',
    },
    devDependencies: {
      'fast-check': '^3.22.0',
      'runar-cli': '^0.3.0',
      'runar-compiler': '^0.3.0',
      'runar-lang': '^0.3.0',
      'runar-testing': '^0.3.0',
      typescript: '^5.6.0',
      vitest: '^2.1.0',
    },
  };
  fs.writeFileSync(
    path.join(projectDir, 'contract', 'package.json'),
    JSON.stringify(contractPackageJson, null, 2) + '\n',
  );

  // -------------------------------------------------------------------------
  // contract/tsconfig.json
  // -------------------------------------------------------------------------
  const contractTsconfig = {
    compilerOptions: {
      target: 'ES2022',
      module: 'Node16',
      moduleResolution: 'Node16',
      lib: ['ES2022'],
      noEmit: true,
      strict: true,
      esModuleInterop: true,
      skipLibCheck: true,
    },
    include: ['**/*.runar.ts', '**/*.test.ts'],
  };
  fs.writeFileSync(
    path.join(projectDir, 'contract', 'tsconfig.json'),
    JSON.stringify(contractTsconfig, null, 2) + '\n',
  );

  // -------------------------------------------------------------------------
  // contract/vitest.config.ts
  // -------------------------------------------------------------------------
  fs.writeFileSync(
    path.join(projectDir, 'contract', 'vitest.config.ts'),
    `import { defineConfig } from 'vitest/config';

export default defineConfig({});
`,
  );

  // -------------------------------------------------------------------------
  // contract/P2PKH.runar.ts — sample contract
  // -------------------------------------------------------------------------
  const sampleContract = `import { SmartContract, assert, PubKey, Sig, Addr, hash160, checkSig } from 'runar-lang';

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

  public unlock(sig: Sig, pubKey: PubKey) {
    assert(hash160(pubKey) === this.pubKeyHash);
    assert(checkSig(sig, pubKey));
  }
}
`;
  fs.writeFileSync(
    path.join(projectDir, 'contract', 'P2PKH.runar.ts'),
    sampleContract,
  );

  // -------------------------------------------------------------------------
  // contract/P2PKH.test.ts — working unit test
  // -------------------------------------------------------------------------
  const sampleTest = `import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { compile } from 'runar-compiler';
import { TestContract, ALICE, signTestMessage } from 'runar-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'P2PKH.runar.ts'), 'utf8');

describe('P2PKH', () => {
  it('should compile without errors', () => {
    const result = compile(source, { fileName: 'P2PKH.runar.ts' });
    expect(result.success).toBe(true);
    expect(result.artifact).toBeDefined();
    expect(result.artifact!.contractName).toBe('P2PKH');
  });

  it('should have the correct ABI', () => {
    const result = compile(source, { fileName: 'P2PKH.runar.ts' });
    const methods = result.artifact!.abi.methods;
    expect(methods).toHaveLength(1);
    expect(methods[0]!.name).toBe('unlock');
    expect(methods[0]!.params).toHaveLength(2);
  });

  it('should produce valid Bitcoin Script', () => {
    const result = compile(source, { fileName: 'P2PKH.runar.ts' });
    expect(result.artifact!.script).toBeDefined();
    expect(result.artifact!.script.length).toBeGreaterThan(0);
  });

  it('should create a TestContract instance', () => {
    const contract = TestContract.fromSource(source, {
      pubKeyHash: ALICE.pubKeyHash,
    });
    expect(contract).toBeDefined();
    expect(contract.state.pubKeyHash).toBe(ALICE.pubKeyHash);
  });
});
`;
  fs.writeFileSync(
    path.join(projectDir, 'contract', 'P2PKH.test.ts'),
    sampleTest,
  );

  // -------------------------------------------------------------------------
  // contract/integration/package.json
  // -------------------------------------------------------------------------
  const integrationPackageJson = {
    name: `${projectName}-integration`,
    version: '0.1.0',
    private: true,
    type: 'module',
    scripts: {
      test: 'vitest run',
    },
    dependencies: {
      'runar-compiler': '^0.3.0',
      'runar-sdk': '^0.3.0',
      'runar-lang': '^0.3.0',
      'runar-ir-schema': '^0.3.0',
      '@bsv/sdk': '^2.0.7',
    },
    devDependencies: {
      vitest: '^2.1.0',
    },
  };
  fs.writeFileSync(
    path.join(projectDir, 'contract', 'integration', 'package.json'),
    JSON.stringify(integrationPackageJson, null, 2) + '\n',
  );

  // -------------------------------------------------------------------------
  // Root package.json
  // -------------------------------------------------------------------------
  const rootPackageJson = {
    name: projectName,
    version: '0.1.0',
    description: `Rúnar smart contract project: ${projectName}`,
    private: true,
    type: 'module',
    scripts: {
      compile: 'cd contract && npm run compile',
      codegen: 'runar codegen contract/*.runar.json -o src/generated/ --lang ts',
      build: 'npm run compile && npm run codegen',
      test: 'cd contract && npm test',
      'test:integration': 'cd contract/integration && npm test',
    },
    dependencies: {
      'runar-lang': '^0.3.0',
      'runar-sdk': '^0.3.0',
    },
    devDependencies: {
      'runar-cli': '^0.3.0',
      typescript: '^5.6.0',
    },
  };
  fs.writeFileSync(
    path.join(projectDir, 'package.json'),
    JSON.stringify(rootPackageJson, null, 2) + '\n',
  );

  // -------------------------------------------------------------------------
  // Root tsconfig.json
  // -------------------------------------------------------------------------
  const rootTsconfig = {
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
    JSON.stringify(rootTsconfig, null, 2) + '\n',
  );

  // -------------------------------------------------------------------------
  // .gitignore
  // -------------------------------------------------------------------------
  const gitignore = `node_modules/
dist/
src/generated/
contract/*.runar.json
.env
`;
  fs.writeFileSync(path.join(projectDir, '.gitignore'), gitignore);

  // -------------------------------------------------------------------------
  // README.md
  // -------------------------------------------------------------------------
  const readme = `# ${projectName}

A [Rúnar](https://github.com/icellan/runar) smart contract project.

## Project Structure

\`\`\`
contract/           Smart contract source, unit tests, and integration tests
src/generated/      Compiled artifacts and generated typed wrappers (auto-generated)
src/                Application source code
\`\`\`

## Getting Started

### 1. Install dependencies

\`\`\`bash
cd contract
npm install
cd ..
npm install
\`\`\`

### 2. Run contract unit tests

\`\`\`bash
cd contract
npm test
\`\`\`

This runs the contract through the TestContract interpreter with mocked crypto.
No blockchain needed — fast feedback during development.

### 3. Compile the contract

\`\`\`bash
cd contract
npm run compile
\`\`\`

This produces \`P2PKH.runar.json\` — the compiled artifact containing the
Bitcoin Script, ABI, state fields, and constructor slots.

### 4. Debug contract execution (optional)

\`\`\`bash
cd contract
npm run debug
\`\`\`

Step through the compiled Bitcoin Script opcode-by-opcode with source mapping.

## Workflow

### Phase 1: Develop the contract

Work entirely in \`contract/\`. Write your contract logic, run unit tests,
and iterate until the contract behaves correctly.

\`\`\`bash
cd contract
npm test              # run unit tests
npm run test:watch    # re-run on file changes
npm run typecheck     # verify types
npm run compile       # compile to artifact
npm run debug         # step through Bitcoin Script
\`\`\`

### Phase 2: Integration test against regtest (optional)

Once unit tests pass, test on-chain behavior against a local regtest node.

\`\`\`bash
cd contract/integration
npm install
npm test
\`\`\`

This deploys the contract to regtest, calls methods, and verifies
on-chain state. Requires a running BSV regtest node.

### Phase 3: Generate the typed wrapper

From the project root:

\`\`\`bash
npm run build
\`\`\`

This runs \`compile\` then \`codegen\`, producing:
- \`src/generated/P2PKH.runar.json\` — compiled artifact
- \`src/generated/P2PKHContract.ts\` — typed wrapper class

### Phase 4: Build your application

Import the generated wrapper in your application code:

\`\`\`typescript
import { P2PKHContract } from './generated/P2PKHContract.js';
import artifact from './generated/P2PKH.runar.json';

const contract = new P2PKHContract(artifact, { pubKeyHash: '...' });
contract.connect(provider, signer);
await contract.deploy({ satoshis: 1000 });
\`\`\`

The wrapper provides type-safe method stubs matching your contract's ABI.

### Phase 5: Deploy to mainnet

Configure a mainnet provider and signer, then deploy:

\`\`\`typescript
import { WhatsOnChainProvider, LocalSigner } from 'runar-sdk';

const provider = new WhatsOnChainProvider('mainnet');
const signer = new LocalSigner(privateKey);
contract.connect(provider, signer);
\`\`\`

## Available Scripts

### In \`contract/\`

| Script              | Description                              |
|---------------------|------------------------------------------|
| \`npm test\`          | Run unit tests                           |
| \`npm run test:watch\`| Run tests in watch mode                  |
| \`npm run compile\`   | Compile contract to artifact (.json)     |
| \`npm run typecheck\` | Type-check contract and tests            |
| \`npm run debug\`     | Debug compiled script step-by-step       |

### In project root

| Script                    | Description                            |
|---------------------------|----------------------------------------|
| \`npm run compile\`         | Compile contract (delegates to contract/) |
| \`npm run codegen\`         | Generate typed wrapper from artifact   |
| \`npm run build\`           | Compile + codegen                      |
| \`npm test\`                | Run contract unit tests                |
| \`npm run test:integration\`| Run integration tests (regtest)        |
`;
  fs.writeFileSync(path.join(projectDir, 'README.md'), readme);

  // -------------------------------------------------------------------------
  // Done — print next steps
  // -------------------------------------------------------------------------
  console.log(`Project created at: ${projectDir}`);
  console.log('');
  console.log('Next steps:');
  console.log(`  cd ${projectName}/contract`);
  console.log('  npm install');
  console.log('  npm test                    # run contract unit tests');
  console.log('  npm run compile             # compile to artifact');
  console.log('');
  console.log('Then from the project root:');
  console.log(`  cd ${projectName}`);
  console.log('  npm install');
  console.log('  npm run build               # compile + codegen');
}
