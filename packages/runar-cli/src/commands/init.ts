// ---------------------------------------------------------------------------
// runar-cli/commands/init.ts — Initialize a new Rúnar project
// ---------------------------------------------------------------------------

import * as fs from 'node:fs';
import * as path from 'node:path';

type Lang = 'ts' | 'zig' | 'go' | 'rust' | 'python' | 'ruby';

const SUPPORTED_LANGS: readonly Lang[] = ['ts', 'zig', 'go', 'rust', 'python', 'ruby'] as const;

interface InitOptions {
  lang: Lang;
}

/**
 * Initialize a new Rúnar project with scaffolded directory structure,
 * configuration files, and a sample contract.
 */
export async function initCommand(name: string | undefined, options: InitOptions): Promise<void> {
  const lang = options.lang;
  if (!SUPPORTED_LANGS.includes(lang)) {
    console.error(`Unsupported language: ${lang}. Supported: ${SUPPORTED_LANGS.join(', ')}`);
    process.exitCode = 1;
    return;
  }

  const projectName = name ?? 'my-runar-project';
  const projectDir = path.resolve(process.cwd(), projectName);

  console.log(`Initializing Rúnar project: ${projectName} (${lang})`);

  if (lang === 'zig') {
    scaffoldZig(projectDir, projectName);
    return;
  }
  if (lang === 'go') {
    scaffoldGo(projectDir, projectName);
    return;
  }
  if (lang === 'rust') {
    scaffoldRust(projectDir, projectName);
    return;
  }
  if (lang === 'python') {
    scaffoldPython(projectDir, projectName);
    return;
  }
  if (lang === 'ruby') {
    scaffoldRuby(projectDir, projectName);
    return;
  }

  // Create directory structure. Matches the documented reference layout
  // in `runar-tic-tac-toe` (single root package.json, namespaced scripts,
  // artifact output under `contract/artifacts/`).
  const dirs = [
    projectDir,
    path.join(projectDir, 'contract'),
    path.join(projectDir, 'contract', 'artifacts'),
    path.join(projectDir, 'contract', 'integration'),
    path.join(projectDir, 'src'),
    path.join(projectDir, 'src', 'generated'),
  ];

  for (const dir of dirs) {
    fs.mkdirSync(dir, { recursive: true });
  }

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
  // contract/integration/vitest.config.ts
  // -------------------------------------------------------------------------
  fs.writeFileSync(
    path.join(projectDir, 'contract', 'integration', 'vitest.config.ts'),
    `import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    testTimeout: 60_000,
  },
});
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
  // Single root package.json. Namespaced scripts (`contract:test`,
  // `contract:compile`, `codegen`, etc.) keep the project to one
  // `npm install`, one `node_modules`, one lockfile. Matches the
  // documented reference layout in `runar-tic-tac-toe`.
  // -------------------------------------------------------------------------
  const rootPackageJson = {
    name: projectName,
    version: '0.1.0',
    description: `Rúnar smart contract project: ${projectName}`,
    private: true,
    type: 'module',
    scripts: {
      'contract:compile': 'cd contract && runar compile P2PKH.runar.ts -o artifacts',
      'contract:test': 'cd contract && vitest run',
      'contract:test:watch': 'cd contract && vitest',
      'contract:test:integration': 'cd contract/integration && vitest run',
      'contract:typecheck': 'cd contract && tsc --noEmit',
      'contract:debug': 'cd contract && runar debug artifacts/P2PKH.runar.json',
      codegen:
        'npm run contract:compile && runar codegen contract/artifacts/P2PKH.runar.json -o src/generated/ --lang ts',
      build: 'npm run codegen',
      test: 'npm run contract:test',
    },
    dependencies: {
      '@bsv/sdk': '^2.0.7',
      'runar-lang': '^0.5.0',
      'runar-sdk': '^0.5.0',
    },
    devDependencies: {
      'runar-cli': '^0.5.0',
      'runar-compiler': '^0.5.0',
      'runar-ir-schema': '^0.5.0',
      'runar-testing': '^0.5.0',
      typescript: '^5.6.0',
      vitest: '^2.1.0',
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
contract/artifacts/
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
package.json            Single root install — namespaced scripts (no per-subdir npm install)
contract/
  P2PKH.runar.ts        Smart contract source
  P2PKH.test.ts         Unit tests (vitest + TestContract)
  artifacts/            Compiled artifact JSON (gitignored, produced by \`contract:compile\`)
  integration/          On-chain regtest tests
src/
  generated/            Codegen output (typed wrapper) — gitignored
\`\`\`

## Getting Started

### 1. Install

\`\`\`bash
npm install
\`\`\`

One install at the root covers contract, tests, codegen, and integration tests.

### 2. Run contract unit tests

\`\`\`bash
npm run contract:test
\`\`\`

Runs the contract through the \`TestContract\` interpreter with mocked crypto.
No blockchain needed — fast feedback during development.

### 3. Compile the contract

\`\`\`bash
npm run contract:compile
\`\`\`

Produces \`contract/artifacts/P2PKH.runar.json\` — the compiled artifact
containing the Bitcoin Script, ABI, state fields, and constructor slots.

### 4. Generate the typed wrapper

\`\`\`bash
npm run codegen
\`\`\`

Compiles the contract and regenerates \`src/generated/P2PKHContract.ts\` — the
typed client wrapper your application code imports.

### 5. Debug contract execution (optional)

\`\`\`bash
npm run contract:debug
\`\`\`

Step through the compiled Bitcoin Script opcode-by-opcode with source mapping.

## Workflow

### Develop the contract

\`\`\`bash
npm run contract:test          # run unit tests
npm run contract:test:watch    # watch mode
npm run contract:typecheck     # type-check contract + tests
npm run contract:compile       # compile to artifact
npm run contract:debug         # step through Bitcoin Script
\`\`\`

### Integration test against regtest (optional)

Once unit tests pass, test on-chain behavior against a local regtest node.

\`\`\`bash
npm run contract:test:integration
\`\`\`

Deploys the contract to regtest, calls methods, and verifies on-chain state.
Requires a running BSV regtest node.

### Build the typed wrapper

\`\`\`bash
npm run build
\`\`\`

Runs \`contract:compile\` then \`codegen\`, producing:
- \`contract/artifacts/P2PKH.runar.json\` — compiled artifact
- \`src/generated/P2PKHContract.ts\` — typed wrapper class

### Use the wrapper in your application

\`\`\`typescript
import { P2PKHContract } from './generated/P2PKHContract.js';
import artifact from '../contract/artifacts/P2PKH.runar.json' with { type: 'json' };

const contract = new P2PKHContract(artifact, { pubKeyHash: '...' });
contract.connect(provider, signer);
await contract.deploy({ satoshis: 1000 });
\`\`\`

### Deploy to mainnet

\`\`\`typescript
import { WhatsOnChainProvider, LocalSigner } from 'runar-sdk';

const provider = new WhatsOnChainProvider('mainnet');
const signer = new LocalSigner(privateKey);
contract.connect(provider, signer);
\`\`\`

## Available Scripts

| Script                            | Description                                |
|-----------------------------------|--------------------------------------------|
| \`npm run contract:compile\`         | Compile contract → \`contract/artifacts/\`     |
| \`npm run contract:test\`            | Run unit tests (interpreter, no chain)     |
| \`npm run contract:test:watch\`      | Unit tests in watch mode                   |
| \`npm run contract:test:integration\`| Integration tests (regtest, requires node) |
| \`npm run contract:typecheck\`       | Type-check contract and tests              |
| \`npm run contract:debug\`           | Step through compiled Bitcoin Script       |
| \`npm run codegen\`                  | Compile + generate typed wrapper           |
| \`npm run build\`                    | Alias for \`codegen\`                         |
| \`npm test\`                         | Alias for \`contract:test\`                   |
`;
  fs.writeFileSync(path.join(projectDir, 'README.md'), readme);

  // -------------------------------------------------------------------------
  // Done — print next steps
  // -------------------------------------------------------------------------
  console.log(`Project created at: ${projectDir}`);
  console.log('');
  console.log('Next steps:');
  console.log(`  cd ${projectName}`);
  console.log('  npm install');
  console.log('  npm run contract:test       # run contract unit tests');
  console.log('  npm run build               # compile + generate typed wrapper');
}

// ---------------------------------------------------------------------------
// Zig scaffolding
// ---------------------------------------------------------------------------

function scaffoldZig(projectDir: string, projectName: string): void {
  fs.mkdirSync(path.join(projectDir, 'src'), { recursive: true });

  fs.writeFileSync(path.join(projectDir, 'build.zig'), `const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const runar_dep = b.dependency("runar-zig", .{
        .target = target,
        .optimize = optimize,
    });
    const runar_module = runar_dep.module("runar");

    const tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/P2PKH_test.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    tests.root_module.addImport("runar", runar_module);

    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run contract tests");
    test_step.dependOn(&run_tests.step);
}
`);

  fs.writeFileSync(path.join(projectDir, 'build.zig.zon'), `.{
    .name = "${projectName}",
    .version = .{ 0, 1, 0 },
    .fingerprint = 0x0000000000000000,
    .dependencies = .{
        .@"runar-zig" = .{
            .url = "https://github.com/icellan/runar/archive/refs/heads/main.tar.gz",
            .lazy = true,
        },
    },
    .paths = .{ "build.zig", "build.zig.zon", "src" },
}
`);

  fs.writeFileSync(path.join(projectDir, 'src', 'P2PKH.runar.zig'), `const runar = @import("runar");

pub const P2PKH = struct {
    pub const Contract = runar.SmartContract;

    pubKeyHash: runar.Addr,

    pub fn init(pubKeyHash: runar.Addr) P2PKH {
        return .{ .pubKeyHash = pubKeyHash };
    }

    pub fn unlock(self: *const P2PKH, sig: runar.Sig, pubKey: runar.PubKey) void {
        runar.assert(runar.hash160(pubKey) == self.pubKeyHash);
        runar.assert(runar.checkSig(sig, pubKey));
    }
};
`);

  fs.writeFileSync(path.join(projectDir, 'src', 'P2PKH_test.zig'), `const std = @import("std");
const runar = @import("runar");

fn compileCheck(comptime basename: []const u8) !void {
    const result = try runar.compileCheckSource(
        std.testing.allocator,
        @embedFile(basename),
        basename,
    );
    defer result.deinit(std.testing.allocator);
    if (!result.ok()) {
        for (result.messages) |message| {
            std.debug.print("compile-check {s}: {s}\\n", .{ basename, message });
        }
        return error.CompileCheckFailed;
    }
}

test "compile-check P2PKH.runar.zig" {
    try compileCheck("P2PKH.runar.zig");
}
`);

  fs.writeFileSync(path.join(projectDir, '.gitignore'), `zig-out/
.zig-cache/
.zig-global-cache/
.zig-local-cache/
`);

  console.log(`Project created at: ${projectDir}`);
  console.log('');
  console.log('Next steps:');
  console.log(`  cd ${projectName}`);
  console.log('  zig build test              # run contract compile-check tests');
}

// ---------------------------------------------------------------------------
// Go scaffolding
// ---------------------------------------------------------------------------

function scaffoldGo(projectDir: string, projectName: string): void {
  fs.mkdirSync(projectDir, { recursive: true });

  fs.writeFileSync(path.join(projectDir, 'go.mod'), `module ${projectName}

go 1.22

require github.com/icellan/runar v0.0.0
`);

  fs.writeFileSync(path.join(projectDir, 'Counter.runar.go'), `package contract

import runar "github.com/icellan/runar/packages/runar-go"

// Counter is a minimal stateful contract.
//
// Because this struct embeds runar.StatefulSmartContract, the compiler
// injects checkPreimage on entry and state continuation on exit.
type Counter struct {
\truncar.StatefulSmartContract
\tCount runar.Bigint // no tag = mutable (stateful)
}

func (c *Counter) Increment() {
\tc.Count++
}

func (c *Counter) Decrement() {
\trunar.Assert(c.Count > 0)
\tc.Count--
}
`);

  fs.writeFileSync(path.join(projectDir, 'Counter_test.go'), `package contract

import (
\t"testing"
\trunar "github.com/icellan/runar/packages/runar-go"
)

func TestCounter_Increment(t *testing.T) {
\tc := &Counter{Count: 0}
\tc.Increment()
\tif c.Count != 1 {
\t\tt.Errorf("expected Count=1, got %d", c.Count)
\t}
}

func TestCounter_Compile(t *testing.T) {
\tif err := runar.CompileCheck("Counter.runar.go"); err != nil {
\t\tt.Fatalf("Runar compile check failed: %v", err)
\t}
}
`);

  fs.writeFileSync(path.join(projectDir, '.gitignore'), `*.exe
*.test
*.out
`);

  console.log(`Project created at: ${projectDir}`);
  console.log('');
  console.log('Next steps:');
  console.log(`  cd ${projectName}`);
  console.log('  go test ./...               # run contract + compile-check tests');
}

// ---------------------------------------------------------------------------
// Rust scaffolding
// ---------------------------------------------------------------------------

function scaffoldRust(projectDir: string, projectName: string): void {
  fs.mkdirSync(projectDir, { recursive: true });
  fs.mkdirSync(path.join(projectDir, 'tests'), { recursive: true });

  fs.writeFileSync(path.join(projectDir, 'Cargo.toml'), `[package]
name = "${projectName}"
version = "0.1.0"
edition = "2021"

[dependencies]
runar = { path = "../packages/runar-rs", package = "runar-rs" }

[[test]]
name = "counter_test"
path = "tests/Counter_test.rs"
`);

  fs.writeFileSync(path.join(projectDir, 'Counter.runar.rs'), `use runar::prelude::*;

/// Counter — a minimal stateful smart contract.
#[runar::contract]
pub struct Counter {
    pub count: Bigint,
}

impl Counter {
    pub fn increment(&mut self) {
        self.count += 1;
    }

    pub fn decrement(&mut self) {
        assert!(self.count > 0);
        self.count -= 1;
    }
}
`);

  fs.writeFileSync(path.join(projectDir, 'tests', 'Counter_test.rs'), `#[path = "../Counter.runar.rs"]
mod contract;

use contract::*;

#[test]
fn test_increment() {
    let mut c = Counter { count: 0 };
    c.increment();
    assert_eq!(c.count, 1);
}

#[test]
fn test_compile() {
    runar::compile_check(include_str!("../Counter.runar.rs"), "Counter.runar.rs").unwrap();
}
`);

  fs.writeFileSync(path.join(projectDir, '.gitignore'), `target/
Cargo.lock
`);

  console.log(`Project created at: ${projectDir}`);
  console.log('');
  console.log('Next steps:');
  console.log(`  cd ${projectName}`);
  console.log('  cargo test                  # run contract + compile-check tests');
}

// ---------------------------------------------------------------------------
// Python scaffolding
// ---------------------------------------------------------------------------

function scaffoldPython(projectDir: string, projectName: string): void {
  fs.mkdirSync(projectDir, { recursive: true });

  fs.writeFileSync(path.join(projectDir, 'Counter.runar.py'), `from runar import StatefulSmartContract, Bigint, public, assert_


class Counter(StatefulSmartContract):
    """Counter -- a minimal stateful smart contract."""

    count: Bigint  # mutable (stateful)

    def __init__(self, count: Bigint):
        super().__init__(count)
        self.count = count

    @public
    def increment(self):
        self.count += 1

    @public
    def decrement(self):
        assert_(self.count > 0)
        self.count -= 1
`);

  fs.writeFileSync(path.join(projectDir, 'test_counter.py'), `import importlib.util
from pathlib import Path


def load_contract(path: str):
    spec = importlib.util.spec_from_file_location("contract", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


contract_mod = load_contract(str(Path(__file__).parent / "Counter.runar.py"))
Counter = contract_mod.Counter


def test_increment():
    c = Counter(count=0)
    c.increment()
    assert c.count == 1


def test_compile():
    from runar import compile_check
    source_path = Path(__file__).parent / "Counter.runar.py"
    compile_check(source_path.read_text(), "Counter.runar.py")
`);

  fs.writeFileSync(path.join(projectDir, 'requirements.txt'), `# Point PYTHONPATH at packages/runar-py to import the runar module.
`);

  fs.writeFileSync(path.join(projectDir, '.gitignore'), `__pycache__/
*.pyc
.venv/
`);

  console.log(`Project created at: ${projectDir}`);
  console.log('');
  console.log('Next steps:');
  console.log(`  cd ${projectName}`);
  console.log('  PYTHONPATH=../packages/runar-py python3 -m pytest');
}

// ---------------------------------------------------------------------------
// Ruby scaffolding
// ---------------------------------------------------------------------------

function scaffoldRuby(projectDir: string, projectName: string): void {
  fs.mkdirSync(projectDir, { recursive: true });

  fs.writeFileSync(path.join(projectDir, 'Gemfile'), `source 'https://rubygems.org'

gem 'rspec'
# Uses the local runar-rb gem checkout.
gem 'runar', path: '../packages/runar-rb'
`);

  fs.writeFileSync(path.join(projectDir, 'Counter.runar.rb'), `require 'runar'

class Counter < Runar::StatefulSmartContract
  prop :count, Bigint

  def initialize(count)
    super(count)
    @count = count
  end

  runar_public
  def increment
    @count += 1
  end

  runar_public
  def decrement
    assert @count > 0
    @count -= 1
  end
end
`);

  fs.writeFileSync(path.join(projectDir, 'counter_spec.rb'), `# frozen_string_literal: true

require 'rspec'
require_relative 'Counter.runar'

RSpec.describe Counter do
  it 'increments' do
    c = Counter.new(0)
    c.increment
    expect(c.count).to eq(1)
  end

  it 'fails to decrement at zero' do
    c = Counter.new(0)
    expect { c.decrement }.to raise_error(RuntimeError)
  end
end
`);

  fs.writeFileSync(path.join(projectDir, '.gitignore'), `*.gem
.bundle/
vendor/bundle/
`);

  console.log(`Project created at: ${projectDir}`);
  console.log('');
  console.log('Next steps:');
  console.log(`  cd ${projectName}`);
  console.log('  bundle install');
  console.log('  bundle exec rspec counter_spec.rb');
}
