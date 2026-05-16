// ---------------------------------------------------------------------------
// runar-cli/commands/compile.ts — Compile Rúnar contracts
// ---------------------------------------------------------------------------

import * as fs from 'node:fs';
import * as path from 'node:path';
import { pathToFileURL } from 'node:url';

interface CompileOptions {
  output: string;
  ir?: boolean;
  asm?: boolean;
  disableConstantFolding?: boolean;
  fromIr?: string;
  hex?: boolean;
  parseOnly?: boolean;
}

interface CompilerDiagnosticLike {
  severity?: string;
  message?: string;
}

interface CompileResultLike {
  success: boolean;
  diagnostics?: CompilerDiagnosticLike[];
  anf?: unknown;
  artifact?: Record<string, unknown>;
}

function jsonWithBigInt(value: unknown): string {
  return JSON.stringify(
    value,
    (_key, v) => {
      if (typeof v === 'bigint') {
        return `${v}n`;
      }
      return v;
    },
    2,
  );
}

/**
 * Compile one or more Rúnar contract source files into artifact JSON.
 *
 * For each input file:
 * 1. Read the TypeScript source.
 * 2. Invoke the compiler pipeline (runar-compiler).
 * 3. Write the resulting artifact JSON to the output directory.
 * 4. Optionally print the ASM to stdout.
 */
export async function compileCommand(
  files: string[],
  options: CompileOptions,
): Promise<void> {
  const outputDir = path.resolve(process.cwd(), options.output);
  fs.mkdirSync(outputDir, { recursive: true });

  // Dynamically import the compiler to avoid hard failures if it's not
  // yet fully built (the compiler package may still be under development).
  type CompileFn = (source: string, options?: { fileName?: string; disableConstantFolding?: boolean; parseOnly?: boolean }) => unknown;
  type CompileFromANFFn = (
    program: unknown,
    options?: { disableConstantFolding?: boolean },
  ) => { scriptHex: string; scriptAsm: string };
  type LoadANFFn = (json: string) => unknown;

  let compile: CompileFn | null = null;
  let compileFromANF: CompileFromANFFn | null = null;
  let loadANFFromJSON: LoadANFFn | null = null;
  try {
    // In monorepo/dev mode, prefer the source entry so conformance and CLI
    // runs always reflect the latest compiler implementation.
    const sourceEntry = path.resolve(process.cwd(), 'packages/runar-compiler/src/index.ts');
    if (fs.existsSync(sourceEntry)) {
      const compiler = (await import(pathToFileURL(sourceEntry).href)) as Record<string, unknown>;
      if (typeof compiler.compile === 'function') {
        compile = compiler.compile as CompileFn;
      }
      if (typeof compiler.compileFromANF === 'function') {
        compileFromANF = compiler.compileFromANF as CompileFromANFFn;
      }
      if (typeof compiler.loadANFFromJSON === 'function') {
        loadANFFromJSON = compiler.loadANFFromJSON as LoadANFFn;
      }
    }

    // Fallback for packaged/non-monorepo usage.
    if (!compile) {
      const moduleName = 'runar-compiler';
      const compiler = (await import(moduleName)) as Record<string, unknown>;
      if (typeof compiler.compile === 'function') {
        compile = compiler.compile as CompileFn;
      }
      if (!compileFromANF && typeof compiler.compileFromANF === 'function') {
        compileFromANF = compiler.compileFromANF as CompileFromANFFn;
      }
      if (!loadANFFromJSON && typeof compiler.loadANFFromJSON === 'function') {
        loadANFFromJSON = compiler.loadANFFromJSON as LoadANFFn;
      }
    }
  } catch {
    // Compiler not available — will fall back to error message below
  }

  // --from-ir mode: compile a single ANF IR JSON file straight to a
  // locking script. Skips parse/validate/typecheck/anf-lower entirely.
  if (options.fromIr) {
    if (!compileFromANF || !loadANFFromJSON) {
      console.error(
        '  Error: runar-compiler does not expose compileFromANF / loadANFFromJSON. Ensure the package is built.',
      );
      process.exitCode = 1;
      return;
    }

    const irPath = path.resolve(process.cwd(), options.fromIr);
    let irJson: string;
    try {
      irJson = fs.readFileSync(irPath, 'utf-8');
    } catch (err) {
      console.error(`  Error reading IR file: ${(err as Error).message}`);
      process.exitCode = 1;
      return;
    }

    let program: unknown;
    try {
      program = loadANFFromJSON(irJson);
    } catch (err) {
      console.error(`  IR parse error: ${(err as Error).message}`);
      process.exitCode = 1;
      return;
    }

    let result: { scriptHex: string; scriptAsm: string };
    try {
      result = compileFromANF(program, { disableConstantFolding: options.disableConstantFolding });
    } catch (err) {
      console.error(`  Compilation error: ${(err as Error).message}`);
      process.exitCode = 1;
      return;
    }

    if (options.hex) {
      // Print only the hex on stdout; no other chatter so the output
      // can be piped into a hex-comparison harness.
      process.stdout.write(result.scriptHex + '\n');
      return;
    }

    const baseName = path.basename(irPath, path.extname(irPath));
    const minimalArtifact = {
      contractName: (program as { contractName?: string }).contractName ?? baseName,
      script: result.scriptHex,
      asm: result.scriptAsm,
    };
    const artifactPath = path.join(outputDir, `${baseName}.json`);
    fs.writeFileSync(artifactPath, JSON.stringify(minimalArtifact, null, 2) + '\n');
    console.log(`Compiling from IR: ${irPath}`);
    console.log(`  Artifact written: ${artifactPath}`);
    if (options.asm) {
      console.log('');
      console.log(`  ASM (${baseName}):`);
      console.log(`  ${result.scriptAsm}`);
      console.log('');
    }
    return;
  }

  // --parse-only requires source files. Bail out clearly so users don't
  // get the silent "0 succeeded, 0 failed" summary.
  if (options.parseOnly && files.length === 0) {
    console.error('  Error: --parse-only requires at least one source file.');
    process.exitCode = 1;
    return;
  }

  let successCount = 0;
  let errorCount = 0;

  for (const filePath of files) {
    const resolvedPath = path.resolve(process.cwd(), filePath);
    const baseName = path.basename(resolvedPath, path.extname(resolvedPath));

    if (!options.hex && !options.parseOnly) {
      console.log(`Compiling: ${resolvedPath}`);
    }

    // Read source
    let source: string;
    try {
      source = fs.readFileSync(resolvedPath, 'utf-8');
    } catch (err) {
      console.error(`  Error reading file: ${(err as Error).message}`);
      errorCount++;
      continue;
    }

    // Compile
    if (!compile) {
      console.error(
        '  Error: runar-compiler is not available. Ensure the package is built and installed.',
      );
      errorCount++;
      continue;
    }

    let compileResult: CompileResultLike;
    try {
      compileResult = compile(source, {
        fileName: resolvedPath,
        disableConstantFolding: options.disableConstantFolding,
        parseOnly: options.parseOnly,
      }) as CompileResultLike;
    } catch (err) {
      console.error(`  Compilation error: ${(err as Error).message}`);
      errorCount++;
      continue;
    }

    // --parse-only mode: success means parse + (early-exit) succeeded with
    // no error diagnostics. There is no artifact to write — emit the same
    // "parser ok" marker as the other 6 compilers' --parse-only mode so
    // tooling (conformance runner, etc.) can rely on a uniform contract.
    if (options.parseOnly) {
      if (!compileResult.success) {
        const errors = (compileResult.diagnostics ?? [])
          .filter(d => d.severity === 'error')
          .map(d => d.message)
          .filter((m): m is string => typeof m === 'string' && m.length > 0);
        if (errors.length > 0) {
          console.error(`  Parse failed:`);
          for (const msg of errors) {
            console.error(`    - ${msg}`);
          }
        } else {
          console.error('  Parse failed.');
        }
        errorCount++;
        continue;
      }
      process.stdout.write('parser ok\n');
      successCount++;
      continue;
    }

    if (!compileResult.success || !compileResult.artifact) {
      const errors = (compileResult.diagnostics ?? [])
        .filter(d => d.severity === 'error')
        .map(d => d.message)
        .filter((m): m is string => typeof m === 'string' && m.length > 0);

      if (errors.length > 0) {
        console.error(`  Compilation failed:`);
        for (const msg of errors) {
          console.error(`    - ${msg}`);
        }
      } else {
        console.error('  Compilation failed: no artifact produced.');
      }
      errorCount++;
      continue;
    }

    const artifact = { ...compileResult.artifact };
    if (options.ir && compileResult.anf) {
      artifact.ir = {
        ...(typeof artifact.ir === 'object' && artifact.ir !== null
          ? artifact.ir as Record<string, unknown>
          : {}),
        anf: compileResult.anf,
      };
    }

    // --hex mode: print only the script hex on stdout (no artifact file
    // written, no chatter). Matches the other 6 CLIs' --hex semantics for
    // source input and the --from-ir + --hex pipeline above.
    if (options.hex) {
      const scriptHex = artifact['script'];
      if (typeof scriptHex !== 'string') {
        console.error('  Error: artifact has no script hex.');
        errorCount++;
        continue;
      }
      process.stdout.write(scriptHex + '\n');
      successCount++;
      continue;
    }

    // Write artifact
    const artifactPath = path.join(outputDir, `${baseName}.json`);
    fs.writeFileSync(
      artifactPath,
      jsonWithBigInt(artifact) + '\n',
    );
    console.log(`  Artifact written: ${artifactPath}`);

    // Print ASM if requested
    if (options.asm && typeof artifact['asm'] === 'string') {
      console.log('');
      console.log(`  ASM (${baseName}):`);
      console.log(`  ${artifact['asm']}`);
      console.log('');
    }

    successCount++;
  }

  // --hex / --parse-only modes are piping-friendly; suppress the summary so
  // stdout stays a clean machine-readable line (matches --from-ir + --hex).
  if (!options.hex && !options.parseOnly) {
    console.log('');
    console.log(
      `Compilation complete: ${successCount} succeeded, ${errorCount} failed`,
    );
  }

  if (errorCount > 0) {
    process.exitCode = 1;
  }
}
