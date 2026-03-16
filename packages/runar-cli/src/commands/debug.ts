// ---------------------------------------------------------------------------
// runar-cli/commands/debug.ts — Interactive Bitcoin Script debugger
// ---------------------------------------------------------------------------

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as readline from 'node:readline';

interface DebugOptions {
  method?: string;
  args?: string;
  unlock?: string;
  break?: string;
}

interface ArtifactLike {
  contractName: string;
  script: string;
  asm: string;
  sourceMap?: { mappings: Array<{ opcodeIndex: number; sourceFile: string; line: number; column: number }> };
  abi: {
    constructor: { params: Array<{ name: string; type: string }> };
    methods: Array<{ name: string; params: Array<{ name: string; type: string }>; isPublic?: boolean }>;
  };
  stateFields?: Array<{ name: string; type: string; index: number }>;
}

interface Breakpoint {
  id: number;
  opcodeIndex?: number;
  file?: string;
  line?: number;
  description: string;
}

export async function debugCommand(artifactPath: string, options: DebugOptions): Promise<void> {
  // Load artifact
  const resolvedPath = path.resolve(artifactPath);
  if (!fs.existsSync(resolvedPath)) {
    console.error(`Error: artifact not found: ${resolvedPath}`);
    process.exit(1);
  }

  let artifact: ArtifactLike;
  try {
    const json = fs.readFileSync(resolvedPath, 'utf8');
    artifact = JSON.parse(json, (_key, value) => {
      if (typeof value === 'string' && value.endsWith('n') && /^\d+n$/.test(value)) {
        return BigInt(value.slice(0, -1));
      }
      return value;
    });
  } catch (err) {
    console.error(`Error: failed to parse artifact: ${(err as Error).message}`);
    process.exit(1);
  }

  // Build unlocking script
  let unlockingHex = '';
  if (options.unlock) {
    unlockingHex = options.unlock;
  } else if (options.method) {
    unlockingHex = buildUnlockingScript(artifact, options.method, options.args);
  }

  const lockingHex = artifact.script;
  if (!lockingHex) {
    console.error('Error: artifact has no compiled script.');
    process.exit(1);
  }

  // Import VM and source map resolver
  const { ScriptVM, SourceMapResolver, hexToBytes, bytesToHex } = await import('runar-testing');

  const vm = new ScriptVM();
  vm.loadHex(unlockingHex, lockingHex);

  // Source map
  const resolver = artifact.sourceMap
    ? new SourceMapResolver(artifact.sourceMap)
    : null;

  // Load source files for line display
  const sourceLines = new Map<string, string[]>();
  if (resolver && !resolver.isEmpty) {
    const artifactDir = path.dirname(resolvedPath);
    for (const file of resolver.sourceFiles) {
      const filePath = path.resolve(artifactDir, file);
      if (fs.existsSync(filePath)) {
        sourceLines.set(file, fs.readFileSync(filePath, 'utf8').split('\n'));
      }
    }
  }

  // Count opcodes in the script
  const scriptBytes = hexToBytes(lockingHex);
  let opcodeCount = 0;
  {
    let i = 0;
    while (i < scriptBytes.length) {
      const byte = scriptBytes[i]!;
      i++;
      opcodeCount++;
      if (byte >= 0x01 && byte <= 0x4b) i += byte;
      else if (byte === 0x4c && i < scriptBytes.length) { i += 1 + scriptBytes[i]!; }
      else if (byte === 0x4d && i + 1 < scriptBytes.length) { i += 2 + (scriptBytes[i]! | (scriptBytes[i + 1]! << 8)); }
      else if (byte === 0x4e && i + 3 < scriptBytes.length) { i += 4 + (scriptBytes[i]! | (scriptBytes[i + 1]! << 8) | (scriptBytes[i + 2]! << 16) | (scriptBytes[i + 3]! << 24)); }
    }
  }

  // Header
  const sourceFile = resolver?.sourceFiles[0] ?? '(unknown)';
  console.log('');
  console.log(`Runar Script Debugger v0.1.0`);
  console.log(`Contract: ${artifact.contractName} (${lockingHex.length / 2} bytes, ${opcodeCount} opcodes)`);
  if (options.method) console.log(`Method:   ${options.method}`);
  console.log(`Source:   ${sourceFile}`);
  console.log('');

  // Breakpoints
  const breakpoints: Breakpoint[] = [];
  let nextBreakpointId = 1;

  // Set initial breakpoint if provided
  if (options.break) {
    addBreakpoint(options.break, breakpoints, nextBreakpointId++, resolver);
  }

  // Execution history for backtrace
  const history: Array<{ offset: number; opcode: string; stackDepth: number }> = [];
  let opcodeCounter = 0;

  // Step and print current position
  function stepAndPrint(): boolean {
    if (vm.isComplete) {
      printCompletion();
      return false;
    }
    const result = vm.step();
    if (!result) {
      printCompletion();
      return false;
    }
    opcodeCounter++;
    history.push({ offset: result.offset, opcode: result.opcode, stackDepth: result.mainStack.length });

    printStep(result.offset, result.opcode, result.mainStack, result.context, result.error);

    if (result.error) {
      console.log(`\nScript failed: ${result.error}`);
      return false;
    }
    return true;
  }

  function printStep(offset: number, opcode: string, stack: Uint8Array[], context: string, error?: string) {
    const offsetStr = offset.toString(16).padStart(4, '0');
    const stackSummary = stack.length === 0 ? '[]' : `[${stack.map(s => formatStackItem(s, bytesToHex)).join(', ')}]`;
    const prefix = error ? 'ERR' : context === 'unlocking' ? 'UNL' : '   ';
    console.log(`${prefix} [${offsetStr}] ${opcode.padEnd(20)} stack: ${stackSummary}`);

    // Source location
    if (resolver) {
      const loc = resolver.resolve(opcodeCounter - 1);
      if (loc) {
        const lines = sourceLines.get(loc.file);
        const lineText = lines ? lines[loc.line - 1]?.trimEnd() : '';
        console.log(`       ${loc.file}:${loc.line}  ${lineText}`);
      }
    }
  }

  function printCompletion() {
    if (vm.isComplete) {
      const stack = vm.currentStack;
      if (vm.isSuccess) {
        console.log(`\nScript completed successfully.`);
      } else {
        console.log(`\nScript failed.`);
      }
      if (stack.length > 0) {
        console.log(`Final stack: [${stack.map(s => formatStackItem(s, bytesToHex)).join(', ')}]`);
      } else {
        console.log('Final stack: (empty)');
      }
    }
  }

  function printStack(stack: Uint8Array[], label: string) {
    if (stack.length === 0) {
      console.log(`${label} (empty)`);
      return;
    }
    console.log(`${label} (${stack.length} items, top first):`);
    for (let i = stack.length - 1; i >= 0; i--) {
      const item = stack[i]!;
      const hex = bytesToHex(item);
      const annotation = annotateStackItem(item);
      console.log(`  [${i}] ${hex || '(empty)'}${annotation ? `  ${annotation}` : ''}`);
    }
  }

  // REPL
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    prompt: '> ',
  });

  rl.prompt();

  rl.on('line', (line) => {
    const input = line.trim();
    if (!input) { rl.prompt(); return; }

    const [cmd, ...args] = input.split(/\s+/);
    const arg = args.join(' ');

    switch (cmd) {
      case 's':
      case 'step':
        stepAndPrint();
        break;

      case 'n':
      case 'next': {
        // Step until source line changes
        const startLoc = resolver?.resolve(opcodeCounter);
        const startLine = startLoc?.line ?? -1;
        let stepped = false;
        while (!vm.isComplete) {
          if (!stepAndPrint()) break;
          stepped = true;
          const curLoc = resolver?.resolve(opcodeCounter);
          if (curLoc && curLoc.line !== startLine) break;
          if (!resolver) break; // No source map — behave like step
        }
        if (!stepped && vm.isComplete) printCompletion();
        break;
      }

      case 'c':
      case 'continue': {
        while (!vm.isComplete) {
          const result = vm.step();
          if (!result) { printCompletion(); break; }
          opcodeCounter++;
          history.push({ offset: result.offset, opcode: result.opcode, stackDepth: result.mainStack.length });

          // Check breakpoints
          const hitBp = breakpoints.find(bp => {
            if (bp.opcodeIndex !== undefined && bp.opcodeIndex === opcodeCounter - 1) return true;
            if (bp.file && bp.line && resolver) {
              const loc = resolver.resolve(opcodeCounter - 1);
              return loc?.file === bp.file && loc?.line === bp.line;
            }
            return false;
          });

          if (hitBp) {
            console.log(`Hit breakpoint ${hitBp.id} — ${hitBp.description}`);
            printStep(result.offset, result.opcode, result.mainStack, result.context, result.error);
            break;
          }

          if (result.error) {
            printStep(result.offset, result.opcode, result.mainStack, result.context, result.error);
            console.log(`\nScript failed: ${result.error}`);
            break;
          }
        }
        if (vm.isComplete) printCompletion();
        break;
      }

      case 'st':
      case 'stack':
        printStack(vm.currentStack, 'Main stack');
        break;

      case 'as':
      case 'altstack':
        printStack(vm.currentAltStack, 'Alt stack');
        break;

      case 'b':
      case 'break':
        if (!arg) {
          console.log('Usage: break <offset> or break <file>:<line>');
        } else {
          addBreakpoint(arg, breakpoints, nextBreakpointId++, resolver);
        }
        break;

      case 'd':
      case 'delete': {
        const bpId = parseInt(arg);
        const idx = breakpoints.findIndex(bp => bp.id === bpId);
        if (idx === -1) {
          console.log(`No breakpoint #${bpId}`);
        } else {
          breakpoints.splice(idx, 1);
          console.log(`Deleted breakpoint #${bpId}`);
        }
        break;
      }

      case 'i':
      case 'info': {
        console.log(`PC: ${vm.pc} (byte offset in ${vm.context} script)`);
        console.log(`Opcodes executed: ${opcodeCounter}`);
        console.log(`Complete: ${vm.isComplete}`);
        if (vm.isComplete) console.log(`Success: ${vm.isSuccess}`);
        if (breakpoints.length > 0) {
          console.log(`Breakpoints:`);
          for (const bp of breakpoints) {
            console.log(`  #${bp.id}: ${bp.description}`);
          }
        }
        if (resolver) {
          const loc = resolver.resolve(opcodeCounter);
          if (loc) {
            const lines = sourceLines.get(loc.file);
            const lineText = lines ? lines[loc.line - 1]?.trimEnd() : '';
            console.log(`Source: ${loc.file}:${loc.line}  ${lineText}`);
          }
        }
        break;
      }

      case 'bt':
      case 'backtrace': {
        const n = parseInt(arg) || 10;
        const start = Math.max(0, history.length - n);
        console.log(`Last ${history.length - start} opcodes:`);
        for (let i = start; i < history.length; i++) {
          const h = history[i]!;
          console.log(`  [${h.offset.toString(16).padStart(4, '0')}] ${h.opcode.padEnd(20)} stack depth: ${h.stackDepth}`);
        }
        break;
      }

      case 'r':
      case 'run':
        vm.loadHex(unlockingHex, lockingHex);
        opcodeCounter = 0;
        history.length = 0;
        console.log('Restarted.');
        break;

      case 'q':
      case 'quit':
        rl.close();
        return;

      case 'h':
      case 'help':
        printHelp();
        break;

      default:
        console.log(`Unknown command: ${cmd}. Type 'help' for available commands.`);
    }

    rl.prompt();
  });

  rl.on('close', () => {
    process.exit(0);
  });
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function buildUnlockingScript(
  artifact: ArtifactLike,
  methodName: string,
  argsJson?: string,
): string {
  const method = artifact.abi.methods.find(m => m.name === methodName && m.isPublic !== false);
  if (!method) {
    console.error(`Error: public method '${methodName}' not found in artifact.`);
    console.error(`Available methods: ${artifact.abi.methods.filter(m => m.isPublic !== false).map(m => m.name).join(', ')}`);
    process.exit(1);
  }

  // Parse args JSON
  let args: Record<string, unknown> = {};
  if (argsJson) {
    try {
      args = JSON.parse(argsJson);
    } catch (err) {
      console.error(`Error: invalid JSON for --args: ${(err as Error).message}`);
      process.exit(1);
    }
  }

  // For now, build a minimal unlocking script from the args
  // This is a simplified version — real unlocking scripts need proper encoding
  let hex = '';
  for (const param of method.params) {
    const value = args[param.name];
    if (value === undefined || value === null) {
      hex += '00'; // OP_0 placeholder (for Sig, SigHashPreimage, etc.)
      continue;
    }
    if (typeof value === 'boolean') {
      hex += value ? '51' : '00';
    } else if (typeof value === 'number' || typeof value === 'bigint') {
      hex += encodeScriptNumber(BigInt(value));
    } else if (typeof value === 'string') {
      hex += encodePushData(value);
    }
  }

  // Method selector for multi-method contracts
  const publicMethods = artifact.abi.methods.filter(m => m.isPublic !== false);
  if (publicMethods.length > 1) {
    const methodIndex = publicMethods.findIndex(m => m.name === methodName);
    hex += encodeScriptNumber(BigInt(methodIndex));
  }

  return hex;
}

function encodeScriptNumber(n: bigint): string {
  if (n === 0n) return '00';
  if (n >= 1n && n <= 16n) return (0x50 + Number(n)).toString(16);
  if (n === -1n) return '4f';

  const negative = n < 0n;
  let absVal = negative ? -n : n;
  const bytes: number[] = [];
  while (absVal > 0n) {
    bytes.push(Number(absVal & 0xffn));
    absVal >>= 8n;
  }
  if ((bytes[bytes.length - 1]! & 0x80) !== 0) {
    bytes.push(negative ? 0x80 : 0x00);
  } else if (negative) {
    bytes[bytes.length - 1]! |= 0x80;
  }
  const hex = bytes.map(b => b.toString(16).padStart(2, '0')).join('');
  return encodePushData(hex);
}

function encodePushData(dataHex: string): string {
  if (dataHex.length === 0) return '00';
  const len = dataHex.length / 2;
  if (len <= 75) return len.toString(16).padStart(2, '0') + dataHex;
  if (len <= 0xff) return '4c' + len.toString(16).padStart(2, '0') + dataHex;
  const lo = (len & 0xff).toString(16).padStart(2, '0');
  const hi = ((len >> 8) & 0xff).toString(16).padStart(2, '0');
  return '4d' + lo + hi + dataHex;
}

function addBreakpoint(
  spec: string,
  breakpoints: Breakpoint[],
  id: number,
  resolver: { reverseResolve(file: string, line: number): number[] } | null,
): void {
  if (spec.includes(':')) {
    const [file, lineStr] = spec.split(':');
    const line = parseInt(lineStr!);
    if (isNaN(line)) {
      console.log(`Invalid line number: ${lineStr}`);
      return;
    }
    const bp: Breakpoint = { id, file: file!, line, description: `${file}:${line}` };
    if (resolver) {
      const offsets = resolver.reverseResolve(file!, line);
      if (offsets.length > 0) {
        bp.opcodeIndex = offsets[0];
        bp.description += ` (opcode #${offsets[0]})`;
      }
    }
    breakpoints.push(bp);
    console.log(`Breakpoint ${id} at ${bp.description}`);
  } else {
    const offset = parseInt(spec, spec.startsWith('0x') ? 16 : 10);
    if (isNaN(offset)) {
      console.log(`Invalid offset: ${spec}`);
      return;
    }
    breakpoints.push({ id, opcodeIndex: offset, description: `opcode #${offset}` });
    console.log(`Breakpoint ${id} at opcode #${offset}`);
  }
}

function formatStackItem(item: Uint8Array, bytesToHex: (b: Uint8Array) => string): string {
  if (item.length === 0) return '0x';
  const hex = bytesToHex(item);
  if (hex.length <= 16) return '0x' + hex;
  return '0x' + hex.slice(0, 8) + '..' + hex.slice(-4);
}

function annotateStackItem(item: Uint8Array): string {
  if (item.length === 0) return 'false';
  if (item.length === 1 && item[0] === 1) return 'true';
  if (item.length === 33 && (item[0] === 0x02 || item[0] === 0x03)) return '(PubKey)';
  if (item.length === 20) return '(Ripemd160/Addr)';
  if (item.length === 32) return '(Sha256)';
  if (item.length === 64) return '(Point)';
  // Try to decode as script number
  if (item.length <= 8) {
    const negative = (item[item.length - 1]! & 0x80) !== 0;
    const bytes = [...item];
    bytes[bytes.length - 1]! &= 0x7f;
    let result = 0n;
    for (let i = bytes.length - 1; i >= 0; i--) {
      result = (result << 8n) | BigInt(bytes[i]!);
    }
    if (result !== 0n || item.length === 1) {
      return `${negative ? '-' : ''}${result}n`;
    }
  }
  return '';
}

function printHelp(): void {
  console.log(`
Commands:
  step    (s)   Execute one opcode
  next    (n)   Execute until source line changes
  continue (c)  Run until breakpoint or completion
  stack   (st)  Print main stack
  altstack (as) Print alt stack
  break   (b)   Set breakpoint: b <opcode#> or b <file>:<line>
  delete  (d)   Delete breakpoint: d <id>
  info    (i)   Show current position and breakpoints
  backtrace (bt) Show last N executed opcodes (default 10)
  run     (r)   Restart execution
  quit    (q)   Exit debugger
  help    (h)   Show this help
`);
}
