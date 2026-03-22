#!/usr/bin/env node

import { readFileSync } from "node:fs";
import path from "node:path";
import { lowerToStack } from "../../../packages/runar-compiler/dist/passes/05-stack-lower.js";
import { emit } from "../../../packages/runar-compiler/dist/passes/06-emit.js";
import { optimizeStackIR } from "../../../packages/runar-compiler/dist/optimizer/peephole.js";

function printHelp() {
  process.stdout.write(
    [
      "Usage: ts_compile_ir_hex.mjs --file <path>",
      "",
      "Compile expected-ir.json with the TypeScript backend reference path",
      "and print normalized script hex to stdout.",
    ].join("\n"),
  );
}

function normalizeHex(value) {
  return value.replace(/\s+/g, "").toLowerCase();
}

function normalizeAnf(node) {
  if (Array.isArray(node)) {
    return node.map((value) => normalizeAnf(value));
  }
  if (!node || typeof node !== "object") {
    return node;
  }

  const out = {};
  for (const [key, value] of Object.entries(node)) {
    out[key] = normalizeAnf(value);
  }

  // The TS backend expects bigint constants for some arithmetic paths.
  if (out.kind === "load_const" && typeof out.value === "number") {
    out.value = BigInt(out.value);
  }

  return out;
}

function parseArgs(argv) {
  let file = null;
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--help" || arg === "-h") {
      printHelp();
      process.exit(0);
    }
    if (arg === "--file") {
      file = argv[i + 1] ?? null;
      i += 1;
      continue;
    }
    if (!arg.startsWith("-") && file === null) {
      file = arg;
      continue;
    }
    throw new Error(`unknown argument: ${arg}`);
  }
  if (!file) {
    throw new Error("missing --file <path>");
  }
  return { file: path.resolve(file) };
}

function main() {
  const { file } = parseArgs(process.argv.slice(2));
  const anf = normalizeAnf(JSON.parse(readFileSync(file, "utf8")));

  let stack;
  let result;
  try {
    stack = lowerToStack(anf);
    for (const method of stack.methods) {
      method.ops = optimizeStackIR(method.ops);
    }
    result = emit(stack);
  } catch (error) {
    const message = error instanceof Error ? error.stack ?? error.message : String(error);
    throw new Error(`TypeScript backend pipeline failed for ${file}\n${message}`);
  }

  if (!result?.scriptHex) {
    throw new Error(`TypeScript backend emit failed for ${file}`);
  }

  process.stdout.write(normalizeHex(result.scriptHex));
}

try {
  main();
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`${message}\n`);
  process.exit(1);
}
