#!/usr/bin/env node

import { readFileSync } from "node:fs";
import path from "node:path";
import { compile } from "../../../packages/runar-compiler/dist/index.js";

function printHelp() {
  process.stdout.write(
    [
      "Usage: ts_compile_source_hex.mjs --file <path>",
      "",
      "Compile a .runar.ts source file with the TypeScript reference compiler",
      "and print normalized script hex to stdout.",
    ].join("\n"),
  );
}

function normalizeHex(value) {
  return value.replace(/\s+/g, "").toLowerCase();
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
  const source = readFileSync(file, "utf8");

  let result;
  try {
    result = compile(source, { fileName: path.basename(file) });
  } catch (error) {
    const message = error instanceof Error ? error.stack ?? error.message : String(error);
    throw new Error(`TypeScript compile crashed for ${file}\n${message}`);
  }

  if (!result.success || !result.scriptHex) {
    const errors = (result.diagnostics ?? [])
      .filter((d) => d.severity === "error")
      .map((d) => {
        const line = d.span?.start?.line;
        const column = d.span?.start?.column;
        const location = Number.isInteger(line) && Number.isInteger(column) ? `:${line}:${column}` : "";
        return `${d.message}${location}`;
      })
      .join("\n");
    throw new Error(errors || `TypeScript compile failed for ${file}`);
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
