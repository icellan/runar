/**
 * Ajv-based validators for Rúnar IR schemas.
 *
 * Validates ANF IR programs and compiled artifacts against their respective
 * JSON Schemas, returning structured error information on failure.
 */

import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Ajv2020 } from 'ajv/dist/2020.js';
import type { ErrorObject } from 'ajv';
import type { ANFProgram } from './anf-ir.js';
import type { RunarArtifact } from './artifact.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// ---------------------------------------------------------------------------
// Schema loading
// ---------------------------------------------------------------------------

function findSchemasDir(): string {
  // When running from compiled output (dist/validators.js), __dirname is
  // <pkg>/dist.  Schemas live in <pkg>/src/schemas and are also copied to
  // <pkg>/dist/schemas by the build script.  We check both locations.
  const candidates = [
    join(__dirname, 'schemas'),        // dist/schemas  (copied by build)
    join(__dirname, '..', 'src', 'schemas'),  // src/schemas (dev / ts-node)
  ];
  for (const dir of candidates) {
    try {
      readFileSync(join(dir, 'anf-ir.schema.json'), 'utf-8');
      return dir;
    } catch {
      // try next
    }
  }
  throw new Error(
    'Could not locate Rúnar IR schema files. Checked: ' + candidates.join(', '),
  );
}

let _schemasDir: string | undefined;

function loadSchema(filename: string): Record<string, unknown> {
  if (!_schemasDir) {
    _schemasDir = findSchemasDir();
  }
  const raw = readFileSync(join(_schemasDir, filename), 'utf-8');
  return JSON.parse(raw) as Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Validation result
// ---------------------------------------------------------------------------

export interface ValidationSuccess {
  valid: true;
}

export interface ValidationFailure {
  valid: false;
  errors: ValidationError[];
}

export interface ValidationError {
  path: string;
  message: string;
  keyword: string;
}

export type ValidationResult = ValidationSuccess | ValidationFailure;

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function mapErrors(errors: ErrorObject[] | null | undefined): ValidationError[] {
  if (!errors) return [];
  return errors.map((err) => ({
    path: err.instancePath || '/',
    message: err.message ?? 'unknown error',
    keyword: err.keyword,
  }));
}

// ---------------------------------------------------------------------------
// Validator instances (lazy-initialised singletons)
// ---------------------------------------------------------------------------

let _ajv: Ajv2020 | undefined;

function getAjv(): Ajv2020 {
  if (!_ajv) {
    const anfSchema = loadSchema('anf-ir.schema.json');
    const artifactSchema = loadSchema('artifact.schema.json');

    _ajv = new Ajv2020({
      strict: true,
      allErrors: true,
      verbose: false,
    });
    // Register schemas so $ref across files resolves correctly.
    _ajv.addSchema(anfSchema, 'anf-ir.schema.json');
    _ajv.addSchema(artifactSchema, 'artifact.schema.json');
  }
  return _ajv;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Validate a plain object against the ANF IR JSON Schema.
 *
 * The input should be a JSON-compatible representation of an `ANFProgram`
 * (i.e. bigints serialised as integers/strings depending on magnitude).
 */
export function validateANF(data: unknown): ValidationResult {
  const ajv = getAjv();
  const validate = ajv.getSchema<ANFProgram>('anf-ir.schema.json');
  if (!validate) {
    throw new Error('ANF IR schema not registered — this is a bug in runar-ir-schema');
  }
  if (validate(data)) {
    return { valid: true };
  }
  return { valid: false, errors: mapErrors(validate.errors) };
}

/**
 * Validate a plain object against the Rúnar Artifact JSON Schema.
 */
export function validateArtifact(data: unknown): ValidationResult {
  const ajv = getAjv();
  const validate = ajv.getSchema<RunarArtifact>('artifact.schema.json');
  if (!validate) {
    throw new Error('Artifact schema not registered — this is a bug in runar-ir-schema');
  }
  if (validate(data)) {
    return { valid: true };
  }
  return { valid: false, errors: mapErrors(validate.errors) };
}

/**
 * Convenience: validate and throw on failure.
 */
export function assertValidANF(data: unknown): asserts data is ANFProgram {
  const result = validateANF(data);
  if (!result.valid) {
    const summary = result.errors
      .map((e) => `  ${e.path}: ${e.message}`)
      .join('\n');
    throw new Error(`Invalid ANF IR:\n${summary}`);
  }
}

/**
 * Convenience: validate and throw on failure.
 */
export function assertValidArtifact(data: unknown): asserts data is RunarArtifact {
  const result = validateArtifact(data);
  if (!result.valid) {
    const summary = result.errors
      .map((e) => `  ${e.path}: ${e.message}`)
      .join('\n');
    throw new Error(`Invalid Rúnar Artifact:\n${summary}`);
  }
}
