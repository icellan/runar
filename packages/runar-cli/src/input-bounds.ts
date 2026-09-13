/**
 * Size bounds for files the CLI reads from a user-supplied path.
 *
 * `compile --from-ir` has bounded its input since it was written
 * (commands/compile.ts): "reject oversized IR files at the CLI boundary so the
 * user gets a tier-agnostic, byte-precise error before the compiler is even
 * invoked". `verify`, `analyze` and `debug` did not — they `readFileSync` and
 * hand the result to `JSON.parse`, so a 2 GB file is a process that allocates
 * until the allocator or the OOM killer decides how the command ends (R-269).
 *
 * A local CLI is not a server and this is not protecting a user from their own
 * disk. It is that these commands take a PATH, and a path arrives from a script,
 * a Makefile, or a CI job that fetched an artifact from somewhere. "JS heap out
 * of memory after ninety seconds" is a worse answer than "that file is 2 GB, the
 * limit is 16 MiB".
 *
 * The check is on the file's SIZE, before the read: reading two gigabytes in
 * order to discover it is too long defeats the purpose.
 */

import { statSync, readFileSync } from 'node:fs';

/** Thrown when a file is larger than the command will read. */
export class InputTooLargeError extends Error {
  constructor(
    readonly path: string,
    readonly actual: number,
    readonly limit: number,
  ) {
    super(`${path} is ${actual} bytes; limit is ${limit}`);
    this.name = 'InputTooLargeError';
  }
}

/**
 * Read a file, refusing before the read if it exceeds `limit` bytes.
 *
 * @throws InputTooLargeError when the file is too large. Any other error (the
 *   file is missing, unreadable, a directory) propagates unchanged, so callers
 *   keep their existing diagnostics for those cases.
 */
export function readBoundedFile(path: string, limit: number): string {
  const size = statSync(path).size;
  if (size > limit) {
    throw new InputTooLargeError(path, size, limit);
  }
  return readFileSync(path, 'utf-8');
}
