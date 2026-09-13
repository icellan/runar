/**
 * The input-size guard, shared by `parse()` and by each per-format parser.
 *
 * R-146 / CL-BUG-055: the limit used to live only in `01-parse.ts`'s
 * dispatcher, while all eight `parse<Format>Source` functions are exported from
 * the package index AND documented in the compiler README as the way to target
 * a specific surface. Measured on a 4,400,037-byte `.runar.sol` source against
 * the 4,194,304-byte limit:
 *
 *     parse()           REFUSED: source exceeds MAX_SOURCE_BYTES
 *     parseSolSource()  ACCEPTED
 *
 * So the guard was present and reachable-around through the advertised door.
 * Same shape as CL-BUG-057, where Python's CLI goes around its own guarded
 * dispatcher.
 *
 * Withdrawing the exports would fix the bug by breaking a documented API for a
 * reason that has nothing to do with the API's shape. Putting the guard where
 * every entry point passes through costs one call per parser.
 */

import { InputLimits, CanonicalJsonError } from 'runar-ir-schema';

/**
 * Throw unless `source` is within `InputLimits.MAX_SOURCE_BYTES`.
 *
 * `where` names the caller so the message says which door the oversize input
 * came through — `parse` for the dispatcher, `parseSolSource` for a direct
 * call. The limit and the error shape are the dispatcher's, unchanged, so a
 * caller already catching `CanonicalJsonError` from `parse()` needs no change.
 */
export function assertSourceWithinLimits(source: string, where: string): void {
  const sourceBytes = Buffer.byteLength(source, 'utf8');
  if (sourceBytes > InputLimits.MAX_SOURCE_BYTES) {
    throw new CanonicalJsonError(
      'bytes',
      `${where}: source exceeds MAX_SOURCE_BYTES (limit=${InputLimits.MAX_SOURCE_BYTES}, actual=${sourceBytes})`,
      { limit: InputLimits.MAX_SOURCE_BYTES, actual: sourceBytes },
    );
  }
}
