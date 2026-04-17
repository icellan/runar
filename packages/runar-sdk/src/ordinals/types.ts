// ---------------------------------------------------------------------------
// runar-sdk/ordinals/types.ts — Types for 1sat ordinals support
// ---------------------------------------------------------------------------

/**
 * Inscription data: content type and hex-encoded payload.
 *
 * The `data` field is a hex string representing the raw inscription bytes.
 * For text content, encode the UTF-8 bytes as hex first. For BSV-20 JSON,
 * use the `BSV20` / `BSV21` helper classes which handle encoding.
 */
export interface Inscription {
  contentType: string;
  data: string; // hex-encoded content
}

/**
 * Hex-char offsets bounding an inscription envelope within a script.
 * Used internally by `findInscriptionEnvelope` and `stripInscriptionEnvelope`.
 */
export interface EnvelopeBounds {
  /** Hex-char offset where the envelope starts (at OP_FALSE). */
  startHex: number;
  /** Hex-char offset where the envelope ends (after OP_ENDIF). */
  endHex: number;
}
