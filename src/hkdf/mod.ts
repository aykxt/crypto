import type { SupportedAlgorithm } from "../hmac/mod.ts";
import { hmac, outputSizes } from "../hmac/mod.ts";

export type { SupportedAlgorithm };

/**
 * RFC 5869 HMAC-based Key Derivation Function (HKDF)
 */
export function hkdf(
  hash: SupportedAlgorithm,
  length: number,
  ikm: Uint8Array,
  salt?: Uint8Array,
  info?: Uint8Array,
): Uint8Array {
  const hashLen = outputSizes[hash];

  if (!salt) salt = new Uint8Array(hashLen);
  if (!info) info = new Uint8Array();

  const prk = hmac(hash, salt, ikm);

  let t = new Uint8Array();
  const nb = Math.ceil(length / hashLen);
  const okm = new Uint8Array(nb * hashLen);

  for (let i = 0; i < nb; i++) {
    const concat = new Uint8Array(t.length + info.length + 1);
    concat.set(t);
    concat.set(info, t.length);
    concat[t.length + info.length] = i + 1;
    t = hmac(hash, prk, concat);
    okm.set(t, hashLen * i);
  }

  return okm.slice(0, length);
}
