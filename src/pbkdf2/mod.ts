import { hmac, outputSizes, SupportedAlgorithm } from "../hmac/mod.ts";

export type { SupportedAlgorithm };

/**
 * PKCS #5: Password-Based Key Derivation Function 2 (PBKDF2)
 */
export function pbkdf2(
  hash: SupportedAlgorithm,
  password: Uint8Array,
  salt: Uint8Array,
  iterations: number,
  keyLen: number,
): Uint8Array {
  const salti = new Uint8Array(salt.length + 4);
  const saltiView = new DataView(salti.buffer);
  salti.set(salt);

  const hashLen = outputSizes[hash];
  const len = Math.ceil(keyLen / hashLen);
  const dk = new Uint8Array(len * hashLen);
  let offset = 0;
  for (let i = 1; i <= len; i++) {
    saltiView.setUint32(salt.length, i);
    const t = hmac(hash, password, salti);
    let u = t;

    for (let j = 1; j < iterations; j++) {
      u = hmac(hash, password, u);
      for (let k = 0; k < hashLen; k++) t[k] ^= u[k];
    }

    dk.set(t, offset);
    offset += hashLen;
  }

  return dk.slice(0, keyLen);
}
