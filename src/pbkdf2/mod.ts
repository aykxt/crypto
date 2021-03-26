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
  keylen: number,
): Uint8Array {
  const dk = new Uint8Array(keylen);

  const salti = new Uint8Array(salt.length + 4);
  const saltiView = new DataView(salti.buffer);
  salti.set(salt);

  const hashLen = outputSizes[hash];
  const len = Math.ceil(keylen / hashLen);

  for (let i = 1, offset = 0; i <= len; i++, offset += hashLen) {
    saltiView.setUint32(salt.length, i);

    const t = hmac(hash, password, salti);
    let u = t;

    for (let j = 1; j < iterations; j++) {
      u = hmac(hash, password, u);
      for (let k = 0; k < hashLen; k++) t[k] ^= u[k];
    }

    dk.set(t, offset);
  }

  return dk;
}
