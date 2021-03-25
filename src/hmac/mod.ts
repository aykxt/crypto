import { createHash, SupportedAlgorithm } from "../../deps.ts";

export type { SupportedAlgorithm } from "../../deps.ts";

export const blockSizes: Record<SupportedAlgorithm, number> = {
  "sha3-512": 72,
  "sha3-384": 48,
  "sha3-256": 136,
  "sha3-224": 144,
  sha512: 128,
  sha384: 128,
  sha256: 64,
  sha224: 64,
  sha1: 64,
  md5: 64,
  md4: 64,
  md2: 16,
  ripemd320: 64,
  ripemd160: 64,
  keccak512: 72,
  keccak384: 48,
  keccak256: 136,
  keccak224: 144,
};

export const outputSizes: Record<SupportedAlgorithm, number> = {
  "sha3-512": 64,
  "sha3-384": 48,
  "sha3-256": 32,
  "sha3-224": 28,
  sha512: 64,
  sha384: 48,
  sha256: 32,
  sha224: 28,
  sha1: 20,
  md5: 16,
  md4: 16,
  md2: 16,
  ripemd320: 40,
  ripemd160: 20,
  keccak512: 64,
  keccak384: 48,
  keccak256: 32,
  keccak224: 28,
};

/**
 * RFC 2104 Keyed Hash Message Authentication Code (HMAC)
 */
export function hmac(
  hash: SupportedAlgorithm,
  key: Uint8Array,
  data: Uint8Array,
): Uint8Array {
  const blockSize = blockSizes[hash];

  if (key.length > blockSize) {
    key = new Uint8Array(createHash(hash).update(key).digest());
  }

  if (key.length < blockSize) {
    const keylong = new Uint8Array(blockSize);
    keylong.set(key, 0);
    key = keylong;
  }

  const opad = new Uint8Array(blockSize);
  const ipad = new Uint8Array(blockSize);

  for (let i = 0; i < blockSize; i++) {
    opad[i] = key[i] ^ 0x5c;
    ipad[i] = key[i] ^ 0x36;
  }

  return new Uint8Array(
    createHash(hash).update(
      concat(
        opad,
        new Uint8Array(createHash(hash).update(concat(ipad, data)).digest()),
      ),
    ).digest(),
  );
}

function concat(a: Uint8Array, b: Uint8Array) {
  const arr = new Uint8Array(a.length + b.length);
  arr.set(a, 0);
  arr.set(b, a.length);
  return arr;
}
