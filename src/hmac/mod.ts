import { createHash, SupportedAlgorithm } from "../../deps.ts";

export type { SupportedAlgorithm };

const blockSizes: Record<SupportedAlgorithm, number> = {
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
