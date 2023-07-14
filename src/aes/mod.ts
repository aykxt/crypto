import { BlockCipher } from "../block-modes/base.ts";
import { bytesToWords } from "../utils/bytes.ts";
import { S, SI, T1, T2, T3, T4, T5, T6, T7, T8 } from "./consts.ts";

/**
 * Advanced Encryption Standard (AES) block cipher.
 *
 * Note: This is a low level class. Use a block cipher mode to
 * encrypt and decrypt data.
 */
export class Aes implements BlockCipher {
  /**
   * The block size of the block cipher in bytes
   */
  static readonly BLOCK_SIZE = 16;
  #ke: Uint32Array;
  #kd: Uint32Array;
  #nr: number;

  constructor(key: Uint8Array) {
    if (![16, 24, 32].includes(key.length)) {
      throw new Error("Invalid key size (must be either 16, 24 or 32 bytes)");
    }

    const keyLen = key.length / 4;
    const rkc = key.length + 28;
    const ke = new Uint32Array(rkc);
    ke.set(bytesToWords(key), 0);
    const kd = new Uint32Array(rkc);

    let i, j, tmp, rcon = 1;
    for (i = keyLen; i < 4 * keyLen + 28; i++) {
      tmp = ke[i - 1];

      if (i % keyLen === 0 || (keyLen === 8 && i % keyLen === 4)) {
        tmp = S[tmp >>> 24] << 24 ^ S[tmp >> 16 & 255] << 16 ^
          S[tmp >> 8 & 255] << 8 ^ S[tmp & 255];

        if (i % keyLen === 0) {
          tmp = tmp << 8 ^ tmp >>> 24 ^ rcon << 24;
          rcon = rcon << 1 ^ (rcon >> 7) * 283;
        }
      }

      ke[i] = ke[i - keyLen] ^ tmp;
    }

    for (j = 0; i; j++, i--) {
      tmp = ke[j & 3 ? i : i - 4];
      if (i <= 4 || j < 4) {
        kd[j] = tmp;
      } else {
        kd[j] = T5[S[tmp >>> 24]] ^
          T6[S[tmp >> 16 & 255]] ^
          T7[S[tmp >> 8 & 255]] ^
          T8[S[tmp & 255]];
      }
    }

    this.#nr = ke.length / 4 - 2;
    this.#ke = ke;
    this.#kd = kd;
  }

  encryptBlock(data: DataView, offset: number) {
    const k = this.#ke;
    let a = data.getUint32(offset + 0) ^ k[0],
      b = data.getUint32(offset + 4) ^ k[1],
      c = data.getUint32(offset + 8) ^ k[2],
      d = data.getUint32(offset + 12) ^ k[3],
      a2,
      b2,
      c2,
      i,
      ki = 4;

    for (i = 0; i < this.#nr; i++) {
      a2 = T1[a >>> 24] ^ T2[b >> 16 & 255] ^ T3[c >> 8 & 255] ^ T4[d & 255] ^
        k[ki];
      b2 = T1[b >>> 24] ^ T2[c >> 16 & 255] ^ T3[d >> 8 & 255] ^ T4[a & 255] ^
        k[ki + 1];
      c2 = T1[c >>> 24] ^ T2[d >> 16 & 255] ^ T3[a >> 8 & 255] ^ T4[b & 255] ^
        k[ki + 2];
      d = T1[d >>> 24] ^ T2[a >> 16 & 255] ^ T3[b >> 8 & 255] ^ T4[c & 255] ^
        k[ki + 3];
      ki += 4;
      a = a2;
      b = b2;
      c = c2;
    }

    for (i = 0; i < 4; i++) {
      data.setUint32(
        offset + i * 4,
        S[a >>> 24] << 24 ^
          S[b >> 16 & 255] << 16 ^
          S[c >> 8 & 255] << 8 ^
          S[d & 255] ^
          k[ki++],
      );
      a2 = a;
      a = b;
      b = c;
      c = d;
      d = a2;
    }
  }

  decryptBlock(data: DataView, offset: number) {
    const k = this.#kd;
    let a = data.getUint32(offset + 0) ^ k[0],
      b = data.getUint32(offset + 12) ^ k[1],
      c = data.getUint32(offset + 8) ^ k[2],
      d = data.getUint32(offset + 4) ^ k[3],
      a2,
      b2,
      c2,
      i,
      ki = 4;

    for (i = 0; i < this.#nr; i++) {
      a2 = T5[a >>> 24] ^ T6[b >> 16 & 255] ^ T7[c >> 8 & 255] ^ T8[d & 255] ^
        k[ki];
      b2 = T5[b >>> 24] ^ T6[c >> 16 & 255] ^ T7[d >> 8 & 255] ^ T8[a & 255] ^
        k[ki + 1];
      c2 = T5[c >>> 24] ^ T6[d >> 16 & 255] ^ T7[a >> 8 & 255] ^ T8[b & 255] ^
        k[ki + 2];
      d = T5[d >>> 24] ^ T6[a >> 16 & 255] ^ T7[b >> 8 & 255] ^ T8[c & 255] ^
        k[ki + 3];
      ki += 4;
      a = a2;
      b = b2;
      c = c2;
    }

    for (i = 0; i < 4; i++) {
      data.setUint32(
        offset + (3 & -i) * 4,
        SI[a >>> 24] << 24 ^
          SI[b >> 16 & 255] << 16 ^
          SI[c >> 8 & 255] << 8 ^
          SI[d & 255] ^
          k[ki++],
      );
      a2 = a;
      a = b;
      b = c;
      c = d;
      d = a2;
    }
  }
}
