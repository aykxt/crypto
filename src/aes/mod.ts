import { S, SI, T1, T2, T3, T4, T5, T6, T7, T8 } from "./consts.ts";
import { BlockCipher } from "../block-modes/base.ts";

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

    const keyView = new DataView(key.buffer, key.byteOffset, key.byteLength);
    const keyLen = key.length / 4;
    const rkc = key.length + 28;

    this.#nr = rkc - 4;
    this.#ke = new Uint32Array(rkc);
    this.#kd = new Uint32Array(rkc);

    for (let i = 0; i < key.length; i += 4) {
      this.#ke[i] = keyView.getUint32(i);
    }

    let rcon = 1;
    for (let i = keyLen; i < rkc; i++) {
      let tmp = this.#ke[i - 1];

      if (i % keyLen === 0 || (keyLen === 8 && i % keyLen === 4)) {
        tmp = S[tmp >>> 24] << 24 ^ S[tmp >> 16 & 0xff] << 16 ^
          S[tmp >> 8 & 0xff] << 8 ^ S[tmp & 0xff];

        if (i % keyLen === 0) {
          tmp = tmp << 8 ^ tmp >>> 24 ^ rcon << 24;
          rcon = rcon << 1 ^ (rcon >> 7) * 0x11b;
        }
      }

      this.#ke[i] = this.#ke[i - keyLen] ^ tmp;
    }

    for (let j = 0, i = rkc; i; j++, i--) {
      const tmp = this.#ke[j & 3 ? i : i - 4];
      if (i <= 4 || j < 4) {
        this.#kd[j] = tmp;
      } else {
        this.#kd[j] = T5[S[tmp >>> 24]] ^
          T6[S[tmp >> 16 & 0xff]] ^
          T7[S[tmp >> 8 & 0xff]] ^
          T8[S[tmp & 0xff]];
      }
    }
  }

  encryptBlock(data: DataView, offset: number) {
    let t0 = data.getUint32(offset) ^ this.#ke[0];
    let t1 = data.getUint32(offset + 4) ^ this.#ke[1];
    let t2 = data.getUint32(offset + 8) ^ this.#ke[2];
    let t3 = data.getUint32(offset + 12) ^ this.#ke[3];
    let a0, a1, a2;

    for (let i = 4; i < this.#nr; i += 4) {
      a0 = T1[t0 >>> 24] ^ T2[t1 >> 16 & 0xff] ^ T3[t2 >> 8 & 0xff] ^
        T4[t3 & 0xff] ^ this.#ke[i];
      a1 = T1[t1 >>> 24] ^ T2[t2 >> 16 & 0xff] ^ T3[t3 >> 8 & 0xff] ^
        T4[t0 & 0xff] ^ this.#ke[i + 1];
      a2 = T1[t2 >>> 24] ^ T2[t3 >> 16 & 0xff] ^ T3[t0 >> 8 & 0xff] ^
        T4[t1 & 0xff] ^ this.#ke[i + 2];
      t3 = T1[t3 >>> 24] ^ T2[t0 >> 16 & 0xff] ^ T3[t1 >> 8 & 0xff] ^
        T4[t2 & 0xff] ^ this.#ke[i + 3];
      t0 = a0, t1 = a1, t2 = a2;
    }

    data.setUint32(
      offset,
      S[t0 >>> 24] << 24 ^ S[t1 >> 16 & 0xff] << 16 ^
        S[t2 >> 8 & 0xff] << 8 ^ S[t3 & 0xff] ^ this.#ke[this.#nr],
    );
    data.setUint32(
      offset + 4,
      S[t1 >>> 24] << 24 ^ S[t2 >> 16 & 0xff] << 16 ^
        S[t3 >> 8 & 0xff] << 8 ^ S[t0 & 0xff] ^ this.#ke[this.#nr + 1],
    );
    data.setUint32(
      offset + 8,
      S[t2 >>> 24] << 24 ^ S[t3 >> 16 & 0xff] << 16 ^
        S[t0 >> 8 & 0xff] << 8 ^ S[t1 & 0xff] ^ this.#ke[this.#nr + 2],
    );
    data.setUint32(
      offset + 12,
      S[t3 >>> 24] << 24 ^ S[t0 >> 16 & 0xff] << 16 ^
        S[t1 >> 8 & 0xff] << 8 ^ S[t2 & 0xff] ^ this.#ke[this.#nr + 3],
    );
  }

  decryptBlock(data: DataView, offset: number) {
    let t0 = data.getUint32(offset) ^ this.#kd[0];
    let t1 = data.getUint32(offset + 4) ^ this.#kd[3];
    let t2 = data.getUint32(offset + 8) ^ this.#kd[2];
    let t3 = data.getUint32(offset + 12) ^ this.#kd[1];
    let a0, a1, a2;

    for (let i = 4; i < this.#nr; i += 4) {
      a0 = T5[t0 >>> 24] ^ T6[t3 >> 16 & 0xff] ^ T7[t2 >> 8 & 0xff] ^
        T8[t1 & 0xff] ^ this.#kd[i];
      a1 = T5[t1 >>> 24] ^ T6[t0 >> 16 & 0xff] ^ T7[t3 >> 8 & 0xff] ^
        T8[t2 & 0xff] ^ this.#kd[i + 3];
      a2 = T5[t2 >>> 24] ^ T6[t1 >> 16 & 0xff] ^ T7[t0 >> 8 & 0xff] ^
        T8[t3 & 0xff] ^ this.#kd[i + 2];
      t3 = T5[t3 >>> 24] ^ T6[t2 >> 16 & 0xff] ^ T7[t1 >> 8 & 0xff] ^
        T8[t0 & 0xff] ^ this.#kd[i + 1];
      t0 = a0, t1 = a1, t2 = a2;
    }

    data.setUint32(
      offset,
      SI[t0 >>> 24] << 24 ^ SI[t3 >> 16 & 0xff] << 16 ^
        SI[t2 >> 8 & 0xff] << 8 ^ SI[t1 & 0xff] ^ this.#kd[this.#nr],
    );
    data.setUint32(
      offset + 4,
      SI[t1 >>> 24] << 24 ^ SI[t0 >> 16 & 0xff] << 16 ^
        SI[t3 >> 8 & 0xff] << 8 ^ SI[t2 & 0xff] ^ this.#kd[this.#nr + 3],
    );
    data.setUint32(
      offset + 8,
      SI[t2 >>> 24] << 24 ^ SI[t1 >> 16 & 0xff] << 16 ^
        SI[t0 >> 8 & 0xff] << 8 ^ SI[t3 & 0xff] ^ this.#kd[this.#nr + 2],
    );
    data.setUint32(
      offset + 12,
      SI[t3 >>> 24] << 24 ^ SI[t2 >> 16 & 0xff] << 16 ^
        SI[t1 >> 8 & 0xff] << 8 ^ SI[t0 & 0xff] ^ this.#kd[this.#nr + 1],
    );
  }
}
