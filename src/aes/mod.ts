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
  #ke: DataView;
  #kd: DataView;
  #nr: number;

  constructor(key: Uint8Array) {
    if (![16, 24, 32].includes(key.length)) {
      throw new Error("Invalid key size (must be either 16, 24 or 32 bytes)");
    }

    const keyView = new DataView(key.buffer, key.byteOffset, key.byteLength);
    const keyLen = key.length / 4;
    const rkc = key.length + 28;

    this.#nr = (rkc - 4) * 4;
    this.#ke = new DataView(new ArrayBuffer(rkc * 4));
    this.#kd = new DataView(new ArrayBuffer(rkc * 4));

    for (let i = 0; i < key.length; i += 4) {
      this.#ke.setUint32(i * 4, keyView.getUint32(i));
    }

    let rcon = 1;
    for (let i = keyLen; i < rkc; i++) {
      let tmp = this.#ke.getUint32((i - 1) * 4);

      if (i % keyLen === 0 || (keyLen === 8 && i % keyLen === 4)) {
        tmp = S.getUint8(tmp >>> 24) << 24 ^
          S.getUint8(tmp >> 16 & 0xff) << 16 ^
          S.getUint8(tmp >> 8 & 0xff) << 8 ^
          S.getUint8(tmp & 0xff);

        if (i % keyLen === 0) {
          tmp = tmp << 8 ^ tmp >>> 24 ^ rcon << 24;
          rcon = rcon << 1 ^ (rcon >> 7) * 0x11b;
        }
      }

      this.#ke.setUint32(
        i * 4,
        this.#ke.getUint32((i - keyLen) * 4) ^ tmp,
      );
    }

    for (let j = 0, i = rkc; i; j++, i--) {
      const tmp = this.#ke.getUint32(j & 3 ? i * 4 : (i - 4) * 4);
      if (i <= 4 || j < 4) {
        this.#kd.setUint32(j * 4, tmp);
      } else {
        this.#kd.setUint32(
          j * 4,
          T5.getUint32(S.getUint8(tmp >>> 24) * 4) ^
            T6.getUint32(S.getUint8(tmp >> 16 & 0xff) * 4) ^
            T7.getUint32(S.getUint8(tmp >> 8 & 0xff) * 4) ^
            T8.getUint32(S.getUint8(tmp & 0xff) * 4),
        );
      }
    }
  }

  encryptBlock(data: DataView, offset: number) {
    let t0 = data.getUint32(offset) ^ this.#ke.getUint32(0);
    let t1 = data.getUint32(offset + 4) ^ this.#ke.getUint32(4);
    let t2 = data.getUint32(offset + 8) ^ this.#ke.getUint32(8);
    let t3 = data.getUint32(offset + 12) ^ this.#ke.getUint32(12);
    let a0, a1, a2;

    for (let i = 16; i < this.#nr; i += 16) {
      a0 = T1.getUint32((t0 >>> 24) * 4) ^
        T2.getUint32((t1 >> 16 & 0xff) * 4) ^
        T3.getUint32((t2 >> 8 & 0xff) * 4) ^
        T4.getUint32((t3 & 0xff) * 4) ^
        this.#ke.getUint32(i);
      a1 = T1.getUint32((t1 >>> 24) * 4) ^
        T2.getUint32((t2 >> 16 & 0xff) * 4) ^
        T3.getUint32((t3 >> 8 & 0xff) * 4) ^
        T4.getUint32((t0 & 0xff) * 4) ^
        this.#ke.getUint32(i + 4);
      a2 = T1.getUint32((t2 >>> 24) * 4) ^
        T2.getUint32((t3 >> 16 & 0xff) * 4) ^
        T3.getUint32((t0 >> 8 & 0xff) * 4) ^
        T4.getUint32((t1 & 0xff) * 4) ^
        this.#ke.getUint32(i + 8);
      t3 = T1.getUint32((t3 >>> 24) * 4) ^
        T2.getUint32((t0 >> 16 & 0xff) * 4) ^
        T3.getUint32((t1 >> 8 & 0xff) * 4) ^
        T4.getUint32((t2 & 0xff) * 4) ^
        this.#ke.getUint32(i + 12);
      t0 = a0, t1 = a1, t2 = a2;
    }

    data.setUint32(
      offset,
      S.getUint8(t0 >>> 24) << 24 ^ S.getUint8(t1 >> 16 & 0xff) << 16 ^
        S.getUint8(t2 >> 8 & 0xff) << 8 ^ S.getUint8(t3 & 0xff) ^
        this.#ke.getUint32(this.#nr),
    );
    data.setUint32(
      offset + 4,
      S.getUint8(t1 >>> 24) << 24 ^ S.getUint8(t2 >> 16 & 0xff) << 16 ^
        S.getUint8(t3 >> 8 & 0xff) << 8 ^ S.getUint8(t0 & 0xff) ^
        this.#ke.getUint32(this.#nr + 4),
    );
    data.setUint32(
      offset + 8,
      S.getUint8(t2 >>> 24) << 24 ^ S.getUint8(t3 >> 16 & 0xff) << 16 ^
        S.getUint8(t0 >> 8 & 0xff) << 8 ^ S.getUint8(t1 & 0xff) ^
        this.#ke.getUint32(this.#nr + 8),
    );
    data.setUint32(
      offset + 12,
      S.getUint8(t3 >>> 24) << 24 ^ S.getUint8(t0 >> 16 & 0xff) << 16 ^
        S.getUint8(t1 >> 8 & 0xff) << 8 ^ S.getUint8(t2 & 0xff) ^
        this.#ke.getUint32(this.#nr + 12),
    );
  }

  decryptBlock(data: DataView, offset: number) {
    let t0 = data.getUint32(offset) ^ this.#kd.getUint32(0);
    let t1 = data.getUint32(offset + 4) ^ this.#kd.getUint32(12);
    let t2 = data.getUint32(offset + 8) ^ this.#kd.getUint32(8);
    let t3 = data.getUint32(offset + 12) ^ this.#kd.getUint32(4);
    let a0, a1, a2;

    for (let i = 16; i < this.#nr; i += 16) {
      a0 = T5.getUint32((t0 >>> 24) * 4) ^
        T6.getUint32((t3 >> 16 & 0xff) * 4) ^
        T7.getUint32((t2 >> 8 & 0xff) * 4) ^
        T8.getUint32((t1 & 0xff) * 4) ^
        this.#kd.getUint32(i);
      a1 = T5.getUint32((t1 >>> 24) * 4) ^
        T6.getUint32((t0 >> 16 & 0xff) * 4) ^
        T7.getUint32((t3 >> 8 & 0xff) * 4) ^
        T8.getUint32((t2 & 0xff) * 4) ^
        this.#kd.getUint32(i + 12);
      a2 = T5.getUint32((t2 >>> 24) * 4) ^
        T6.getUint32((t1 >> 16 & 0xff) * 4) ^
        T7.getUint32((t0 >> 8 & 0xff) * 4) ^
        T8.getUint32((t3 & 0xff) * 4) ^
        this.#kd.getUint32(i + 8);
      t3 = T5.getUint32((t3 >>> 24) * 4) ^
        T6.getUint32((t2 >> 16 & 0xff) * 4) ^
        T7.getUint32((t1 >> 8 & 0xff) * 4) ^
        T8.getUint32((t0 & 0xff) * 4) ^
        this.#kd.getUint32(i + 4);
      t0 = a0, t1 = a1, t2 = a2;
    }

    data.setUint32(
      offset,
      SI.getUint8(t0 >>> 24) << 24 ^ SI.getUint8(t3 >> 16 & 0xff) << 16 ^
        SI.getUint8(t2 >> 8 & 0xff) << 8 ^ SI.getUint8(t1 & 0xff) ^
        this.#kd.getUint32(this.#nr),
    );
    data.setUint32(
      offset + 4,
      SI.getUint8(t1 >>> 24) << 24 ^ SI.getUint8(t0 >> 16 & 0xff) << 16 ^
        SI.getUint8(t3 >> 8 & 0xff) << 8 ^ SI.getUint8(t2 & 0xff) ^
        this.#kd.getUint32(this.#nr + 12),
    );
    data.setUint32(
      offset + 8,
      SI.getUint8(t2 >>> 24) << 24 ^ SI.getUint8(t1 >> 16 & 0xff) << 16 ^
        SI.getUint8(t0 >> 8 & 0xff) << 8 ^ SI.getUint8(t3 & 0xff) ^
        this.#kd.getUint32(this.#nr + 8),
    );
    data.setUint32(
      offset + 12,
      SI.getUint8(t3 >>> 24) << 24 ^ SI.getUint8(t2 >> 16 & 0xff) << 16 ^
        SI.getUint8(t1 >> 8 & 0xff) << 8 ^ SI.getUint8(t0 & 0xff) ^
        this.#kd.getUint32(this.#nr + 4),
    );
  }
}
