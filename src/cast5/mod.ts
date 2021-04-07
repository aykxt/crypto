import { S1, S2, S3, S4, S5, S6, S7, S8 } from "./consts.ts";
import { BlockCipher } from "../block-modes/base.ts";

/**
 * CAST5 block cipher.
 * 
 * Note: This is a low level class. Use a block cipher mode to
 * encrypt and decrypt data.
 */
// https://tools.ietf.org/html/rfc2144
export class Cast5 implements BlockCipher {
  /**
   * The block size of the block cipher in bytes
   */
  static readonly BLOCK_SIZE = 8;

  #km = new Uint32Array(16);
  #kr = new Uint8Array(16);
  #shortKey: boolean;

  constructor(key: Uint8Array) {
    if (key.length < 5 || key.length > 16) {
      throw new Error(
        "Invalid key size (must be between 5 and 16 bytes)",
      );
    }

    // https://tools.ietf.org/html/rfc2144#section-2.5
    this.#shortKey = key.length <= 10;

    const x = new Uint8Array(16);
    x.set(key);
    const xV = new DataView(x.buffer, x.byteOffset, x.byteLength);
    const k = new Uint32Array(32);

    const z = new Uint8Array(16);
    const zV = new DataView(z.buffer);

    // https://tools.ietf.org/html/rfc2144#section-2.4
    // deno-fmt-ignore
    for (let i = 0; i <= 16; i += 16) {
      zV.setUint32(0, xV.getUint32(0) ^ S5[x[13]] ^ S6[x[15]] ^ S7[x[12]] ^ S8[x[14]] ^ S7[x[8]]);
      zV.setUint32(4, xV.getUint32(8) ^ S5[z[0]] ^ S6[z[2]] ^ S7[z[1]] ^ S8[z[3]] ^ S8[x[10]]);
      zV.setUint32(8, xV.getUint32(12) ^ S5[z[7]] ^ S6[z[6]] ^ S7[z[5]] ^ S8[z[4]] ^ S5[x[9]]),
      zV.setUint32(12, xV.getUint32(4) ^ S5[z[10]] ^ S6[z[9]] ^ S7[z[11]] ^ S8[z[8]] ^ S6[x[11]]);
      k[i + 0] = S5[z[8]] ^ S6[z[9]] ^ S7[z[7]] ^ S8[z[6]] ^ S5[z[2]];
      k[i + 1] = S5[z[10]] ^ S6[z[11]] ^ S7[z[5]] ^ S8[z[4]] ^ S6[z[6]];
      k[i + 2] = S5[z[12]] ^ S6[z[13]] ^ S7[z[3]] ^ S8[z[2]] ^ S7[z[9]];
      k[i + 3] = S5[z[14]] ^ S6[z[15]] ^ S7[z[1]] ^ S8[z[0]] ^ S8[z[12]];
      xV.setUint32(0, zV.getUint32(8) ^ S5[z[5]] ^ S6[z[7]] ^ S7[z[4]] ^ S8[z[6]] ^ S7[z[0]]);
      xV.setUint32(4, zV.getUint32(0) ^ S5[x[0]] ^ S6[x[2]] ^ S7[x[1]] ^ S8[x[3]] ^ S8[z[2]]);
      xV.setUint32(8, zV.getUint32(4) ^ S5[x[7]] ^ S6[x[6]] ^ S7[x[5]] ^ S8[x[4]] ^ S5[z[1]]);
      xV.setUint32(12, zV.getUint32(12) ^ S5[x[10]] ^ S6[x[9]] ^ S7[x[11]] ^ S8[x[8]] ^ S6[z[3]]);
      k[i + 4] = S5[x[3]] ^ S6[x[2]] ^ S7[x[12]] ^ S8[x[13]] ^ S5[x[8]];
      k[i + 5] = S5[x[1]] ^ S6[x[0]] ^ S7[x[14]] ^ S8[x[15]] ^ S6[x[13]];
      k[i + 6] = S5[x[7]] ^ S6[x[6]] ^ S7[x[8]] ^ S8[x[9]] ^ S7[x[3]];
      k[i + 7] = S5[x[5]] ^ S6[x[4]] ^ S7[x[10]] ^ S8[x[11]] ^ S8[x[7]];
      zV.setUint32(0, xV.getUint32(0) ^ S5[x[13]] ^ S6[x[15]] ^ S7[x[12]] ^ S8[x[14]] ^ S7[x[8]]);
      zV.setUint32(4, xV.getUint32(8) ^ S5[z[0]] ^ S6[z[2]] ^ S7[z[1]] ^ S8[z[3]] ^ S8[x[10]]);
      zV.setUint32(8, xV.getUint32(12) ^ S5[z[7]] ^ S6[z[6]] ^ S7[z[5]] ^ S8[z[4]] ^ S5[x[9]]);
      zV.setUint32(12, xV.getUint32(4) ^ S5[z[10]] ^ S6[z[9]] ^ S7[z[11]] ^ S8[z[8]] ^ S6[x[11]]);
      k[i + 8] = S5[z[3]] ^ S6[z[2]] ^ S7[z[12]] ^ S8[z[13]] ^ S5[z[9]];
      k[i + 9] = S5[z[1]] ^ S6[z[0]] ^ S7[z[14]] ^ S8[z[15]] ^ S6[z[12]];
      k[i + 10] = S5[z[7]] ^ S6[z[6]] ^ S7[z[8]] ^ S8[z[9]] ^ S7[z[2]];
      k[i + 11] = S5[z[5]] ^ S6[z[4]] ^ S7[z[10]] ^ S8[z[11]] ^ S8[z[6]];
      xV.setUint32(0, zV.getUint32(8) ^ S5[z[5]] ^ S6[z[7]] ^ S7[z[4]] ^ S8[z[6]] ^ S7[z[0]]);
      xV.setUint32(4, zV.getUint32(0) ^ S5[x[0]] ^ S6[x[2]] ^ S7[x[1]] ^ S8[x[3]] ^ S8[z[2]]);
      xV.setUint32(8, zV.getUint32(4) ^ S5[x[7]] ^ S6[x[6]] ^ S7[x[5]] ^ S8[x[4]] ^ S5[z[1]]);
      xV.setUint32(12, zV.getUint32(12) ^ S5[x[10]] ^ S6[x[9]] ^ S7[x[11]] ^ S8[x[8]] ^ S6[z[3]]);
      k[i + 12] = S5[x[8]] ^ S6[x[9]] ^ S7[x[7]] ^ S8[x[6]] ^ S5[x[3]];
      k[i + 13] = S5[x[10]] ^ S6[x[11]] ^ S7[x[5]] ^ S8[x[4]] ^ S6[x[7]];
      k[i + 14] = S5[x[12]] ^ S6[x[13]] ^ S7[x[3]] ^ S8[x[2]] ^ S7[x[8]];
      k[i + 15] = S5[x[14]] ^ S6[x[15]] ^ S7[x[1]] ^ S8[x[0]] ^ S8[x[13]];
    }

    for (let i = 0; i < 16; i++) {
      this.#km[i] = k[i];
      this.#kr[i] = k[16 + i] & 0x1f;
    }
  }

  encryptBlock(data: DataView, offset: number) {
    let l = data.getUint32(offset);
    let r = data.getUint32(offset + 4);
    let t;

    t = r;
    r = l ^ this.f1(r, 0);
    l = t;
    t = r;
    r = l ^ this.f2(r, 1);
    l = t;
    t = r;
    r = l ^ this.f3(r, 2);
    l = t;
    t = r;
    r = l ^ this.f1(r, 3);
    l = t;

    t = r;
    r = l ^ this.f2(r, 4);
    l = t;
    t = r;
    r = l ^ this.f3(r, 5);
    l = t;
    t = r;
    r = l ^ this.f1(r, 6);
    l = t;
    t = r;
    r = l ^ this.f2(r, 7);
    l = t;

    t = r;
    r = l ^ this.f3(r, 8);
    l = t;
    t = r;
    r = l ^ this.f1(r, 9);
    l = t;
    t = r;
    r = l ^ this.f2(r, 10);
    l = t;
    t = r;
    r = l ^ this.f3(r, 11);
    l = t;

    if (!this.#shortKey) {
      t = r;
      r = l ^ this.f1(r, 12);
      l = t;
      t = r;
      r = l ^ this.f2(r, 13);
      l = t;
      t = r;
      r = l ^ this.f3(r, 14);
      l = t;
      t = r;
      r = l ^ this.f1(r, 15);
      l = t;
    }

    data.setUint32(offset, r);
    data.setUint32(offset + 4, l);
  }

  decryptBlock(data: DataView, offset: number) {
    let l = data.getUint32(offset);
    let r = data.getUint32(offset + 4);
    let t;

    if (!this.#shortKey) {
      t = r;
      r = l ^ this.f1(r, 15);
      l = t;
      t = r;
      r = l ^ this.f3(r, 14);
      l = t;
      t = r;
      r = l ^ this.f2(r, 13);
      l = t;
      t = r;
      r = l ^ this.f1(r, 12);
      l = t;
    }

    t = r;
    r = l ^ this.f3(r, 11);
    l = t;
    t = r;
    r = l ^ this.f2(r, 10);
    l = t;
    t = r;
    r = l ^ this.f1(r, 9);
    l = t;
    t = r;
    r = l ^ this.f3(r, 8);
    l = t;

    t = r;
    r = l ^ this.f2(r, 7);
    l = t;
    t = r;
    r = l ^ this.f1(r, 6);
    l = t;
    t = r;
    r = l ^ this.f3(r, 5);
    l = t;
    t = r;
    r = l ^ this.f2(r, 4);
    l = t;

    t = r;
    r = l ^ this.f1(r, 3);
    l = t;
    t = r;
    r = l ^ this.f3(r, 2);
    l = t;
    t = r;
    r = l ^ this.f2(r, 1);
    l = t;
    t = r;
    r = l ^ this.f1(r, 0);
    l = t;

    data.setUint32(offset, r);
    data.setUint32(offset + 4, l);
  }

  private f1(d: number, n: number) {
    const r = this.#kr[n];
    const t = this.#km[n] + d;
    const i = t << r | t >>> (32 - r);
    return ((S1[i >>> 24] ^ S2[i >>> 16 & 0xff]) -
      S3[i >>> 8 & 0xff]) + S4[i & 0xff];
  }

  private f2(d: number, n: number) {
    const r = this.#kr[n];
    const t = this.#km[n] ^ d;
    const i = t << r | t >>> (32 - r);
    return ((S1[i >>> 24] - S2[i >>> 16 & 0xff]) +
      S3[i >>> 8 & 0xff]) ^ S4[i & 0xff];
  }

  private f3(d: number, n: number) {
    const r = this.#kr[n];
    const t = this.#km[n] - d;
    const i = t << r | t >>> (32 - r);
    return ((S1[i >>> 24] + S2[i >>> 16 & 0xff]) ^
      S3[i >>> 8 & 0xff]) - S4[i & 0xff];
  }
}
