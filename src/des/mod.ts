import type { BlockCipher } from "../block-modes/base.ts";
// deno-fmt-ignore
import { PC2_0, PC2_1, PC2_10, PC2_11, PC2_12, PC2_13, PC2_2, PC2_3, PC2_4, PC2_5, PC2_6, PC2_7, PC2_8, PC2_9, SHIFTS, SP1, SP2, SP3, SP4, SP5, SP6, SP7, SP8 } from "./consts.ts";

/**
 * Data Encryption Standard (DES) block cipher.
 * 
 * Note: This is a low level class. Use a block cipher mode to
 * encrypt and decrypt data.
 */
export class Des implements BlockCipher {
  /**
   * The block size of the block cipher in bytes
   */
  static readonly BLOCK_SIZE = 8;
  #keys = new Uint32Array(32);

  constructor(key: Uint8Array) {
    if (key.length != 8) {
      throw new Error("Invalid key length (must be 8 bytes)");
    }

    const keyV = new DataView(key.buffer);
    let l = keyV.getUint32(0);
    let r = keyV.getUint32(4);
    let t = (l >>> 4 ^ r) & 0x0f0f0f0f;
    r ^= t;
    l ^= t << 4;
    t = (r >>> 16 ^ l) & 0x0000ffff;
    l ^= t;
    r ^= t << 16;
    t = (l >>> 2 ^ r) & 0x33333333;
    r ^= t;
    l ^= t << 2;
    t = (r >>> 16 ^ l) & 0x0000ffff;
    l ^= t;
    r ^= t << 16;
    t = (l >>> 1 ^ r) & 0x55555555;
    r ^= t;
    l ^= t << 1;
    t = (r >>> 8 ^ l) & 0x00ff00ff;
    l ^= t;
    r ^= t << 8;
    t = (l >>> 1 ^ r) & 0x55555555;
    r ^= t;
    l ^= t << 1;
    t = l << 8 | r >>> 20 & 0x000000f0;
    l = r << 24 | r << 8 & 0xff0000 | r >>> 8 & 0xff00 | r >>> 24 & 0xf0;
    r = t;

    for (let i = 0; i < 32; i += 2) {
      if (SHIFTS[i / 2]) {
        l = l << 2 | l >>> 26;
        r = r << 2 | r >>> 26;
      } else {
        l = l << 1 | l >>> 27;
        r = r << 1 | r >>> 27;
      }
      l &= -0xf;
      r &= -0xf;
      const lt = PC2_0[l >>> 28] | PC2_1[(l >>> 24) & 0xf] |
        PC2_2[(l >>> 20) & 0xf] | PC2_3[(l >>> 16) & 0xf] |
        PC2_4[(l >>> 12) & 0xf] | PC2_5[(l >>> 8) & 0xf] |
        PC2_6[(l >>> 4) & 0xf];
      const rt = PC2_7[r >>> 28] | PC2_8[(r >>> 24) & 0xf] |
        PC2_9[(r >>> 20) & 0xf] | PC2_10[(r >>> 16) & 0xf] |
        PC2_11[(r >>> 12) & 0xf] | PC2_12[(r >>> 8) & 0xf] |
        PC2_13[(r >>> 4) & 0xf];
      t = ((rt >>> 16) ^ lt) & 0x0000ffff;
      this.#keys[i] = lt ^ t;
      this.#keys[i + 1] = rt ^ (t << 16);
    }
  }

  encryptBlock(data: DataView, offset: number) {
    let l = data.getUint32(offset);
    let r = data.getUint32(offset + 4);
    let t = (l >>> 4 ^ r) & 0x0f0f0f0f;
    r ^= t;
    l ^= t << 4;
    t = (l >>> 16 ^ r) & 0x0000ffff;
    r ^= t;
    l ^= t << 16;
    t = (r >>> 2 ^ l) & 0x33333333;
    l ^= t;
    r ^= t << 2;
    t = (r >>> 8 ^ l) & 0x00ff00ff;
    l ^= t;
    r ^= t << 8;
    t = (l >>> 1 ^ r) & 0x55555555;
    r ^= t;
    l ^= t << 1;
    l = l << 1 | l >>> 31;
    r = r << 1 | r >>> 31;

    for (let i = 0; i < 32; i += 2) {
      const r1 = r ^ this.#keys[i];
      const r2 = (r >>> 4 | r << 28) ^ this.#keys[i + 1];
      t = l, l = r;
      r = t ^ (
        SP2[r1 >>> 24 & 0x3f] |
        SP4[r1 >>> 16 & 0x3f] |
        SP6[r1 >>> 8 & 0x3f] |
        SP8[r1 & 0x3f] |
        SP1[r2 >>> 24 & 0x3f] |
        SP3[r2 >>> 16 & 0x3f] |
        SP5[r2 >>> 8 & 0x3f] |
        SP7[r2 & 0x3f]
      );
    }

    t = l, l = r, r = t;
    l = l >>> 1 | l << 31;
    r = r >>> 1 | r << 31;
    t = (l >>> 1 ^ r) & 0x55555555;
    r ^= t;
    l ^= t << 1;
    t = (r >>> 8 ^ l) & 0x00ff00ff;
    l ^= t;
    r ^= t << 8;
    t = (r >>> 2 ^ l) & 0x33333333;
    l ^= t;
    r ^= t << 2;
    t = (l >>> 16 ^ r) & 0x0000ffff;
    r ^= t;
    l ^= t << 16;
    t = (l >>> 4 ^ r) & 0x0f0f0f0f;
    r ^= t;
    l ^= t << 4;
    data.setUint32(offset, l);
    data.setUint32(offset + 4, r);
  }

  decryptBlock(data: DataView, offset: number) {
    let l = data.getUint32(offset);
    let r = data.getUint32(offset + 4);
    let t = (l >>> 4 ^ r) & 0x0f0f0f0f;
    r ^= t;
    l ^= t << 4;
    t = (l >>> 16 ^ r) & 0x0000ffff;
    r ^= t;
    l ^= t << 16;
    t = (r >>> 2 ^ l) & 0x33333333;
    l ^= t;
    r ^= t << 2;
    t = (r >>> 8 ^ l) & 0x00ff00ff;
    l ^= t;
    r ^= t << 8;
    t = (l >>> 1 ^ r) & 0x55555555;
    r ^= t;
    l ^= t << 1;
    l = l << 1 | l >>> 31;
    r = r << 1 | r >>> 31;

    for (let i = 30; i >= 0; i -= 2) {
      const r1 = r ^ this.#keys[i];
      const r2 = (r >>> 4 | r << 28) ^ this.#keys[i + 1];
      t = l, l = r;
      r = t ^ (
        SP2[r1 >>> 24 & 0x3f] |
        SP4[r1 >>> 16 & 0x3f] |
        SP6[r1 >>> 8 & 0x3f] |
        SP8[r1 & 0x3f] |
        SP1[r2 >>> 24 & 0x3f] |
        SP3[r2 >>> 16 & 0x3f] |
        SP5[r2 >>> 8 & 0x3f] |
        SP7[r2 & 0x3f]
      );
    }

    t = l, l = r, r = t;
    l = l >>> 1 | l << 31;
    r = r >>> 1 | r << 31;
    t = (l >>> 1 ^ r) & 0x55555555;
    r ^= t;
    l ^= t << 1;
    t = (r >>> 8 ^ l) & 0x00ff00ff;
    l ^= t;
    r ^= t << 8;
    t = (r >>> 2 ^ l) & 0x33333333;
    l ^= t;
    r ^= t << 2;
    t = (l >>> 16 ^ r) & 0x0000ffff;
    r ^= t;
    l ^= t << 16;
    t = (l >>> 4 ^ r) & 0x0f0f0f0f;
    r ^= t;
    l ^= t << 4;
    data.setInt32(offset, l);
    data.setInt32(offset + 4, r);
  }
}
