import { BlockCipher } from "../block-modes/base.ts";
import { P, S } from "./consts.ts";

/**
 * Blowfish block cipher.
 *
 * Note: This is a low level class. Use a block cipher mode to
 * encrypt and decrypt data.
 */
export class Blowfish implements BlockCipher {
  /**
   * The block size of the block cipher in bytes.
   */
  static readonly BLOCK_SIZE = 8;

  readonly #p: Uint32Array = P.slice();
  readonly #s: [Uint32Array, Uint32Array, Uint32Array, Uint32Array] = [
    S[0].slice(),
    S[1].slice(),
    S[2].slice(),
    S[3].slice(),
  ];

  constructor(key: Uint8Array) {
    if (key.length < 4 || key.length > 56) {
      throw new Error("Invalid key size (must be between 4 and 56 bytes)");
    }

    const longKey: number[] = [];
    while (longKey.length < 72) {
      longKey.push(...key);
    }
    const keyView = new DataView(new Uint8Array(longKey).buffer);

    for (let i = 0, j = 0; i < 18; i++, j += 4) {
      this.#p[i] ^= keyView.getUint32(j);
    }
    const tmp = new DataView(new ArrayBuffer(8));

    for (let i = 0; i < 18; i += 2) {
      this.encryptBlock(tmp, 0);
      this.#p[i] = tmp.getUint32(0);
      this.#p[i + 1] = tmp.getUint32(4);
    }
    for (let i = 0; i < 4; i++) {
      for (let j = 0; j < 256; j += 2) {
        this.encryptBlock(tmp, 0);
        this.#s[i][j] = tmp.getUint32(0);
        this.#s[i][j + 1] = tmp.getUint32(4);
      }
    }
  }

  encryptBlock(data: DataView, offset: number) {
    let l = data.getUint32(offset);
    let r = data.getUint32(offset + 4);
    for (let i = 0; i < 16; i += 2) {
      l ^= this.#p[i];
      r ^= this.f(l);
      r ^= this.#p[i + 1];
      l ^= this.f(r);
    }
    data.setUint32(offset, r ^ this.#p[17]);
    data.setUint32(offset + 4, l ^ this.#p[16]);
  }

  decryptBlock(data: DataView, offset: number) {
    let l = data.getUint32(offset);
    let r = data.getUint32(offset + 4);
    for (let i = 16; i > 0; i -= 2) {
      l ^= this.#p[i + 1];
      r ^= this.f(l);
      r ^= this.#p[i];
      l ^= this.f(r);
    }
    data.setUint32(offset, r ^ this.#p[0]);
    data.setUint32(offset + 4, l ^ this.#p[1]);
  }

  private f(x: number): number {
    return ((this.#s[0][x >>> 24] + this.#s[1][x >>> 16 & 0xff]) ^
      this.#s[2][x >>> 8 & 0xff]) + this.#s[3][x & 0xff];
  }
}
