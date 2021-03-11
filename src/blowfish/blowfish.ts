import { P, S } from "./consts.ts";

export class Blowfish {
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
      throw new Error("Invalid key length");
    }

    const longKey: number[] = [];
    while (longKey.length < 72) {
      longKey.push(...key);
    }
    const keyView = new DataView(new Uint8Array(longKey).buffer);

    for (let i = 0, j = 0; i < 18; i++, j += 4) {
      this.#p[i] ^= keyView.getUint32(j);
    }
    let l = 0;
    let r = 0;
    for (let i = 0; i < 18; i += 2) {
      [l, r] = this.encrypt(l, r);
      this.#p[i] = l;
      this.#p[i + 1] = r;
    }
    for (let i = 0; i < 4; i++) {
      for (let j = 0; j < 256; j += 2) {
        [l, r] = this.encrypt(l, r);
        this.#s[i][j] = l;
        this.#s[i][j + 1] = r;
      }
    }
  }

  encrypt(l: number, r: number): [number, number] {
    for (let i = 0; i < 16; i += 2) {
      l ^= this.#p[i];
      r ^= this.f(l);
      r ^= this.#p[i + 1];
      l ^= this.f(r);
    }
    l ^= this.#p[16];
    r ^= this.#p[17];
    return [r, l];
  }

  decrypt(l: number, r: number): [number, number] {
    for (let i = 16; i > 0; i -= 2) {
      l ^= this.#p[i + 1];
      r ^= this.f(l);
      r ^= this.#p[i];
      l ^= this.f(r);
    }
    l ^= this.#p[1];
    r ^= this.#p[0];
    return [r, l];
  }

  private f(x: number): number {
    return ((this.#s[0][x >>> 24] + this.#s[1][x >>> 16 & 0xff]) ^
      this.#s[2][x >>> 8 & 0xff]) + this.#s[3][x & 0xff];
  }
}
