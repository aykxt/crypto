import { P, S0, S1, S2, S3 } from "./constants.ts";
import {
  expandKey,
  packFourBytes,
  pad,
  sumMod32,
  toUint8Array,
  unpackFourBytes,
  unpad,
  xor,
} from "./helpers.ts";

enum Mode {
  ECB,
  CBC,
}

export enum Padding {
  PKCS5,
  ONE_AND_ZEROS,
  LAST_BYTE,
  NULL,
  SPACES,
}

enum Type {
  STRING,
  BINARY,
}

interface BlowfishOptions {
  mode?: Mode;
  padding?: Padding;
  iv?: Uint8Array;
}

export default class Blowfish {
  static readonly ORIG_P = P;
  static readonly ORIG_S = [S0, S1, S2, S3];

  static readonly MODE = Mode;
  static readonly PADDING = Padding;
  static readonly TYPE = Type;

  mode: Mode;
  padding: Padding;
  iv?: Uint8Array;
  p = P.slice();
  s = [
    S0.slice(),
    S1.slice(),
    S2.slice(),
    S3.slice(),
  ];

  constructor(key: string | Uint8Array, options: BlowfishOptions = {}) {
    this.mode = options.mode || Mode.ECB;
    this.padding = options.padding || Padding.NULL;

    if (this.mode === Mode.CBC) {
      if (!options.iv) {
        throw new Error("IV is not set.");
      }
      if (options.iv.length !== 8) {
        throw new Error("IV should be 8 byte length.");
      }
      this.iv = options.iv;
    }

    key = expandKey(toUint8Array(key));
    for (let i = 0, j = 0; i < 18; i++, j += 4) {
      const n = packFourBytes(key[j], key[j + 1], key[j + 2], key[j + 3]);
      this.p[i] = xor(this.p[i], n);
    }
    let l = 0;
    let r = 0;
    for (let i = 0; i < 18; i += 2) {
      [l, r] = this.encryptBlock(l, r);
      this.p[i] = l;
      this.p[i + 1] = r;
    }
    for (let i = 0; i < 4; i++) {
      for (let j = 0; j < 256; j += 2) {
        [l, r] = this.encryptBlock(l, r);
        this.s[i][j] = l;
        this.s[i][j + 1] = r;
      }
    }
  }

  encode(data: string | Uint8Array) {
    data = pad(toUint8Array(data), this.padding);

    if (this.mode === Blowfish.MODE.ECB) {
      return this.encodeECB(data);
    } else {
      return this.encodeCBC(data);
    }
  }

  decode(input: string | Uint8Array, returnType?: Type.BINARY): Uint8Array;
  decode(input: string | Uint8Array, returnType: Type.STRING): string;
  decode(
    input: string | Uint8Array,
    returnType: Type = Blowfish.TYPE.BINARY,
  ) {
    let data = toUint8Array(input);

    if (data.length % 8 !== 0) {
      throw new Error("Input data should be multiple of 8 bytes");
    }

    switch (this.mode) {
      case Blowfish.MODE.ECB: {
        data = this.decodeECB(data);
        break;
      }
      case Blowfish.MODE.CBC: {
        data = this.decodeCBC(data);
        break;
      }
    }

    data = unpad(data, this.padding);

    if (returnType == Blowfish.TYPE.STRING) {
      const enc = new TextDecoder("utf-8");
      return enc.decode(data);
    }
    return data;
  }

  private encryptBlock(l: number, r: number) {
    for (let i = 0; i < 16; i++) {
      l = xor(l, this.p[i]);
      r = xor(r, this.f(l));
      [l, r] = [r, l];
    }
    [l, r] = [r, l];
    r = xor(r, this.p[16]);
    l = xor(l, this.p[17]);
    return [l, r];
  }

  private decryptBlock(l: number, r: number) {
    for (let i = 17; i > 1; i--) {
      l = xor(l, this.p[i]);
      r = xor(r, this.f(l));
      [l, r] = [r, l];
    }
    [l, r] = [r, l];
    r = xor(r, this.p[1]);
    l = xor(l, this.p[0]);
    return [l, r];
  }

  private f(x: number) {
    const a = (x >>> 24) & 0xFF;
    const b = (x >>> 16) & 0xFF;
    const c = (x >>> 8) & 0xFF;
    const d = x & 0xFF;

    let res = sumMod32(this.s[0][a], this.s[1][b]);
    res = xor(res, this.s[2][c]);
    return sumMod32(res, this.s[3][d]);
  }

  private encodeECB(bytes: Uint8Array) {
    const encoded = new Uint8Array(bytes.length);
    for (let i = 0; i < bytes.length; i += 8) {
      let l = packFourBytes(bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]);
      let r = packFourBytes(
        bytes[i + 4],
        bytes[i + 5],
        bytes[i + 6],
        bytes[i + 7],
      );
      [l, r] = this.encryptBlock(l, r);
      encoded.set(unpackFourBytes(l), i);
      encoded.set(unpackFourBytes(r), i + 4);
    }
    return encoded;
  }

  private encodeCBC(bytes: Uint8Array) {
    const encoded = new Uint8Array(bytes.length);
    let prevL = packFourBytes(
      this.iv![0],
      this.iv![1],
      this.iv![2],
      this.iv![3],
    );
    let prevR = packFourBytes(
      this.iv![4],
      this.iv![5],
      this.iv![6],
      this.iv![7],
    );
    for (let i = 0; i < bytes.length; i += 8) {
      let l = packFourBytes(bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]);
      let r = packFourBytes(
        bytes[i + 4],
        bytes[i + 5],
        bytes[i + 6],
        bytes[i + 7],
      );
      [l, r] = [xor(prevL, l), xor(prevR, r)];
      [l, r] = this.encryptBlock(l, r);
      [prevL, prevR] = [l, r];
      encoded.set(unpackFourBytes(l), i);
      encoded.set(unpackFourBytes(r), i + 4);
    }
    return encoded;
  }

  private decodeECB(bytes: Uint8Array) {
    const decoded = new Uint8Array(bytes.length);
    for (let i = 0; i < bytes.length; i += 8) {
      let l = packFourBytes(bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]);
      let r = packFourBytes(
        bytes[i + 4],
        bytes[i + 5],
        bytes[i + 6],
        bytes[i + 7],
      );
      [l, r] = this.decryptBlock(l, r);
      decoded.set(unpackFourBytes(l), i);
      decoded.set(unpackFourBytes(r), i + 4);
    }
    return decoded;
  }

  private decodeCBC(bytes: Uint8Array) {
    const decoded = new Uint8Array(bytes.length);
    let prevL = packFourBytes(
      this.iv![0],
      this.iv![1],
      this.iv![2],
      this.iv![3],
    );
    let prevR = packFourBytes(
      this.iv![4],
      this.iv![5],
      this.iv![6],
      this.iv![7],
    );
    let prevLTmp;
    let prevRTmp;
    for (let i = 0; i < bytes.length; i += 8) {
      let l = packFourBytes(bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]);
      let r = packFourBytes(
        bytes[i + 4],
        bytes[i + 5],
        bytes[i + 6],
        bytes[i + 7],
      );
      [prevLTmp, prevRTmp] = [l, r];
      [l, r] = this.decryptBlock(l, r);
      [l, r] = [xor(prevL, l), xor(prevR, r)];
      [prevL, prevR] = [prevLTmp, prevRTmp];
      decoded.set(unpackFourBytes(l), i);
      decoded.set(unpackFourBytes(r), i + 4);
    }
    return decoded;
  }
}
