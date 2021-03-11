import { Blowfish } from "./blowfish.ts";
import { pad, Padding, unpad } from "../utils/padding.ts";
import { BlockCipher } from "../common/blockcipher.ts";

export class BlowfishEcb implements BlockCipher {
  #bf: Blowfish;

  constructor(
    key: Uint8Array,
    private padding: Padding = Padding.NONE,
  ) {
    this.#bf = new Blowfish(key);
  }

  encrypt(data: Uint8Array): Uint8Array {
    data = pad(data, this.padding, Blowfish.BLOCK_SIZE);
    const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
    const encrypted = new Uint8Array(data.length);
    const encryptedView = new DataView(encrypted.buffer);
    for (let i = 0; i < data.length; i += Blowfish.BLOCK_SIZE) {
      let l = view.getUint32(i);
      let r = view.getUint32(i + 4);
      [l, r] = this.#bf.encrypt(l, r);
      encryptedView.setUint32(i, l);
      encryptedView.setUint32(i + 4, r);
    }
    return encrypted;
  }

  decrypt(data: Uint8Array): Uint8Array {
    if ((data.length % Blowfish.BLOCK_SIZE) !== 0) {
      throw new Error("invalid data size (must be multiple of 8 bytes)");
    }

    const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
    const decrypted = new Uint8Array(data.length);
    const decodedView = new DataView(decrypted.buffer);
    for (let i = 0; i < data.length; i += Blowfish.BLOCK_SIZE) {
      let l = view.getUint32(i);
      let r = view.getUint32(i + 4);
      [l, r] = this.#bf.decrypt(l, r);
      decodedView.setUint32(i, l);
      decodedView.setUint32(i + 4, r);
    }
    return unpad(decrypted, this.padding, Blowfish.BLOCK_SIZE);
  }
}

export class BlowfishCbc implements BlockCipher {
  #bf: Blowfish;
  #prevL: number;
  #prevR: number;

  constructor(
    key: Uint8Array,
    iv: Uint8Array,
    private padding: Padding = Padding.NONE,
  ) {
    if (iv.length != Blowfish.BLOCK_SIZE) {
      throw new Error("Invalid initialization vector size (must be 8 bytes)");
    }

    const ivView = new DataView(iv.buffer, iv.byteOffset, iv.byteLength);

    this.#prevL = ivView.getUint32(0);
    this.#prevR = ivView.getUint32(4);
    this.#bf = new Blowfish(key);
  }

  encrypt(data: Uint8Array): Uint8Array {
    data = pad(data, this.padding, Blowfish.BLOCK_SIZE);

    const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
    const encrypted = new Uint8Array(data.length);
    const encryptedView = new DataView(encrypted.buffer);
    for (let i = 0; i < data.length; i += Blowfish.BLOCK_SIZE) {
      let l = view.getUint32(i);
      let r = view.getUint32(i + 4);
      [l, r] = [this.#prevL ^ l, this.#prevR ^ r];
      [l, r] = this.#bf.encrypt(l, r);
      [this.#prevL, this.#prevR] = [l, r];
      encryptedView.setUint32(i, l);
      encryptedView.setUint32(i + 4, r);
    }
    return encrypted;
  }

  decrypt(data: Uint8Array): Uint8Array {
    if ((data.length % Blowfish.BLOCK_SIZE) !== 0) {
      throw new Error("Invalid data size (must be multiple of 8 data)");
    }

    const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
    const decrypted = new Uint8Array(data.length);
    const decryptedView = new DataView(decrypted.buffer);

    let prevLTmp;
    let prevRTmp;
    for (let i = 0; i < data.length; i += Blowfish.BLOCK_SIZE) {
      let l = view.getUint32(i);
      let r = view.getUint32(i + 4);
      [prevLTmp, prevRTmp] = [l, r];
      [l, r] = this.#bf.decrypt(l, r);
      [l, r] = [this.#prevL ^ l, this.#prevR ^ r];
      [this.#prevL, this.#prevR] = [prevLTmp, prevRTmp];
      decryptedView.setUint32(i, l);
      decryptedView.setUint32(i + 4, r);
    }

    return unpad(decrypted, this.padding, Blowfish.BLOCK_SIZE);
  }
}
