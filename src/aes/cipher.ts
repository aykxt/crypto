import { AES } from "./aes.ts";
import { pad, Padding, unpad } from "../utils/padding.ts";
import { BlockCipher } from "../common/blockcipher.ts";

export class AesEcb implements BlockCipher {
  #aes: AES;

  constructor(
    key: Uint8Array,
    private padding: Padding = Padding.NONE,
  ) {
    this.#aes = new AES(key);
  }

  encrypt(data: Uint8Array): Uint8Array {
    data = pad(data, this.padding, AES.BLOCK_SIZE);

    const encrypted = new Uint8Array(data.length);

    for (let i = 0; i < data.length; i += 16) {
      const block = data.slice(i, i + 16);
      encrypted.set(this.#aes.encrypt(block), i);
    }

    return encrypted;
  }

  decrypt(data: Uint8Array): Uint8Array {
    if ((data.length % 16) !== 0) {
      throw new Error("invalid data size (must be multiple of 16 bytes)");
    }

    const decrypted = new Uint8Array(data.length);

    for (let i = 0; i < data.length; i += 16) {
      const block = data.slice(i, i + 16);
      decrypted.set(this.#aes.decrypt(block), i);
    }

    return unpad(decrypted, this.padding, AES.BLOCK_SIZE);
  }
}

export class AesCbc implements BlockCipher {
  #aes: AES;
  #prev: Uint8Array;

  constructor(
    key: Uint8Array,
    iv: Uint8Array,
    private padding: Padding = Padding.NONE,
  ) {
    if (iv.length != 16) {
      throw new Error("invalid initialation vector size (must be 16 bytes)");
    }

    this.#prev = iv;
    this.#aes = new AES(key);
  }

  encrypt(data: Uint8Array): Uint8Array {
    data = pad(data, this.padding, AES.BLOCK_SIZE);

    const encrypted = new Uint8Array(data.length);

    for (let i = 0; i < data.length; i += 16) {
      const block = data.slice(i, i + 16);

      for (let j = 0; j < 16; j++) {
        block[j] ^= this.#prev[j];
      }

      this.#prev = this.#aes.encrypt(block);
      encrypted.set(this.#prev, i);
    }

    return encrypted;
  }

  decrypt(data: Uint8Array): Uint8Array {
    if ((data.length % 16) !== 0) {
      throw new Error("invalid data size (must be multiple of 16 bytes)");
    }

    const decrypted = new Uint8Array(data.length);

    for (let i = 0; i < data.length; i += 16) {
      const block = this.#aes.decrypt(data.slice(i, i + 16));

      for (let j = 0; j < 16; j++) {
        decrypted[i + j] = block[j] ^ this.#prev[j];
      }

      this.#prev = data.slice(i, i + 16);
    }

    return unpad(decrypted, this.padding, AES.BLOCK_SIZE);
  }
}
