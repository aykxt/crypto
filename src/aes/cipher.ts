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

    const encrypted = data.slice();

    for (let i = 0; i < data.length; i += AES.BLOCK_SIZE) {
      this.#aes.encrypt(encrypted.subarray(i, i + AES.BLOCK_SIZE));
    }

    return encrypted;
  }

  decrypt(data: Uint8Array): Uint8Array {
    if ((data.length % AES.BLOCK_SIZE) !== 0) {
      throw new Error("invalid data size (must be multiple of 16 bytes)");
    }

    const decrypted = data.slice();

    for (let i = 0; i < data.length; i += AES.BLOCK_SIZE) {
      this.#aes.decrypt(decrypted.subarray(i, i + AES.BLOCK_SIZE));
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
    if (iv.length != AES.BLOCK_SIZE) {
      throw new Error("invalid initialation vector size (must be 16 bytes)");
    }

    this.#prev = iv;
    this.#aes = new AES(key);
  }

  encrypt(data: Uint8Array): Uint8Array {
    data = pad(data, this.padding, AES.BLOCK_SIZE);

    const encrypted = data.slice();

    for (let i = 0; i < data.length; i += AES.BLOCK_SIZE) {
      const block = encrypted.subarray(i, i + AES.BLOCK_SIZE);

      for (let j = 0; j < AES.BLOCK_SIZE; j++) {
        block[j] ^= this.#prev[j];
      }

      this.#aes.encrypt(block);
      this.#prev = block;
    }

    return encrypted;
  }

  decrypt(data: Uint8Array): Uint8Array {
    if ((data.length % 16) !== 0) {
      throw new Error("invalid data size (must be multiple of 16 bytes)");
    }

    const decrypted = data.slice();

    for (let i = 0; i < data.length; i += AES.BLOCK_SIZE) {
      const block = decrypted.subarray(i, i + AES.BLOCK_SIZE);
      this.#aes.decrypt(block);

      for (let j = 0; j < AES.BLOCK_SIZE; j++) {
        block[j] ^= this.#prev[j];
      }

      this.#prev = data.subarray(i, i + AES.BLOCK_SIZE);
    }

    return unpad(decrypted, this.padding, AES.BLOCK_SIZE);
  }
}
