import { AES } from "./aes.ts";
import { pad, Padding, unpad } from "../utils/padding.ts";
import { BlockCipher } from "../common/blockcipher.ts";

function checkBlockSize(size: number) {
  if (size % AES.BLOCK_SIZE !== 0) {
    throw new Error("Invalid data size (must be multiple of 16 bytes)");
  }
}

function checkIvSize(size: number) {
  if (size != AES.BLOCK_SIZE) {
    throw new Error("Invalid initialization vector size (must be 16 bytes)");
  }
}

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
    checkBlockSize(data.length);

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
    checkIvSize(iv.length);

    this.#prev = iv.slice();
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

    this.#prev = this.#prev.slice();
    return encrypted;
  }

  decrypt(data: Uint8Array): Uint8Array {
    checkBlockSize(data.length);

    const decrypted = data.slice();

    for (let i = 0; i < data.length; i += AES.BLOCK_SIZE) {
      const block = decrypted.subarray(i, i + AES.BLOCK_SIZE);
      this.#aes.decrypt(block);

      for (let j = 0; j < AES.BLOCK_SIZE; j++) {
        block[j] ^= this.#prev[j];
      }

      this.#prev = data.subarray(i, i + AES.BLOCK_SIZE);
    }

    this.#prev = this.#prev.slice();
    return unpad(decrypted, this.padding, AES.BLOCK_SIZE);
  }
}

export class AesCfb implements BlockCipher {
  #aes: AES;
  #prev: Uint8Array;

  constructor(
    key: Uint8Array,
    iv: Uint8Array,
    private padding: Padding = Padding.NONE,
  ) {
    checkIvSize(iv.length);

    this.#prev = iv.slice();
    this.#aes = new AES(key);
  }

  encrypt(data: Uint8Array): Uint8Array {
    data = pad(data, this.padding, AES.BLOCK_SIZE);

    const encrypted = new Uint8Array(data.length);

    for (let i = 0; i < data.length; i += AES.BLOCK_SIZE) {
      this.#aes.encrypt(this.#prev);

      for (let j = 0; j < AES.BLOCK_SIZE; j++) {
        encrypted[i + j] = this.#prev[j] ^ data[i + j];
      }

      this.#prev = encrypted.slice(i, i + AES.BLOCK_SIZE);
    }

    return encrypted;
  }

  decrypt(data: Uint8Array): Uint8Array {
    checkBlockSize(data.length);

    const decrypted = new Uint8Array(data.length);

    for (let i = 0; i < data.length; i += 16) {
      this.#aes.encrypt(this.#prev);

      for (let j = 0; j < 16; j++) {
        decrypted[i + j] = this.#prev[j] ^ data[i + j];
      }

      this.#prev = data.subarray(i, i + 16);
    }

    this.#prev = this.#prev.slice();
    return unpad(decrypted, this.padding, AES.BLOCK_SIZE);
  }
}

export class AesOfb implements BlockCipher {
  #aes: AES;
  #prev: Uint8Array;

  constructor(
    key: Uint8Array,
    iv: Uint8Array,
  ) {
    checkIvSize(iv.length);

    this.#prev = iv.slice();
    this.#aes = new AES(key);
  }

  encrypt(data: Uint8Array): Uint8Array {
    const encrypted = data.slice();

    for (let i = 0; i < data.length; i += AES.BLOCK_SIZE) {
      this.#aes.encrypt(this.#prev);

      for (let j = 0; j < AES.BLOCK_SIZE; j++) {
        encrypted[i + j] ^= this.#prev[j];
      }
    }

    return encrypted;
  }

  decrypt = this.encrypt;
}
