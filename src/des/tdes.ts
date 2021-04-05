import { BlockCipher } from "../block-modes/base.ts";
import { Des } from "./mod.ts";

/**
 * Triple DES (3DES/TDES) block cipher.
 * 
 * Note: This is a low level class. Use a block cipher mode to
 * encrypt and decrypt data.
 */
export class TripleDes implements BlockCipher {
  /**
   * The block size of the block cipher in bytes
   */
  static readonly BLOCK_SIZE = 8;
  #des1: Des;
  #des2: Des;
  #des3: Des;

  constructor(key: Uint8Array) {
    if (key.length === 8) {
      this.#des1 = new Des(key);
      this.#des2 = new Des(key);
      this.#des3 = new Des(key);
    } else if (key.length === 16) {
      this.#des1 = new Des(key.subarray(0, 8));
      this.#des2 = new Des(key.subarray(8, 16));
      this.#des3 = new Des(key.subarray(0, 8));
    } else if (key.length === 24) {
      this.#des1 = new Des(key.subarray(0, 8));
      this.#des2 = new Des(key.subarray(8, 16));
      this.#des3 = new Des(key.subarray(16, 24));
    } else {
      throw new Error("Invalid key size (must be either 8, 16 or 24 bytes)");
    }
  }

  encryptBlock(data: DataView, offset: number) {
    this.#des1.encryptBlock(data, offset);
    this.#des2.encryptBlock(data, offset);
    this.#des3.encryptBlock(data, offset);
  }

  decryptBlock(data: DataView, offset: number) {
    this.#des3.decryptBlock(data, offset);
    this.#des2.decryptBlock(data, offset);
    this.#des1.decryptBlock(data, offset);
  }
}
