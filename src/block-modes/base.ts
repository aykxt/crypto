import { Padding } from "../utils/padding.ts";

/**
 * This is a low level class. Use a block cipher mode to encrypt and decrypt
 * data 
 */
export interface BlockCipherClass<T extends BlockCipher> {
  /**
   * The block size of the block cipher in bytes
   */
  readonly BLOCK_SIZE: number;
  new (key: Uint8Array): T;
}

export interface BlockCipher {
  /**
   * Encrypts the next block at the given offset.
   */
  encryptBlock(data: DataView, offset: number): void;
  /**
   * Decrypts the next block at the given offset.
   */
  decryptBlock(data: DataView, offset: number): void;
}

/**
 * Block cipher mode of operation.
 */
export abstract class BlockCipherMode<T extends BlockCipher> {
  protected readonly cipher: BlockCipher;
  protected readonly blockSize: number;
  protected readonly padding: Padding;

  constructor(
    cipher: BlockCipherClass<T>,
    key: Uint8Array,
    padding: Padding = Padding.NONE,
  ) {
    this.cipher = new cipher(key);
    this.blockSize = cipher.BLOCK_SIZE;
    this.padding = padding;
  }

  abstract encrypt(data: Uint8Array): Uint8Array;
  abstract decrypt(data: Uint8Array): Uint8Array;

  protected checkBlockSize(size: number) {
    if (size % this.blockSize !== 0) {
      throw new Error(
        `Invalid data size (must be multiple of ${this.blockSize} bytes)`,
      );
    }
  }

  protected checkIvSize(size: number) {
    if (size != this.blockSize) {
      throw new Error(
        `Invalid initialization vector size (must be ${this.blockSize} bytes)`,
      );
    }
  }
}
