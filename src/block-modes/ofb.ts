import { BlockCipher, BlockCipherClass, BlockCipherMode } from "./base.ts";

/**
 * Output feedback (OFB) mode of operation.
 */
export class Ofb<T extends BlockCipher> extends BlockCipherMode<T> {
  readonly #prev: DataView;

  constructor(
    cipher: BlockCipherClass<T>,
    key: Uint8Array,
    iv: Uint8Array,
  ) {
    super(cipher, key);
    this.checkIvSize(iv.length);

    this.#prev = new DataView(iv.buffer.slice(0));
  }

  encrypt(data: Uint8Array): Uint8Array {
    const encrypted = data.slice();
    const encryptedView = new DataView(encrypted.buffer);

    for (let i = 0; i < data.length; i += this.blockSize) {
      this.cipher.encryptBlock(this.#prev, 0);

      for (let j = 0; j < this.blockSize; j += 4) {
        encryptedView.setUint32(
          i + j,
          encryptedView.getUint32(i + j) ^ this.#prev.getUint32(j),
        );
      }
    }

    return encrypted;
  }

  // Encryption and decryption is symmetric
  decrypt = this.encrypt;
}
