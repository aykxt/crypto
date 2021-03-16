import { pad, Padding, unpad } from "../utils/padding.ts";
import { BlockCipher, BlockCipherClass, BlockCipherMode } from "./base.ts";

/**
 * Cipher block chaining (CBC) mode of operation.
 */
export class Cbc<T extends BlockCipher> extends BlockCipherMode<T> {
  readonly #prev: DataView;

  constructor(
    cipher: BlockCipherClass<T>,
    key: Uint8Array,
    iv: Uint8Array,
    padding: Padding = Padding.NONE,
  ) {
    super(cipher, key, padding);
    this.checkIvSize(iv.length);
    this.#prev = new DataView(iv.buffer.slice(iv.byteOffset, iv.byteLength));
  }

  encrypt(data: Uint8Array): Uint8Array {
    data = pad(data, this.padding, this.blockSize);

    const encrypted = data.slice();
    const encryptedView = new DataView(encrypted.buffer);

    for (let i = 0; i < encrypted.length; i += this.blockSize) {
      for (let j = 0; j < this.blockSize; j += 4) {
        encryptedView.setUint32(
          i + j,
          encryptedView.getUint32(i + j) ^ this.#prev.getUint32(j),
        );
      }

      this.cipher.encryptBlock(encryptedView, i);

      for (let j = 0; j < this.blockSize; j += 4) {
        this.#prev.setUint32(j, encryptedView.getUint32(i + j));
      }
    }

    return encrypted;
  }

  decrypt(data: Uint8Array): Uint8Array {
    this.checkBlockSize(data.length);

    const view = new DataView(data.buffer);
    const decrypted = data.slice();
    const decryptedView = new DataView(decrypted.buffer);

    for (let i = 0; i < decrypted.length; i += this.blockSize) {
      this.cipher.decryptBlock(decryptedView, i);

      for (let j = 0; j < this.blockSize; j += 4) {
        decryptedView.setUint32(
          i + j,
          decryptedView.getUint32(i + j) ^ this.#prev.getUint32(j),
        );
      }

      for (let j = 0; j < this.blockSize; j += 4) {
        this.#prev.setUint32(j, view.getUint32(i + j));
      }
    }

    return unpad(decrypted, this.padding, this.blockSize);
  }
}
