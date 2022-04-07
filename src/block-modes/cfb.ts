import { pad, Padding, unpad } from "../utils/padding.ts";
import { BlockCipher, BlockCipherClass, BlockCipherMode } from "./base.ts";

/**
 * Cipher feedback (CFB) mode of operation.
 */
export class Cfb<T extends BlockCipher> extends BlockCipherMode<T> {
  readonly #prev: DataView;

  constructor(
    chiper: BlockCipherClass<T>,
    key: Uint8Array,
    iv: Uint8Array,
    padding: Padding = Padding.NONE,
  ) {
    super(chiper, key, padding);
    this.checkIvSize(iv.length);

    this.#prev = new DataView(iv.buffer.slice(0));
  }

  encrypt(data: Uint8Array): Uint8Array {
    data = pad(data, this.padding, this.blockSize);

    const view = new DataView(data.buffer);
    const encrypted = new Uint8Array(data.length);
    const encryptedView = new DataView(encrypted.buffer);

    for (let i = 0; i < data.length; i += this.blockSize) {
      this.cipher.encryptBlock(this.#prev, 0);

      for (let j = 0; j < this.blockSize; j += 4) {
        encryptedView.setUint32(
          i + j,
          this.#prev.getUint32(j) ^ view.getUint32(i + j),
        );
      }

      for (let j = 0; j < this.blockSize; j += 4) {
        this.#prev.setUint32(j, encryptedView.getUint32(i + j));
      }
    }

    return encrypted;
  }

  decrypt(data: Uint8Array): Uint8Array {
    this.checkBlockSize(data.length);

    const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
    const decrypted = new Uint8Array(data.length);
    const decryptedView = new DataView(decrypted.buffer);

    for (let i = 0; i < data.length; i += this.blockSize) {
      this.cipher.encryptBlock(this.#prev, 0);

      for (let j = 0; j < this.blockSize; j += 4) {
        decryptedView.setUint32(
          i + j,
          this.#prev.getUint32(j) ^ view.getUint32(i + j),
        );
      }

      for (let j = 0; j < this.blockSize; j += 4) {
        this.#prev.setUint32(j, view.getUint32(i + j));
      }
    }
    return unpad(decrypted, this.padding, this.blockSize);
  }
}
