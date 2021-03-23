import { BlockCipher, BlockCipherClass, BlockCipherMode } from "./base.ts";

/**
 * Counter (CTR) mode of operation.
 */
export class Ctr<T extends BlockCipher> extends BlockCipherMode<T> {
  #counter: DataView;
  #counterTmp: DataView;

  constructor(
    cipher: BlockCipherClass<T>,
    key: Uint8Array,
    iv: Uint8Array,
  ) {
    super(cipher, key);
    this.checkIvSize(iv.length);
    this.#counter = new DataView(
      iv.buffer.slice(iv.byteOffset, iv.byteOffset + iv.byteLength),
    );
    this.#counterTmp = new DataView(new ArrayBuffer(this.blockSize));
  }

  encrypt(data: Uint8Array): Uint8Array {
    const encrypted = data.slice();
    const encryptedView = new DataView(encrypted.buffer);
    for (let i = 0; i < encrypted.length; i += this.blockSize) {
      for (let j = 0; j < this.blockSize; j += 4) {
        this.#counterTmp.setUint32(j, this.#counter.getUint32(j));
      }

      this.cipher.encryptBlock(this.#counterTmp, 0);

      for (let j = 0; j < this.blockSize; j += 4) {
        encryptedView.setUint32(
          i + j,
          encryptedView.getUint32(i + j) ^ this.#counterTmp.getUint32(j),
        );
      }

      this.increment();
    }
    return encrypted;
  }

  decrypt = this.encrypt;

  private increment() {
    for (let i = this.blockSize - 4; i >= 0; i -= 4) {
      if (this.#counter.getUint32(i) === 0xffffffff) {
        this.#counter.setUint32(i, 0);
      } else {
        this.#counter.setUint32(i, this.#counter.getUint32(i) + 1);
        break;
      }
    }
  }
}
