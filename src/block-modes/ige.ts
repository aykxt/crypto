import { pad, Padding, unpad } from "../utils/padding.ts";
import { BlockCipher, BlockCipherClass, BlockCipherMode } from "./base.ts";

/**
 * Infinite Garble Extension (IGE) mode of operation.
 */
export class Ige<T extends BlockCipher> extends BlockCipherMode<T> {
  private iv1View: DataView;
  private iv2View: DataView;

  constructor(
    cipher: BlockCipherClass<T>,
    key: Uint8Array,
    iv: Uint8Array,
    padding: Padding = Padding.NONE,
  ) {
    super(cipher, key, padding);
    if (iv.byteLength !== this.blockSize * 2) {
      throw new Error("IV must be twice the block size");
    }

    this.iv1View = new DataView(iv.slice(0, this.blockSize).buffer);
    this.iv2View = new DataView(iv.slice(this.blockSize).buffer);
  }

  encrypt(data: Uint8Array): Uint8Array {
    data = pad(data, this.padding, this.blockSize);
    const dataView = new DataView(
      data.buffer,
      data.byteOffset,
      data.byteLength,
    );

    const encrypted = new Uint8Array(data.length);
    const encryptedView = new DataView(encrypted.buffer);

    for (let i = 0; i < data.length; i += this.blockSize) {
      for (let j = 0; j < this.blockSize; j += 4) {
        encryptedView.setUint32(
          i + j,
          dataView.getUint32(i + j) ^ this.iv1View.getUint32(j),
        );
      }

      this.cipher.encryptBlock(encryptedView, i);

      for (let j = 0; j < this.blockSize; j += 4) {
        encryptedView.setUint32(
          i + j,
          encryptedView.getUint32(i + j) ^ this.iv2View.getUint32(j),
        );

        this.iv1View.setUint32(j, encryptedView.getUint32(i + j));
        this.iv2View.setUint32(j, dataView.getUint32(i + j));
      }
    }

    return encrypted;
  }

  decrypt(data: Uint8Array): Uint8Array {
    this.checkBlockSize(data.length);
    const dataView = new DataView(
      data.buffer,
      data.byteOffset,
      data.byteLength,
    );
    const decrypted = new Uint8Array(data.length);
    const decryptedView = new DataView(decrypted.buffer);

    for (let i = 0; i < data.length; i += this.blockSize) {
      for (let j = 0; j < this.blockSize; j += 4) {
        decryptedView.setUint32(
          i + j,
          dataView.getUint32(i + j) ^ this.iv2View.getUint32(j),
        );
      }

      this.cipher.decryptBlock(decryptedView, i);

      for (let j = 0; j < this.blockSize; j += 4) {
        decryptedView.setUint32(
          i + j,
          decryptedView.getUint32(i + j) ^ this.iv1View.getUint32(j),
        );

        this.iv1View.setUint32(j, dataView.getUint32(i + j));
        this.iv2View.setUint32(j, decryptedView.getUint32(i + j));
      }
    }

    return unpad(decrypted, this.padding, this.blockSize);
  }
}
