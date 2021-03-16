import { pad, Padding, unpad } from "../utils/padding.ts";
import { BlockCipher, BlockCipherClass, BlockCipherMode } from "./base.ts";

/**
 * Electronic codebook (ECB) mode of operation.
 */
export class Ecb<T extends BlockCipher> extends BlockCipherMode<T> {
  constructor(
    cipher: BlockCipherClass<T>,
    key: Uint8Array,
    padding: Padding = Padding.NONE,
  ) {
    super(cipher, key, padding);
  }

  encrypt(data: Uint8Array): Uint8Array {
    data = pad(data, this.padding, this.blockSize);
    const encrypted = data.slice();
    const encryptedView = new DataView(encrypted.buffer);
    for (let i = 0; i < data.length; i += this.blockSize) {
      this.cipher.encryptBlock(encryptedView, i);
    }
    return encrypted;
  }

  decrypt(data: Uint8Array): Uint8Array {
    this.checkBlockSize(data.length);
    const decrypted = data.slice();
    const decryptedView = new DataView(decrypted.buffer);
    for (let i = 0; i < data.length; i += this.blockSize) {
      this.cipher.decryptBlock(decryptedView, i);
    }
    return unpad(decrypted, this.padding, this.blockSize);
  }
}
