import { AES } from "./aes.ts";
import { pad, Padding, unpad } from "../utils/padding.ts";
import type { BlockCipher } from "../common/blockcipher.ts";

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
    const encryptedView = new DataView(encrypted.buffer);

    for (let i = 0; i < encrypted.length; i += AES.BLOCK_SIZE) {
      this.#aes.encrypt(encryptedView, i);
    }

    return encrypted;
  }

  decrypt(data: Uint8Array): Uint8Array {
    checkBlockSize(data.length);

    const decrypted = data.slice();
    const decryptedView = new DataView(decrypted.buffer);

    for (let i = 0; i < decrypted.length; i += AES.BLOCK_SIZE) {
      this.#aes.decrypt(decryptedView, i);
    }

    return unpad(decrypted, this.padding, AES.BLOCK_SIZE);
  }
}

export class AesCbc implements BlockCipher {
  #aes: AES;
  #prev: DataView;

  constructor(
    key: Uint8Array,
    iv: Uint8Array,
    private padding: Padding = Padding.NONE,
  ) {
    checkIvSize(iv.length);

    this.#prev = new DataView(iv.buffer.slice(iv.byteOffset, iv.byteLength));

    this.#aes = new AES(key);
  }

  encrypt(data: Uint8Array): Uint8Array {
    data = pad(data, this.padding, AES.BLOCK_SIZE);

    const encrypted = data.slice();
    const encryptedView = new DataView(encrypted.buffer);

    for (let i = 0; i < encrypted.length; i += AES.BLOCK_SIZE) {
      encryptedView.setUint32(
        i,
        encryptedView.getUint32(i) ^ this.#prev.getUint32(0),
      );
      encryptedView.setUint32(
        i + 4,
        encryptedView.getUint32(i + 4) ^ this.#prev.getUint32(4),
      );
      encryptedView.setUint32(
        i + 8,
        encryptedView.getUint32(i + 8) ^ this.#prev.getUint32(8),
      );
      encryptedView.setUint32(
        i + 12,
        encryptedView.getUint32(i + 12) ^ this.#prev.getUint32(12),
      );

      this.#aes.encrypt(encryptedView, i);

      this.#prev.setUint32(0, encryptedView.getUint32(i));
      this.#prev.setUint32(4, encryptedView.getUint32(i + 4));
      this.#prev.setUint32(8, encryptedView.getUint32(i + 8));
      this.#prev.setUint32(12, encryptedView.getUint32(i + 12));
    }

    return encrypted;
  }

  decrypt(data: Uint8Array): Uint8Array {
    checkBlockSize(data.length);

    const view = new DataView(data.buffer);
    const decrypted = data.slice();
    const decryptedView = new DataView(decrypted.buffer);

    for (let i = 0; i < decrypted.length; i += AES.BLOCK_SIZE) {
      this.#aes.decrypt(decryptedView, i);

      decryptedView.setUint32(
        i,
        decryptedView.getUint32(i) ^ this.#prev.getUint32(0),
      );
      decryptedView.setUint32(
        i + 4,
        decryptedView.getUint32(i + 4) ^ this.#prev.getUint32(4),
      );
      decryptedView.setUint32(
        i + 8,
        decryptedView.getUint32(i + 8) ^ this.#prev.getUint32(8),
      );
      decryptedView.setUint32(
        i + 12,
        decryptedView.getUint32(i + 12) ^ this.#prev.getUint32(12),
      );

      this.#prev.setUint32(0, view.getUint32(i));
      this.#prev.setUint32(4, view.getUint32(i + 4));
      this.#prev.setUint32(8, view.getUint32(i + 8));
      this.#prev.setUint32(12, view.getUint32(i + 12));
    }

    return unpad(decrypted, this.padding, AES.BLOCK_SIZE);
  }
}

export class AesCfb implements BlockCipher {
  #aes: AES;
  #prev: DataView;

  constructor(
    key: Uint8Array,
    iv: Uint8Array,
    private padding: Padding = Padding.NONE,
  ) {
    checkIvSize(iv.length);

    this.#prev = new DataView(iv.buffer.slice(0));
    this.#aes = new AES(key);
  }

  encrypt(data: Uint8Array): Uint8Array {
    data = pad(data, this.padding, AES.BLOCK_SIZE);

    const view = new DataView(data.buffer);
    const encrypted = new Uint8Array(data.length);
    const encryptedView = new DataView(encrypted.buffer);

    for (let i = 0; i < data.length; i += AES.BLOCK_SIZE) {
      this.#aes.encrypt(this.#prev, 0);

      encryptedView.setUint32(
        i,
        this.#prev.getUint32(0) ^ view.getUint32(i),
      );
      encryptedView.setUint32(
        i + 4,
        this.#prev.getUint32(4) ^ view.getUint32(i + 4),
      );
      encryptedView.setUint32(
        i + 8,
        this.#prev.getUint32(8) ^ view.getUint32(i + 8),
      );
      encryptedView.setUint32(
        i + 12,
        this.#prev.getUint32(12) ^ view.getUint32(i + 12),
      );

      this.#prev.setUint32(0, encryptedView.getUint32(i));
      this.#prev.setUint32(4, encryptedView.getUint32(i + 4));
      this.#prev.setUint32(8, encryptedView.getUint32(i + 8));
      this.#prev.setUint32(12, encryptedView.getUint32(i + 12));
    }

    return encrypted;
  }

  decrypt(data: Uint8Array): Uint8Array {
    checkBlockSize(data.length);

    const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
    const decrypted = new Uint8Array(data.length);
    const decryptedView = new DataView(decrypted.buffer);

    for (let i = 0; i < data.length; i += AES.BLOCK_SIZE) {
      this.#aes.encrypt(this.#prev, 0);

      decryptedView.setUint32(
        i,
        this.#prev.getUint32(0) ^ view.getUint32(i),
      );
      decryptedView.setUint32(
        i + 4,
        this.#prev.getUint32(4) ^ view.getUint32(i + 4),
      );
      decryptedView.setUint32(
        i + 8,
        this.#prev.getUint32(8) ^ view.getUint32(i + 8),
      );
      decryptedView.setUint32(
        i + 12,
        this.#prev.getUint32(12) ^ view.getUint32(i + 12),
      );

      this.#prev.setUint32(0, view.getUint32(i));
      this.#prev.setUint32(4, view.getUint32(i + 4));
      this.#prev.setUint32(8, view.getUint32(i + 8));
      this.#prev.setUint32(12, view.getUint32(i + 12));
    }
    return unpad(decrypted, this.padding, AES.BLOCK_SIZE);
  }
}

export class AesOfb implements BlockCipher {
  #aes: AES;
  #prev: DataView;

  constructor(
    key: Uint8Array,
    iv: Uint8Array,
  ) {
    checkIvSize(iv.length);

    this.#prev = new DataView(iv.buffer.slice(0));
    this.#aes = new AES(key);
  }

  encrypt(data: Uint8Array): Uint8Array {
    const encrypted = data.slice();
    const encryptedView = new DataView(encrypted.buffer);

    for (let i = 0; i < data.length; i += AES.BLOCK_SIZE) {
      this.#aes.encrypt(this.#prev, 0);

      encryptedView.setUint32(
        i,
        encryptedView.getUint32(i) ^ this.#prev.getUint32(0),
      );
      encryptedView.setUint32(
        i + 4,
        encryptedView.getUint32(i + 4) ^ this.#prev.getUint32(4),
      );
      encryptedView.setUint32(
        i + 8,
        encryptedView.getUint32(i + 8) ^ this.#prev.getUint32(8),
      );
      encryptedView.setUint32(
        i + 12,
        encryptedView.getUint32(i + 12) ^ this.#prev.getUint32(12),
      );
    }

    return encrypted;
  }

  decrypt = this.encrypt;
}
