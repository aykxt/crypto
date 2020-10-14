/** Packs four bytes in big endian format */
export function packFourBytes(bytes: [number, number, number, number]) {
  return bytes[0] << 24 | bytes[1] << 16 | bytes[2] << 8 | bytes[3];
}

/** Unpacks four bytes in big endian format */
// deno-fmt-ignore
export function unpackFourBytes(pack: number): [number, number, number, number] {
  return [
    (pack >>> 24) & 0xFF,
    (pack >>> 16) & 0xFF,
    (pack >>> 8) & 0xFF,
    pack & 0xFF,
  ];
}

export function toUint8Array(val: string | Uint8Array): Uint8Array {
  if (typeof val === "string") {
    return new TextEncoder().encode(val);
  }
  return val;
}

export function expandKey(key: Uint8Array) {
  if (key.length >= 72) { // 576 bits -> 72 bytes
    return key;
  }
  const longKey = [];
  while (longKey.length < 72) {
    for (let i = 0; i < key.length; i++) {
      longKey.push(key[i]);
    }
  }
  return new Uint8Array(longKey);
}

export enum Padding {
  PKCS5,
  ONE_AND_ZEROS,
  LAST_BYTE,
  NULL,
  SPACES,
}

export function pad(bytes: Uint8Array, padding: Padding) {
  const count = 8 - bytes.length % 8;
  if (count === 8 && bytes.length > 0 && padding !== Padding.PKCS5) {
    return bytes;
  }
  const writer = new Uint8Array(bytes.length + count);
  const newBytes = [];
  let remaining = count;
  let padChar = 0;

  switch (padding) {
    case Padding.PKCS5: {
      padChar = count;
      break;
    }
    case Padding.ONE_AND_ZEROS: {
      newBytes.push(0x80);
      remaining--;
      break;
    }
    case Padding.SPACES: {
      padChar = 0x20;
      break;
    }
  }

  while (remaining > 0) {
    if (padding === Padding.LAST_BYTE && remaining === 1) {
      newBytes.push(count);
      break;
    }
    newBytes.push(padChar);
    remaining--;
  }

  writer.set(bytes);
  writer.set(newBytes, bytes.length);
  return writer;
}

export function unpad(bytes: Uint8Array, padding: Padding) {
  let cutLength = 0;
  switch (padding) {
    case Padding.LAST_BYTE:
    case Padding.PKCS5: {
      const lastChar = bytes[bytes.length - 1];
      if (lastChar <= 8) {
        cutLength = lastChar;
      }
      break;
    }
    case Padding.ONE_AND_ZEROS: {
      for (let i = 1; i <= 8; i++) {
        const char = bytes[bytes.length - i];
        if (char === 0x80) {
          cutLength = i;
          break;
        }
        if (char !== 0) {
          break;
        }
      }
      break;
    }
    case Padding.NULL:
    case Padding.SPACES: {
      const padChar = (padding === Padding.SPACES) ? 0x20 : 0;
      for (let i = 1; i <= 8; i++) {
        const char = bytes[bytes.length - i];
        if (char !== padChar) {
          cutLength = i - 1;
          break;
        }
      }
      break;
    }
  }
  return bytes.subarray(0, bytes.length - cutLength);
}
