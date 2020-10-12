import { Padding } from "./mod.ts";

export function signedToUnsigned(signed: number): number {
  return signed >>> 0;
}

export function xor(a: number, b: number): number {
  return signedToUnsigned(a ^ b);
}

export function sumMod32(a: number, b: number): number {
  return signedToUnsigned((a + b) | 0);
}

// deno-fmt-ignore
export function packFourBytes(byte1: number, byte2: number, byte3: number, byte4: number) {
  return signedToUnsigned(byte1 << 24 | byte2 << 16 | byte3 << 8 | byte4);
}

export function unpackFourBytes(pack: number) {
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
      let i = 1;
      while (i <= 8) {
        const char = bytes[bytes.length - i];
        if (char === 0x80) {
          cutLength = i;
          break;
        }
        if (char !== 0) {
          break;
        }
        i++;
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
        i++;
      }
      break;
    }
  }
  return bytes.subarray(0, bytes.length - cutLength);
}
