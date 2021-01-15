export enum Padding {
  NONE = 1,
  PKCS7,
  ONE_AND_ZEROS,
  LAST_BYTE,
  NULL,
  SPACES,
}

export function pad(bytes: Uint8Array, padding: Padding, blockSize: number) {
  if (padding === Padding.NONE) {
    if (bytes.length % blockSize === 0) return bytes;
    else throw new Error("Block size is incorrect.");
  }

  const count = blockSize - bytes.length % blockSize;

  if (count === blockSize && bytes.length > 0 && padding !== Padding.PKCS7) {
    return bytes;
  }

  const writer = new Uint8Array(bytes.length + count);
  const newBytes = [];
  let remaining = count;
  let padChar = 0;

  switch (padding) {
    case Padding.PKCS7: {
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

export function unpad(bytes: Uint8Array, padding: Padding, blockSize: number) {
  let cutLength = 0;
  switch (padding) {
    case Padding.NONE: {
      return bytes;
    }
    case Padding.LAST_BYTE:
    case Padding.PKCS7: {
      const lastChar = bytes[bytes.length - 1];
      if (lastChar <= blockSize) {
        cutLength = lastChar;
      }
      break;
    }
    case Padding.ONE_AND_ZEROS: {
      for (let i = 1; i <= blockSize; i++) {
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
      for (let i = 1; i <= blockSize; i++) {
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
