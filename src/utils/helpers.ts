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