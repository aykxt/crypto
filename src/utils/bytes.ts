export function bytesToWords(bytes: Uint8Array): Uint32Array {
  const dataView = new DataView(
    bytes.buffer,
    bytes.byteOffset,
    bytes.byteLength,
  );
  const words = new Uint32Array(bytes.length / 4);
  for (let i = 0; i < words.length; i++) {
    words[i] = dataView.getUint32(i * 4);
  }
  return words;
}
