export const S = new DataView(new ArrayBuffer(256));
export const SI = new DataView(new ArrayBuffer(256));

export const T1 = new DataView(new ArrayBuffer(1024));
export const T2 = new DataView(new ArrayBuffer(1024));
export const T3 = new DataView(new ArrayBuffer(1024));
export const T4 = new DataView(new ArrayBuffer(1024));
export const T5 = new DataView(new ArrayBuffer(1024));
export const T6 = new DataView(new ArrayBuffer(1024));
export const T7 = new DataView(new ArrayBuffer(1024));
export const T8 = new DataView(new ArrayBuffer(1024));

const d = new Uint8Array(256);
const t = new Uint8Array(256);

for (let i = 0; i < 256; i++) {
  d[i] = i << 1 ^ (i >> 7) * 283;
  t[d[i] ^ i] = i;
}

let x2, x4, x8, s, tEnc, tDec, xInv = 0;

for (let x = 0; !S.getUint8(x); x ^= x2 || 1) {
  s = xInv ^ xInv << 1 ^ xInv << 2 ^ xInv << 3 ^ xInv << 4;
  s = s >> 8 ^ s & 255 ^ 99;

  S.setUint8(x, s);
  SI.setUint8(s, x);

  x8 = d[x4 = d[x2 = d[x]]];
  tDec = x8 * 0x1010101 ^ x4 * 0x10001 ^ x2 * 0x101 ^ x * 0x1010100;
  tEnc = d[s] * 0x101 ^ s * 0x1010100;

  const i = x * 4;

  tEnc = tEnc << 24 ^ tEnc >>> 8;
  T1.setUint32(i, tEnc);
  tEnc = tEnc << 24 ^ tEnc >>> 8;
  T2.setUint32(i, tEnc);
  tEnc = tEnc << 24 ^ tEnc >>> 8;
  T3.setUint32(i, tEnc);
  tEnc = tEnc << 24 ^ tEnc >>> 8;
  T4.setUint32(i, tEnc);

  tDec = tDec << 24 ^ tDec >>> 8;
  T5.setUint32(s * 4, tDec);
  tDec = tDec << 24 ^ tDec >>> 8;
  T6.setUint32(s * 4, tDec);
  tDec = tDec << 24 ^ tDec >>> 8;
  T7.setUint32(s * 4, tDec);
  tDec = tDec << 24 ^ tDec >>> 8;
  T8.setUint32(s * 4, tDec);

  xInv = t[xInv] || 1;
}
