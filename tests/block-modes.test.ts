import { assertEquals, assertThrows } from "../dev_deps.ts";
import { Cbc, Cfb, Ctr, Ecb, Ofb } from "../block-modes.ts";
import { Aes } from "../aes.ts";

const key = new Uint8Array(16);
const iv = new Uint8Array(16);
const original = new Uint8Array(64);

// TODO: Test with test vectors

Deno.test("[Block Cipher Mode] Base", () => {
  assertThrows(
    () => {
      const cipher = new Ecb(Aes, key);
      cipher.decrypt(new Uint8Array(4));
    },
    Error,
    "Invalid data size (must be multiple of 16 bytes)",
  );

  assertThrows(
    () => {
      const cipher = new Cbc(Aes, key, new Uint8Array(4));
      cipher.encrypt(new Uint8Array(4));
    },
    Error,
    "Invalid initialization vector size (must be 16 bytes)",
  );
});

Deno.test("[Block Cipher Mode] ECB", () => {
  const cipher = new Ecb(Aes, key);
  const enc = cipher.encrypt(original);
  const dec = cipher.decrypt(enc);
  assertEquals(dec, original);
});

Deno.test("[Block Cipher Mode] CBC", () => {
  const cipher = new Cbc(Aes, key, iv);
  const decipher = new Cbc(Aes, key, iv);
  const enc = cipher.encrypt(original);
  const dec = decipher.decrypt(enc);
  assertEquals(dec, original);
});

Deno.test("[Block Cipher Mode] CFB ", () => {
  const original = new Uint8Array(32);
  const cipher = new Cfb(Aes, key, iv);
  const decipher = new Cfb(Aes, key, iv);
  const enc = cipher.encrypt(original);
  const dec = decipher.decrypt(enc);
  assertEquals(dec, original);
});

Deno.test("[Block Cipher Mode] OFB ", () => {
  const cipher = new Ofb(Aes, key, iv);
  const decipher = new Ofb(Aes, key, iv);
  const enc = cipher.encrypt(original);
  const dec = decipher.decrypt(enc);
  assertEquals(dec, original);
});

Deno.test("[Block Cipher Mode] CTR", () => {
  const cipher = new Ctr(Aes, key, iv);
  const decipher = new Ctr(Aes, key, iv);
  const enc = cipher.encrypt(original);
  const dec = decipher.decrypt(enc);
  assertEquals(dec, original);
});
