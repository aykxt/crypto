import { assertEquals, assertThrows } from "../dev_deps.ts";
import { Aes } from "../aes.ts";
import { Cbc, Cfb, Ctr, Ecb, Ofb } from "../block-modes.ts";

// deno-fmt-ignore
const iv = new Uint8Array([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]);
// deno-fmt-ignore
const original = new Uint8Array([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]);

Deno.test("AES-128-ECB ", () => {
  // deno-fmt-ignore
  const key = new Uint8Array([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]);
  const cipher = new Ecb(Aes, key);

  const enc = cipher.encrypt(original);
  // deno-fmt-ignore
  const expectedEnc = new Uint8Array([52,195,59,127,20,253,83,220,234,37,224,26,2,225,103,39,52,195,59,127,20,253,83,220,234,37,224,26,2,225,103,39]);

  assertEquals(enc, expectedEnc);

  const dec = cipher.decrypt(enc);
  assertEquals(dec, original);

  assertThrows(
    () => {
      new Ecb(Aes, new Uint8Array(17));
    },
    Error,
    "Invalid key size (must be either 16, 24 or 32 bytes)",
  );
});

Deno.test("AES-192-ECB", () => {
  // deno-fmt-ignore
  const key = new Uint8Array([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24]);
  const cipher = new Ecb(Aes, key);

  const enc = cipher.encrypt(original);
  const dec = cipher.decrypt(enc);

  assertEquals(dec, original);
});

Deno.test("AES-256-ECB", () => {
  // deno-fmt-ignore
  const key = new Uint8Array([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32]);
  const cipher = new Ecb(Aes, key);

  const enc = cipher.encrypt(original);
  const dec = cipher.decrypt(enc);

  assertEquals(dec, original);
});

Deno.test("AES-128-CBC", () => {
  // deno-fmt-ignore
  const key = new Uint8Array([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]);
  const cipher = new Cbc(Aes, key, iv);
  const decipher = new Cbc(Aes, key, iv);

  const enc = cipher.encrypt(original);
  const dec = decipher.decrypt(enc);

  assertEquals(dec, original);
});

Deno.test("AES-128-CFB ", () => {
  // deno-fmt-ignore
  const key = new Uint8Array([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]);
  const iv = new Uint8Array(16);

  const original = new Uint8Array(32);

  const cipher = new Cfb(Aes, key, iv);
  const decipher = new Cfb(Aes, key, iv);

  const enc = cipher.encrypt(original);
  const dec = decipher.decrypt(enc);

  assertEquals(dec, original);
});

Deno.test("AES-128-OFB ", () => {
  // deno-fmt-ignore
  const key = new Uint8Array([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]);
  const iv = new Uint8Array(16);

  const original = new Uint8Array(32);

  const cipher = new Ofb(Aes, key, iv);
  const decipher = new Ofb(Aes, key, iv);

  const enc = cipher.encrypt(original);
  const dec = decipher.decrypt(enc);

  assertEquals(dec, original);
});

Deno.test("AES-128-CTR ", () => {
  // deno-fmt-ignore
  const key = new Uint8Array([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]);
  const iv = new Uint8Array(16);

  const original = new Uint8Array(32);

  const cipher = new Ctr(Aes, key, iv);
  const decipher = new Ctr(Aes, key, iv);

  const enc = cipher.encrypt(original);
  const dec = decipher.decrypt(enc);

  assertEquals(dec, original);
});
