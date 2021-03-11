import { assertEquals } from "../dev_deps.ts";
import { AesCbc, AesEcb } from "../aes.ts";

// deno-fmt-ignore
const iv = new Uint8Array([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]);
// deno-fmt-ignore
const original = new Uint8Array([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]);

Deno.test("AES-128-ECB ", () => {
  // deno-fmt-ignore
  const key = new Uint8Array([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]);
  const cipher = new AesEcb(key);

  const enc = cipher.encrypt(original);
  // deno-fmt-ignore
  const expectedEnc = new Uint8Array([52,195,59,127,20,253,83,220,234,37,224,26,2,225,103,39,52,195,59,127,20,253,83,220,234,37,224,26,2,225,103,39]);

  assertEquals(enc, expectedEnc);

  const dec = cipher.decrypt(enc);
  assertEquals(dec, original);
});

Deno.test("AES-192-ECB", () => {
  // deno-fmt-ignore
  const key = new Uint8Array([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24]);
  const cipher = new AesEcb(key);

  const enc = cipher.encrypt(original);
  const dec = cipher.decrypt(enc);

  assertEquals(dec, original);
});

Deno.test("AES-256-ECB", () => {
  // deno-fmt-ignore
  const key = new Uint8Array([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24]);
  const cipher = new AesEcb(key);

  const enc = cipher.encrypt(original);
  const dec = cipher.decrypt(enc);

  assertEquals(dec, original);
});

Deno.test("AES-128-CBC", () => {
  // deno-fmt-ignore
  const key = new Uint8Array([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]);
  const cipher = new AesCbc(key, iv);
  const decipher = new AesCbc(key, iv);

  const enc = cipher.encrypt(original);
  const dec = decipher.decrypt(enc);

  assertEquals(dec, original);
});
