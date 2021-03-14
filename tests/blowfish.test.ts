import { assertEquals, assertThrows } from "../dev_deps.ts";
import {
  BlowfishCbc,
  BlowfishCfb,
  BlowfishEcb,
  BlowfishOfb,
} from "../blowfish.ts";

const key = new Uint8Array([97, 98, 99, 100, 101, 102, 103, 104]);
const iv = new Uint8Array(8);

Deno.test("Blowfish-ECB", () => {
  const bf = new BlowfishEcb(key);

  const original = new Uint8Array([97, 98, 99, 100, 101, 102, 103, 104]);

  const expectedEnc = new Uint8Array([49, 76, 81, 95, 230, 247, 169, 237]);
  const enc = bf.encrypt(original);
  assertEquals(enc, expectedEnc);

  const dec = bf.decrypt(enc);
  assertEquals(dec, original);
});

Deno.test("Blowfish-CBC", () => {
  assertThrows(
    () =>
      new BlowfishCbc(
        key,
        new Uint8Array([10, 20]),
      ),
    Error,
    "Invalid initialization vector size (must be 8 bytes)",
  );

  const cipher = new BlowfishCbc(key, iv);
  const decipher = new BlowfishCbc(key, iv);

  const original = new Uint8Array(16);

  const enc = cipher.encrypt(original);
  const dec = decipher.decrypt(enc);

  assertEquals(dec, original);
});

Deno.test("Blowfish-CFB", () => {
  const cipher = new BlowfishCfb(key, iv);
  const decipher = new BlowfishCfb(key, iv);

  const original = new Uint8Array(16);

  const enc = cipher.encrypt(original);
  const dec = decipher.decrypt(enc);

  assertEquals(dec, original);
});

Deno.test("Blowfish-OFB", () => {
  const cipher = new BlowfishOfb(key, iv);
  const decipher = new BlowfishOfb(key, iv);

  const original = new Uint8Array(16);

  const enc = cipher.encrypt(original);
  const dec = decipher.decrypt(enc);

  assertEquals(dec, original);
});
