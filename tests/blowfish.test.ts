import { assertEquals, assertThrows } from "../dev_deps.ts";
import { BlowfishCbc, BlowfishEcb } from "../blowfish.ts";

const key = new Uint8Array([97, 98, 99, 100, 101, 102, 103, 104]);

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

  const cipher = new BlowfishCbc(key, new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7]));
  const decipher = new BlowfishCbc(
    key,
    new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7]),
  );

  const original = new Uint8Array([97, 98, 99, 100, 101, 102, 103, 104]);

  const expectedEnc = new Uint8Array([58, 232, 212, 65, 248, 24, 140, 110]);
  const enc = cipher.encrypt(original);
  assertEquals(enc, expectedEnc);

  const dec = decipher.decrypt(enc);
  assertEquals(dec, original);
});
