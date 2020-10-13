import { assertEquals } from "https://deno.land/std@0.74.0/testing/asserts.ts";

import Blowfish from "../../src/blowfish/mod.ts";

Deno.test("BF-ECB", () => {
  const bf = new Blowfish("abcdefgh");

  const original = new Uint8Array([97, 98, 99, 100, 101, 102, 103, 104]);
  const expectedEnc = new Uint8Array([49, 76, 81, 95, 230, 247, 169, 237]);

  const enc = bf.encode(original);
  assertEquals(enc, expectedEnc);

  const dec = bf.decode(enc);
  assertEquals(dec, original);
});

Deno.test("BF-CBC", () => {
  const bf = new Blowfish("abcdefgh", {
    mode: Blowfish.MODE.CBC,
    iv: new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7]),
  });

  const original = new Uint8Array([97, 98, 99, 100, 101, 102, 103, 104]);
  const expectedEnc = new Uint8Array([58, 232, 212, 65, 248, 24, 140, 110]);

  const enc = bf.encode(original);
  assertEquals(enc, expectedEnc);

  const dec = bf.decode(enc);
  assertEquals(dec, original);
});
