import { AES } from "../../mod.ts";

import { assertEquals } from "https://deno.land/std@0.74.0/testing/asserts.ts";

Deno.test("AES-ECB", () => {
  const key = new Uint8Array(
    [10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140, 150, 160],
  );
  const aes = new AES(key);

  // deno-fmt-ignore
  const original = new Uint8Array(
    [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
  );

  const enc = aes.encrypt(original);
  const dec = aes.decrypt(enc);

  assertEquals(dec, original);
});

Deno.test("AES-CBC", () => {
  const key = new Uint8Array(
    [10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140, 150, 160],
  );
  const aes = new AES(
    key,
    {
      mode: AES.MODE.CBC,
      iv: new Uint8Array(
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
      ),
      padding: AES.PADDING.NONE,
    },
  );

  // deno-fmt-ignore
  const original = new Uint8Array(
    [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
  );

  const enc = aes.encrypt(original);
  const dec = aes.decrypt(enc);

  assertEquals(dec, original);
});
