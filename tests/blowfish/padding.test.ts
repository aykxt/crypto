import { assertEquals } from "https://deno.land/std@0.74.0/testing/asserts.ts";
import { pad, Padding, unpad } from "../../src/blowfish/helpers.ts";

Deno.test("PKCS#5 padding", () => {
  const original = new Uint8Array([97, 98, 99, 100, 101, 102, 103, 104]);
  const padded = pad(original, Padding.PKCS5);
  const paddedExpected = new Uint8Array(
    [97, 98, 99, 100, 101, 102, 103, 104, 8, 8, 8, 8, 8, 8, 8, 8],
  );

  assertEquals(padded, paddedExpected);
  assertEquals(unpad(padded, Padding.PKCS5), original);
});

Deno.test("Zero padding", () => {
  const mode = Padding.NULL;

  const original = new Uint8Array([97, 98, 99, 100, 101, 102, 103, 104, 105]);
  const padded = pad(original, mode);
  const paddedExpected = new Uint8Array(
    [97, 98, 99, 100, 101, 102, 103, 104, 105, 0, 0, 0, 0, 0, 0, 0],
  );

  assertEquals(padded, paddedExpected);
  assertEquals(unpad(padded, mode), original);
});

Deno.test("Spaces padding", () => {
  const mode = Padding.SPACES;

  const original = new Uint8Array([97, 98, 99, 100, 101, 102, 103, 104, 105]);
  const padded = pad(original, mode);
  const paddedExpected = new Uint8Array(
    [97, 98, 99, 100, 101, 102, 103, 104, 105, 32, 32, 32, 32, 32, 32, 32],
  );

  assertEquals(padded, paddedExpected);
  assertEquals(unpad(padded, mode), original);
});

Deno.test("ANSI X9.23 padding", () => {
  const mode = Padding.LAST_BYTE;

  const original = new Uint8Array(
    [97, 98, 99, 100, 101, 102, 103, 104, 105, 106],
  );
  const padded = pad(original, mode);
  const paddedExpected = new Uint8Array(
    [97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 0, 0, 0, 0, 0, 6],
  );

  assertEquals(padded, paddedExpected);
  assertEquals(unpad(padded, mode), original);
});

Deno.test("ISO/IEC 7816-4 padding", () => {
  const mode = Padding.ONE_AND_ZEROS;

  const original = new Uint8Array(
    [97, 98, 99, 100, 101, 102, 103, 104, 105, 106],
  );
  const padded = pad(original, mode);
  const paddedExpected = new Uint8Array(
    [97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 128, 0, 0, 0, 0, 0],
  );

  assertEquals(padded, paddedExpected);
  assertEquals(unpad(padded, mode), original);
});
