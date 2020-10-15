import { assertEquals } from "https://deno.land/std@0.74.0/testing/asserts.ts";
import { pad, Padding, unpad } from "../../src/utils/padding.ts";

Deno.test("PKCS#7 padding", () => {
  const original = new Uint8Array([97, 98, 99, 100, 101, 102, 103]);
  const padded = pad(original, Padding.PKCS7, 16);
  const paddedExpected = new Uint8Array(
    [97, 98, 99, 100, 101, 102, 103, 9, 9, 9, 9, 9, 9, 9, 9, 9],
  );

  assertEquals(padded, paddedExpected);
  assertEquals(unpad(padded, Padding.PKCS7, 16), original);
});

Deno.test("Zero padding", () => {
  const mode = Padding.NULL;

  const original = new Uint8Array([97, 98, 99, 100, 101, 102, 103, 104, 105]);
  const padded = pad(original, mode, 8);
  const paddedExpected = new Uint8Array(
    [97, 98, 99, 100, 101, 102, 103, 104, 105, 0, 0, 0, 0, 0, 0, 0],
  );

  assertEquals(padded, paddedExpected);
  assertEquals(unpad(padded, mode, 8), original);
});

Deno.test("Spaces padding", () => {
  const mode = Padding.SPACES;

  const original = new Uint8Array([97, 98, 99, 100, 101, 102, 103, 104, 105]);
  const padded = pad(original, mode, 8);
  const paddedExpected = new Uint8Array(
    [97, 98, 99, 100, 101, 102, 103, 104, 105, 32, 32, 32, 32, 32, 32, 32],
  );

  assertEquals(padded, paddedExpected);
  assertEquals(unpad(padded, mode, 8), original);
});

Deno.test("ANSI X9.23 padding", () => {
  const mode = Padding.LAST_BYTE;

  const original = new Uint8Array(
    [97, 98, 99, 100, 101, 102, 103, 104, 105, 106],
  );
  const padded = pad(original, mode, 8);
  const paddedExpected = new Uint8Array(
    [97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 0, 0, 0, 0, 0, 6],
  );

  assertEquals(padded, paddedExpected);
  assertEquals(unpad(padded, mode, 8), original);
});

Deno.test("ISO/IEC 7816-4 padding", () => {
  const mode = Padding.ONE_AND_ZEROS;

  const original = new Uint8Array(
    [97, 98, 99, 100, 101, 102, 103, 104, 105, 106],
  );
  const padded = pad(original, mode, 8);
  const paddedExpected = new Uint8Array(
    [97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 128, 0, 0, 0, 0, 0],
  );

  assertEquals(padded, paddedExpected);
  assertEquals(unpad(padded, mode, 8), original);
});
