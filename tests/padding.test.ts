import { assertEquals, assertThrows } from "../dev_deps.ts";
import { pad, Padding, unpad } from "../src/utils/padding.ts";

Deno.test("[Padding] PKCS#7", () => {
  const mode = Padding.PKCS7;

  const original = new Uint8Array([1, 2, 3, 4, 5, 6, 7]);
  const padded = pad(original, mode, 16);
  const paddedExpected = new Uint8Array(
    [1, 2, 3, 4, 5, 6, 7, 9, 9, 9, 9, 9, 9, 9, 9, 9],
  );

  assertEquals(padded, paddedExpected);
  assertEquals(unpad(padded, mode, 16), original);
});

Deno.test("[Padding] Zero", () => {
  const mode = Padding.NULL;

  const original = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9]);
  const padded = pad(original, mode, 8);
  const paddedExpected = new Uint8Array(
    [1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0, 0, 0],
  );

  assertEquals(padded, paddedExpected);
  assertEquals(unpad(padded, mode, 8), original);
});

Deno.test("[Padding] Spaces", () => {
  const mode = Padding.SPACES;

  const original = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9]);
  const padded = pad(original, mode, 8);
  const paddedExpected = new Uint8Array(
    [1, 2, 3, 4, 5, 6, 7, 8, 9, 32, 32, 32, 32, 32, 32, 32],
  );

  assertEquals(padded, paddedExpected);
  assertEquals(unpad(padded, mode, 8), original);
});

Deno.test("[Padding] ANSI X9.23 padding", () => {
  const mode = Padding.LAST_BYTE;

  const original = new Uint8Array(
    [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
  );
  const padded = pad(original, mode, 8);
  const paddedExpected = new Uint8Array(
    [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0, 0, 0, 0, 6],
  );

  assertEquals(padded, paddedExpected);
  assertEquals(unpad(padded, mode, 8), original);
});

Deno.test("[Padding] ISO/IEC 7816-4", () => {
  const mode = Padding.ONE_AND_ZEROS;

  const original = new Uint8Array(
    [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
  );
  const padded = pad(original, mode, 8);
  const paddedExpected = new Uint8Array(
    [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 128, 0, 0, 0, 0, 0],
  );

  assertEquals(padded, paddedExpected);
  assertEquals(unpad(padded, mode, 8), original);
});

Deno.test("[Padding] No padding", () => {
  const mode = Padding.NONE;

  const original = new Uint8Array([97, 98, 99, 100, 101, 102, 103, 104]);
  const padded = pad(original, mode, 8);

  assertEquals(padded, original);
  assertEquals(unpad(padded, mode, 8), original);

  assertThrows(
    () => {
      pad(new Uint8Array(17), mode, 16);
    },
    Error,
    "Incorrect block size (must be 16 bytes long)",
  );
});
