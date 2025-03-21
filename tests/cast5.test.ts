import { assertEquals, assertThrows } from "@std/assert";
import { decodeHex } from "@std/encoding/hex";
import { Cast5 } from "../cast5.ts";

// https://tools.ietf.org/html/rfc2144#appendix-B.1

Deno.test("[Block Cipher] CAST5-128", () => {
  const key = decodeHex("0123456712345678234567893456789A");
  const plaintext = decodeHex("0123456789ABCDEF");
  const ciphertext = decodeHex("238B4FE5847E44B2");

  const encrypted = plaintext.slice();
  const encryptedView = new DataView(encrypted.buffer);

  const cipher = new Cast5(key);
  cipher.encryptBlock(encryptedView, 0);
  assertEquals(encrypted, ciphertext);

  cipher.decryptBlock(encryptedView, 0);
  assertEquals(encrypted, plaintext);

  assertThrows(
    () => {
      new Cast5(new Uint8Array(4));
    },
    Error,
    "Invalid key size (must be between 5 and 16 bytes)",
  );

  assertThrows(
    () => {
      new Cast5(new Uint8Array(17));
    },
    Error,
    "Invalid key size (must be between 5 and 16 bytes)",
  );
});

Deno.test("[Block Cipher] CAST5-80", () => {
  const key = decodeHex("01234567123456782345");
  const plaintext = decodeHex("0123456789ABCDEF");
  const ciphertext = decodeHex("EB6A711A2C02271B");

  const encrypted = plaintext.slice();
  const encryptedView = new DataView(encrypted.buffer);

  const cipher = new Cast5(key);
  cipher.encryptBlock(encryptedView, 0);
  assertEquals(encrypted, ciphertext);

  cipher.decryptBlock(encryptedView, 0);
  assertEquals(encrypted, plaintext);
});

Deno.test("[Block Cipher] CAST5-40", () => {
  const key = decodeHex("0123456712");
  const plaintext = decodeHex("0123456789ABCDEF");
  const ciphertext = decodeHex("7AC816D16E9B302E");

  const encrypted = plaintext.slice();
  const encryptedView = new DataView(encrypted.buffer);

  const cipher = new Cast5(key);
  cipher.encryptBlock(encryptedView, 0);
  assertEquals(encrypted, ciphertext);

  cipher.decryptBlock(encryptedView, 0);
  assertEquals(encrypted, plaintext);
});
