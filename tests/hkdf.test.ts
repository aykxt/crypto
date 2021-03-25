import { hkdf } from "../hkdf.ts";
import { assertEquals, decodeHex, encodeToHex } from "../dev_deps.ts";

Deno.test("HKDF-SHA256", () => {
  // https://tools.ietf.org/html/rfc5869#appendix-A.1

  const ikm = decodeHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
  const salt = decodeHex("000102030405060708090a0b0c");
  const info = decodeHex("f0f1f2f3f4f5f6f7f8f9");
  const len = 42;

  const okm = hkdf("sha256", len, ikm, salt, info);

  const expected =
    "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865";

  assertEquals(encodeToHex(okm), expected);
});
