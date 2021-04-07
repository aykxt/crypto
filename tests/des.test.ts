import { assertEquals, assertThrows, decodeHex } from "../dev_deps.ts";
import { Des } from "../des.ts";

Deno.test("[Block Cipher] DES", () => {
  const testData = [
    ["0000000000000000", "0000000000000000", "8CA64DE9C1B123A7"],
    ["FFFFFFFFFFFFFFFF", "FFFFFFFFFFFFFFFF", "7359B2163E4EDC58"],
    ["3000000000000000", "1000000000000001", "958E6E627A05557B"],
    ["1111111111111111", "1111111111111111", "F40379AB9E0EC533"],
    ["0123456789ABCDEF", "1111111111111111", "17668DFC7292532D"],
    ["1111111111111111", "0123456789ABCDEF", "8A5AE1F81AB8F2DD"],
    ["FEDCBA9876543210", "0123456789ABCDEF", "ED39D950FA74BCC4"],
  ];

  for (const [key, plaintext, ciphertext] of testData) {
    const des = new Des(decodeHex(key));
    const data = decodeHex(plaintext);
    const dataView = new DataView(data.buffer);

    des.encryptBlock(dataView, 0);
    assertEquals(data, decodeHex(ciphertext));

    des.decryptBlock(dataView, 0);
    assertEquals(data, decodeHex(plaintext));
  }

  assertThrows(
    () => {
      new Des(new Uint8Array(16));
    },
    Error,
    "Invalid key size (must be 8 bytes)",
  );
});
