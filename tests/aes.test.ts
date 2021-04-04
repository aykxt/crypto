import { assertEquals, assertThrows, decodeHex } from "../dev_deps.ts";
import { Aes } from "../aes.ts";

// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/AESAVS.pdf

Deno.test("[Block Cipher] AES-128 ", () => {
  const testVectors: readonly [string, string][] = [
    ["f34481ec3cc627bacd5dc3fb08f273e6", "0336763e966d92595a567cc9ce537f5e"],
    ["9798c4640bad75c7c3227db910174e72", "a9a1631bf4996954ebc093957b234589"],
    ["96ab5c2ff612d9dfaae8c31f30c42168", "ff4f8391a6a40ca5b25d23bedd44a597"],
    ["6a118a874519e64e9963798a503f1d35", "dc43be40be0e53712f7e2bf5ca707209"],
    ["cb9fceec81286ca3e989bd979b0cb284", "92beedab1895a94faa69b632e5cc47ce"],
    ["b26aeb1874e47ca8358ff22378f09144", "459264f4798f6a78bacb89c15ed3d601"],
    ["58c8e00b2631686d54eab84b91f0aca1", "08a4e2efec8a8e3312ca7460b9040bbf"],
  ];
  const aes = new Aes(new Uint8Array(16));

  for (const [plaintext, chiphertext] of testVectors) {
    const data = decodeHex(plaintext);
    const dataView = new DataView(data.buffer);
    aes.encryptBlock(dataView, 0);
    assertEquals(data, decodeHex(chiphertext));
    aes.decryptBlock(dataView, 0);
    assertEquals(data, decodeHex(plaintext));
  }

  assertThrows(
    () => {
      new Aes(new Uint8Array(17));
    },
    Error,
    "Invalid key size (must be either 16, 24 or 32 bytes)",
  );
});

Deno.test("[Block Cipher] AES-192 ", () => {
  const testVectors: readonly [string, string][] = [
    ["1b077a6af4b7f98229de786d7516b639", "275cfc0413d8ccb70513c3859b1d0f72"],
    ["9c2d8842e5f48f57648205d39a239af1", "c9b8135ff1b5adc413dfd053b21bd96d"],
    ["bff52510095f518ecca60af4205444bb", "4a3650c3371ce2eb35e389a171427440"],
    ["51719783d3185a535bd75adc65071ce1", "4f354592ff7c8847d2d0870ca9481b7c"],
    ["26aa49dcfe7629a8901a69a9914e6dfd", "d5e08bf9a182e857cf40b3a36ee248cc"],
    ["941a4773058224e1ef66d10e0a6ee782", "067cd9d3749207791841562507fa9626"],
  ];
  const aes = new Aes(new Uint8Array(24));

  for (const [plaintext, chiphertext] of testVectors) {
    const data = decodeHex(plaintext);
    const dataView = new DataView(data.buffer);
    aes.encryptBlock(dataView, 0);
    assertEquals(data, decodeHex(chiphertext));
    aes.decryptBlock(dataView, 0);
    assertEquals(data, decodeHex(plaintext));
  }
});

Deno.test("[Block Cipher] AES-256", () => {
  const testVectors: readonly [string, string][] = [
    ["014730f80ac625fe84f026c60bfd547d", "5c9d844ed46f9885085e5d6a4f94c7d7"],
    ["0b24af36193ce4665f2825d7b4749c98", "a9ff75bd7cf6613d3731c77c3b6d0c04"],
    ["761c1fe41a18acf20d241650611d90f1", "623a52fcea5d443e48d9181ab32c7421"],
    ["8a560769d605868ad80d819bdba03771", "38f2c7ae10612415d27ca190d27da8b4"],
    ["91fbef2d15a97816060bee1feaa49afe", "1bc704f1bce135ceb810341b216d7abe"],
  ];

  const aes = new Aes(new Uint8Array(32));

  for (const [plaintext, chiphertext] of testVectors) {
    const data = decodeHex(plaintext);
    const dataView = new DataView(data.buffer);
    aes.encryptBlock(dataView, 0);
    assertEquals(data, decodeHex(chiphertext));
    aes.decryptBlock(dataView, 0);
    assertEquals(data, decodeHex(plaintext));
  }
});
