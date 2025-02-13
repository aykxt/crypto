import { assertEquals, assertThrows } from "@std/assert";
import { decodeHex } from "@std/encoding/hex";
import { Aes } from "../aes.ts";
import { Cbc, Cfb, Ctr, Ecb, Ige, Ofb } from "../block-modes.ts";

const key = new Uint8Array(16);
const iv = new Uint8Array(16);
const original = new Uint8Array(64);

interface TestVector {
  key: string;
  plain: string;
  cipher: string;
}

interface TestVectorWithIV extends TestVector {
  iv: string;
}

// TODO: Test with test vectors

Deno.test("[Block Cipher Mode] Base", () => {
  assertThrows(
    () => {
      const cipher = new Ecb(Aes, key);
      cipher.decrypt(new Uint8Array(4));
    },
    Error,
    "Invalid data size (must be multiple of 16 bytes)",
  );

  assertThrows(
    () => {
      const cipher = new Cbc(Aes, key, new Uint8Array(4));
      cipher.encrypt(new Uint8Array(4));
    },
    Error,
    "Invalid initialization vector size (must be 16 bytes)",
  );
});

Deno.test("[Block Cipher Mode] ECB", () => {
  const testVectors: TestVector[] = [
    {
      key: "000102030405060708090a0b0c0d0e0f",
      plain: "00112233445566778899aabbccddeeff",
      cipher: "69c4e0d86a7b0430d8cdb78070b4c55a",
    },
    {
      key: "2b7e151628aed2a6abf7158809cf4f3c",
      plain: "6bc1bee22e409f96e93d7e117393172a",
      cipher: "3ad77bb40d7a3660a89ecaf32466ef97",
    },
    {
      key: "2b7e151628aed2a6abf7158809cf4f3c",
      plain: "ae2d8a571e03ac9c9eb76fac45af8e51",
      cipher: "f5d3d58503b9699de785895a96fdbaaf",
    },
    {
      key: "2b7e151628aed2a6abf7158809cf4f3c",
      plain: "30c81c46a35ce411e5fbc1191a0a52ef",
      cipher: "43b1cd7f598ece23881b00e3ed030688",
    },
    {
      key: "2b7e151628aed2a6abf7158809cf4f3c",
      plain: "f69f2445df4f9b17ad2b417be66c3710",
      cipher: "7b0c785e27e8ad3f8223207104725dd4",
    },
  ];

  for (const testVector of testVectors) {
    const key = decodeHex(testVector.key);
    const plain = decodeHex(testVector.plain);
    const encrypted = decodeHex(testVector.cipher);

    const cipher = new Ecb(Aes, key);
    const enc = cipher.encrypt(plain);

    assertEquals(plain, decodeHex(testVector.plain));
    assertEquals(enc, encrypted);

    const dec = cipher.decrypt(enc);
    assertEquals(dec, plain);
  }
});

Deno.test("[Block Cipher Mode] CBC", () => {
  const cipher = new Cbc(Aes, key, iv);
  const decipher = new Cbc(Aes, key, iv);
  const enc = cipher.encrypt(original);
  const dec = decipher.decrypt(enc);
  assertEquals(dec, original);
});

Deno.test("[Block Cipher Mode] CFB ", () => {
  const original = new Uint8Array(32);
  const cipher = new Cfb(Aes, key, iv);
  const decipher = new Cfb(Aes, key, iv);
  const enc = cipher.encrypt(original);
  const dec = decipher.decrypt(enc);
  assertEquals(dec, original);
});

Deno.test("[Block Cipher Mode] OFB ", () => {
  const cipher = new Ofb(Aes, key, iv);
  const decipher = new Ofb(Aes, key, iv);
  const enc = cipher.encrypt(original);
  const dec = decipher.decrypt(enc);
  assertEquals(dec, original);
});

Deno.test("[Block Cipher Mode] CTR", () => {
  const cipher = new Ctr(Aes, key, iv);
  const decipher = new Ctr(Aes, key, iv);
  const enc = cipher.encrypt(original);
  const dec = decipher.decrypt(enc);
  assertEquals(dec, original);
});

Deno.test("[Block Cipher Mode] IGE", () => {
  // https://www.links.org/files/openssl-ige.pdf
  const testVectors: TestVectorWithIV[] = [
    {
      key: "000102030405060708090A0B0C0D0E0F",
      iv: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
      plain: "0000000000000000000000000000000000000000000000000000000000000000",
      cipher:
        "1A8519A6557BE652E9DA8E43DA4EF4453CF456B4CA488AA383C79C98B34797CB",
    },
    {
      key: "5468697320697320616E20696D706C65",
      iv: "6D656E746174696F6E206F6620494745206D6F646520666F72204F70656E5353",
      plain: "99706487A1CDE613BC6DE0B6F24B1C7AA448C8B9C3403E3467A8CAD89340F53B",
      cipher:
        "4C2E204C6574277320686F70652042656E20676F74206974207269676874210A",
    },
  ];

  for (const testVector of testVectors) {
    const key = decodeHex(testVector.key);
    const iv = decodeHex(testVector.iv);
    const plaintext = decodeHex(testVector.plain);
    const ciphertext = decodeHex(testVector.cipher);

    const cipher = new Ige(Aes, key, iv);
    const enc = cipher.encrypt(plaintext);
    assertEquals(enc, ciphertext);

    const decipher = new Ige(Aes, key, iv);
    const dec = decipher.decrypt(ciphertext);
    assertEquals(dec, plaintext);
  }
});
