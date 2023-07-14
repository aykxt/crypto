import { Aes } from "../aes.ts";
import { Cbc, Cfb, Ctr, Ecb, Ofb } from "../block-modes.ts";
import {
  assertEquals,
  assertThrows,
  decodeHex
} from "../dev_deps.ts";

const key = new Uint8Array(16);
const iv = new Uint8Array(16);
const original = new Uint8Array(64);

// TODO: Test with test vectors

Deno.test("[Block Cipher Mode] Base", () => {
  assertThrows(
    () => {
      const cipher = new Ecb(Aes, key);
      cipher.decrypt(new Uint8Array(4));
    },
    Error,
    "Invalid data size (must be multiple of 16 bytes)"
  );

  assertThrows(
    () => {
      const cipher = new Cbc(Aes, key, new Uint8Array(4));
      cipher.encrypt(new Uint8Array(4));
    },
    Error,
    "Invalid initialization vector size (must be 16 bytes)"
  );
});

Deno.test("[Block Cipher Mode] ECB", () => {
  interface TestVector {
    key: string;
    plain: string;
    cipher: string;
  }

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
