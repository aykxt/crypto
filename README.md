# Crypto

![ci](https://github.com/aykxt/crypto/workflows/ci/badge.svg)

A collection of useful crypto algorithms written in Typescript.

> ⚠ This project is still in an early stage of development. Expect **breaking
> changes**.

## Supported algorithms

### Block ciphers

- AES (Advanced Encryption Standard)
- Blowfish
- ECB, CBC, CFB and OFB block modes

## Examples

```ts
import { AesEcb } from "https://deno.land/x/crypto/aes.ts";
import { assertEquals } from "https://deno.land/std/testing/asserts.ts";

//deno-fmt-ignore
const key = new Uint8Array([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]);

const cipher = new AesEcb(key);

//deno-fmt-ignore
const data = new Uint8Array([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]);

const encrypted = cipher.encrypt(data);

assertEquals(cipher.decrypt(encrypted), data);
```
