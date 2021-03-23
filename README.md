# Crypto

![ci](https://github.com/aykxt/crypto/workflows/ci/badge.svg)

A collection of useful crypto algorithms written in Typescript.

> ⚠ This project is still in an early stage of development. Expect **breaking
> changes**.

## Supported algorithms

### Block ciphers

- AES (Advanced Encryption Standard)
- Blowfish
- ECB, CBC, CFB, OFB and CTR block modes

## Examples

```ts
import { Aes } from "https://deno.land/x/crypto/aes.ts";
import { Ecb } from "https://deno.land/x/crypto/block-modes.ts";
import { assertEquals } from "https://deno.land/std/testing/asserts.ts";

//deno-fmt-ignore
const key = new Uint8Array([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]);

const cipher = new Ecb(Aes, key);

//deno-fmt-ignore
const data = new Uint8Array([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]);

const encrypted = cipher.encrypt(data);

assertEquals(cipher.decrypt(encrypted), data);
```
