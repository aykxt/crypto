<h1 align="center">🔐 Deno Crypto</h1>
<p align="center">
<img src="https://github.com/aykxt/crypto/workflows/ci/badge.svg" />
<img src="https://img.shields.io/endpoint?url=https%3A%2F%2Fdeno-visualizer.danopia.net%2Fshields%2Fupdates%2Fhttps%2Fdeno.land%2Fx%2Fcrypto%2Fdeps.ts" />
<a href="https://deno.land/x/crypto"><img src="https://img.shields.io/endpoint?url=https%3A%2F%2Fdeno-visualizer.danopia.net%2Fshields%2Flatest-version%2Fx%2Fcrypto" /></a>
</p>
<p align="center">A collection of useful cryptographic algorithms written in Typescript.</p>

---

> 🧪 **This project is still in an early stage of development. Expect breaking
> changes**.

---

## ✔ Supported algorithms

### [Block ciphers]

- [AES] (Rijndael)
- [Blowfish]
- [CAST5] (CAST-128)
- [DES]
- ECB, CBC, CFB, OFB and CTR [block modes]

### [Message Authentication Code] algorithms (MACs)

- [HMAC]

### [Key Derivation Functions] (KDFs)

- [HKDF]
- [PBKDF2]

## 📝 Examples

#### AES-128-CBC

```ts
import { Aes } from "https://deno.land/x/crypto/aes.ts";
import { Cbc, Padding } from "https://deno.land/x/crypto/block-modes.ts";

const te = new TextEncoder();

const key = te.encode("SuperDuperSecret");
const data = te.encode("DataToBeEncrypted");
const iv = new Uint8Array(16);

// Ciphers have an internal state, you should therefore create
// separate ciphers for encryption and decryption
const cipher = new Cbc(Aes, key, iv, Padding.PKCS7);
const decipher = new Cbc(Aes, key, iv, Padding.PKCS7);

const encrypted = cipher.encrypt(data);
const decrypted = decipher.decrypt(encrypted);
```

## 🔔 Disclaimer

This repository has not yet received any formal cryptographic and security
reviews. **USE AT YOUR OWN RISK**

[Block ciphers]: https://en.wikipedia.org/wiki/Block_cipher
[block modes]: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation
[AES]: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
[Blowfish]: https://en.wikipedia.org/wiki/Blowfish_(cipher)
[CAST5]: https://en.wikipedia.org/wiki/CAST-128
[DES]: https://en.wikipedia.org/wiki/Data_Encryption_Standard
[Message Authentication Code]: https://en.wikipedia.org/wiki/Message_authentication_code
[HMAC]: https://en.wikipedia.org/wiki/HMAC
[Key Derivation Functions]: https://en.wikipedia.org/wiki/Key_derivation_function
[HKDF]: https://en.wikipedia.org/wiki/HKDF
[PBKDF2]: https://en.wikipedia.org/wiki/PBKDF2
