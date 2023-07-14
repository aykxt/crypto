import { AES as GodCryptoAES } from "https://deno.land/x/god_crypto@v1.4.11/aes.ts";
import { Aes } from "../aes.ts";
import { Cbc, Cfb, Ctr, Ecb, Ofb } from "../block-modes.ts";

const key = new Uint8Array(16);
const iv = new Uint8Array(Aes.BLOCK_SIZE);
const data = new Uint8Array(1024 * 1024 * 2);

Deno.bench({
  name: "AES-128-ECB 2MiB Encrypt",
  fn() {
    const cipher = new Ecb(Aes, key);
    cipher.encrypt(data);
  },
});

Deno.bench({
  name: "AES-128-ECB 2MiB Decrypt",
  fn() {
    const cipher = new Ecb(Aes, key);
    cipher.decrypt(data);
  },
});

Deno.bench({
  name: "AES-128-CBC 2MiB Encrypt",
  fn() {
    const cipher = new Cbc(Aes, key, iv);
    cipher.encrypt(data);
  },
});

Deno.bench({
  name: "AES-128-CBC 2MiB Decrypt",
  fn() {
    const cipher = new Cbc(Aes, key, iv);
    cipher.decrypt(data);
  },
});

Deno.bench({
  name: "AES-128-CFB 2MiB Encrypt",
  fn() {
    const cipher = new Cfb(Aes, key, iv);
    cipher.encrypt(data);
  },
});

Deno.bench({
  name: "AES-128-CFB 2MiB Decrypt",
  fn() {
    const cipher = new Cfb(Aes, key, iv);
    cipher.decrypt(data);
  },
});

Deno.bench({
  name: "AES-128-OFB 2MiB Encrypt/Decrypt",
  fn() {
    const cipher = new Ofb(Aes, key, iv);
    cipher.encrypt(data);
  },
});

Deno.bench({
  name: "AES-128-CTR 2MiB Encrypt/Decrypt",
  fn() {
    const cipher = new Ctr(Aes, key, iv);
    cipher.encrypt(data);
  },
});

Deno.bench({
  name: "AES-128-ECB (GodCrypto) 2MiB Encrypt",
  async fn() {
    const cipher = new GodCryptoAES(key, { mode: "ecb" });
    await cipher.encrypt(data);
  },
});

Deno.bench({
  name: "AES-128-ECB (GodCrypto) 2MiB Decrypt",
  async fn() {
    const cipher = new GodCryptoAES(key, { mode: "ecb" });
    await cipher.decrypt(data);
  },
});

Deno.bench({
  name: "AES-128-CBC (GodCrypto) 2MiB Encrypt",
  async fn() {
    const cipher = new GodCryptoAES(key, {
      mode: "cbc",
      iv,
    });
    await cipher.encrypt(data);
  },
});

Deno.bench({
  name: "AES-128-CBC (GodCrypto) 2MiB Decrypt",
  async fn() {
    const cipher = new GodCryptoAES(key, {
      mode: "cbc",
      iv,
    });
    await cipher.decrypt(data);
  },
});

Deno.bench({
  name: "AES-128-CFB (GodCrypto) 2MiB Encrypt",
  async fn() {
    const cipher = new GodCryptoAES(key, {
      mode: "cfb",
      iv,
    });
    await cipher.encrypt(data);
  },
});

Deno.bench({
  name: "AES-128-CFB (GodCrypto) 2MiB Decrypt",
  async fn() {
    const cipher = new GodCryptoAES(key, {
      mode: "cfb",
      iv,
    });
    await cipher.decrypt(data);
  },
});
