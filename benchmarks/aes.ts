import { Aes } from "../aes.ts";
import { Cbc, Cfb, Ctr, Ecb, Ofb } from "../block-modes.ts";
import { Ige } from "../src/block-modes/ige.ts";

const key = new Uint8Array(16);
const iv = new Uint8Array(Aes.BLOCK_SIZE);
const iv2 = new Uint8Array(Aes.BLOCK_SIZE * 2);
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
  name: "AES-128-CBC 2MiB Encrypt (WebCrypto)",
  async fn() {
    const ckey = await crypto.subtle.importKey(
      "raw",
      key,
      {
        name: "AES-CBC",
      },
      true,
      ["encrypt"],
    );
    await crypto.subtle.encrypt(
      {
        name: "AES-CBC",
        iv,
      },
      ckey,
      data,
    );
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
  name: "AES-128-IGE 2MiB Encrypt",
  fn() {
    const cipher = new Ige(Aes, key, iv2);
    cipher.encrypt(data);
  },
});

Deno.bench({
  name: "AES-128-IGE 2MiB Decrypt",
  fn() {
    const cipher = new Ige(Aes, key, iv2);
    cipher.decrypt(data);
  },
});
