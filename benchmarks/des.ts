import { Cbc, Cfb, Ctr, Ecb, Ofb } from "../block-modes.ts";
import { Des } from "../des.ts";

const key = new Uint8Array(8);
const iv = new Uint8Array(Des.BLOCK_SIZE);
const data = new Uint8Array(1024 * 1024 * 2);

Deno.bench({
  name: "DES-ECB 2MiB Encrypt",
  fn() {
    const cipher = new Ecb(Des, key);
    cipher.encrypt(data);
  },
});

Deno.bench({
  name: "DES-ECB 2MiB Decrypt",
  fn() {
    const cipher = new Ecb(Des, key);
    cipher.decrypt(data);
  },
});

Deno.bench({
  name: "DES-CBC 2MiB Encrypt",
  fn() {
    const cipher = new Cbc(Des, key, iv);
    cipher.encrypt(data);
  },
});

Deno.bench({
  name: "DES-CBC 2MiB Decrypt",
  fn() {
    const cipher = new Cbc(Des, key, iv);
    cipher.decrypt(data);
  },
});

Deno.bench({
  name: "DES-CFB 2MiB Encrypt",
  fn() {
    const cipher = new Cfb(Des, key, iv);
    cipher.encrypt(data);
  },
});

Deno.bench({
  name: "DES-CFB 2MiB Decrypt",
  fn() {
    const cipher = new Cfb(Des, key, iv);
    cipher.decrypt(data);
  },
});

Deno.bench({
  name: "DES-OFB 2MiB Encrypt/Decrypt",
  fn() {
    const cipher = new Ofb(Des, key, iv);
    cipher.encrypt(data);
  },
});

Deno.bench({
  name: "DES-CTR 2MiB Encrypt/Decrypt",
  fn() {
    const cipher = new Ctr(Des, key, iv);
    cipher.encrypt(data);
  },
});
