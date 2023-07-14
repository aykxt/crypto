import { Cbc, Cfb, Ctr, Ecb, Ofb } from "../block-modes.ts";
import { TripleDes } from "../tdes.ts";

const key = new Uint8Array(24);
const iv = new Uint8Array(TripleDes.BLOCK_SIZE);
const data = new Uint8Array(1024 * 1024 * 2);

Deno.bench({
  name: "3DES-ECB 2MiB Encrypt",
  fn() {
    const cipher = new Ecb(TripleDes, key);
    cipher.encrypt(data);
  },
});

Deno.bench({
  name: "3DES-ECB 2MiB Decrypt",
  fn() {
    const cipher = new Ecb(TripleDes, key);
    cipher.decrypt(data);
  },
});

Deno.bench({
  name: "3DES-CBC 2MiB Encrypt",
  fn() {
    const cipher = new Cbc(TripleDes, key, iv);
    cipher.encrypt(data);
  },
});

Deno.bench({
  name: "3DES-CBC 2MiB Decrypt",
  fn() {
    const cipher = new Cbc(TripleDes, key, iv);
    cipher.decrypt(data);
  },
});

Deno.bench({
  name: "3DES-CFB 2MiB Encrypt",
  fn() {
    const cipher = new Cfb(TripleDes, key, iv);
    cipher.encrypt(data);
  },
});

Deno.bench({
  name: "3DES-CFB 2MiB Decrypt",
  fn() {
    const cipher = new Cfb(TripleDes, key, iv);
    cipher.decrypt(data);
  },
});

Deno.bench({
  name: "3DES-OFB 2MiB Encrypt/Decrypt",
  fn() {
    const cipher = new Ofb(TripleDes, key, iv);
    cipher.encrypt(data);
  },
});

Deno.bench({
  name: "3DES-CTR 2MiB Encrypt/Decrypt",
  fn() {
    const cipher = new Ctr(TripleDes, key, iv);
    cipher.encrypt(data);
  },
});
