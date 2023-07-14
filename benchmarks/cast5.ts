import { Cbc, Cfb, Ctr, Ecb, Ofb } from "../block-modes.ts";
import { Cast5 } from "../cast5.ts";

const key = new Uint8Array(16);
const iv = new Uint8Array(Cast5.BLOCK_SIZE);
const data = new Uint8Array(1024 * 1024 * 2);

Deno.bench({
  name: "CAST5-ECB 2MiB Encrypt",
  fn() {
    const cipher = new Ecb(Cast5, key);
    cipher.encrypt(data);
  },
});

Deno.bench({
  name: "CAST5-ECB 2MiB Decrypt",
  fn() {
    const cipher = new Ecb(Cast5, key);
    cipher.decrypt(data);
  },
});

Deno.bench({
  name: "CAST5-CBC 2MiB Encrypt",
  fn() {
    const cipher = new Cbc(Cast5, key, iv);
    cipher.encrypt(data);
  },
});

Deno.bench({
  name: "CAST5-CBC 2MiB Decrypt",
  fn() {
    const cipher = new Cbc(Cast5, key, iv);
    cipher.decrypt(data);
  },
});

Deno.bench({
  name: "CAST5-CFB 2MiB Encrypt",
  fn() {
    const cipher = new Cfb(Cast5, key, iv);
    cipher.encrypt(data);
  },
});

Deno.bench({
  name: "CAST5-CFB 2MiB Decrypt",
  fn() {
    const cipher = new Cfb(Cast5, key, iv);
    cipher.decrypt(data);
  },
});

Deno.bench({
  name: "CAST5-OFB 2MiB Encrypt/Decrypt",
  fn() {
    const cipher = new Ofb(Cast5, key, iv);
    cipher.decrypt(data);
  },
});

Deno.bench({
  name: "CAST5-CTR 2MiB Encrypt/Decrypt",
  fn() {
    const cipher = new Ctr(Cast5, key, iv);
    cipher.encrypt(data);
  },
});
