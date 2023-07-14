import { Cbc, Cfb, Ctr, Ecb, Ofb } from "../block-modes.ts";
import { Blowfish } from "../blowfish.ts";

const key = new Uint8Array(8);
const iv = new Uint8Array(Blowfish.BLOCK_SIZE);
const data = new Uint8Array(1024 * 1024 * 2);

Deno.bench({
  name: "Blowfish-ECB 2MiB Encrypt",
  fn() {
    const cipher = new Ecb(Blowfish, key);
    cipher.encrypt(data);
  },
});

Deno.bench({
  name: "Blowfish-ECB 2MiB Encrypt",
  fn() {
    const cipher = new Ecb(Blowfish, key);
    cipher.encrypt(data);
  },
});

Deno.bench({
  name: "Blowfish-ECB 2MiB Decrypt",
  fn() {
    const cipher = new Ecb(Blowfish, key);
    cipher.decrypt(data);
  },
});

Deno.bench({
  name: "Blowfish-CBC 2MiB Encrypt",
  fn() {
    const cipher = new Cbc(Blowfish, key, iv);
    cipher.encrypt(data);
  },
});

Deno.bench({
  name: "Blowfish-CBC 2MiB Decrypt",
  fn() {
    const bf = new Cbc(Blowfish, key, iv);
    bf.decrypt(data);
  },
});

Deno.bench({
  name: "Blowfish-CFB 2MiB Encrypt",
  fn() {
    const cipher = new Cfb(Blowfish, key, iv);
    cipher.encrypt(data);
  },
});

Deno.bench({
  name: "Blowfish-CFB 2MiB Decrypt",
  fn() {
    const cipher = new Cfb(Blowfish, key, iv);
    cipher.decrypt(data);
  },
});

Deno.bench({
  // Encryption and decryption are the same
  name: "Blowfish-OFB 2MiB Encrypt/Decrypt",
  fn() {
    const cipher = new Ofb(Blowfish, key, iv);
    cipher.encrypt(data);
  },
});

Deno.bench({
  name: "Blowfish-CTR 2MiB Encrypt/Decrypt",
  fn() {
    const cipher = new Ctr(Blowfish, key, iv);
    cipher.encrypt(data);
  },
});
