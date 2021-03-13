import { bench, runBenchmarks } from "../dev_deps.ts";
import { AesCbc, AesCfb, AesEcb, AesOfb } from "../src/aes/mod.ts";
import { AES as GodCryptoAES } from "https://deno.land/x/god_crypto@v1.4.9/aes.ts";
import { parseBenchmarkArgs } from "./utils/parseBenchmarkArgs.ts";

const { runs: _runs, ...opts } = parseBenchmarkArgs();
const runs = _runs || 25;

// deno-fmt-ignore
const key = new Uint8Array([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16])
const iv = new Uint8Array(16);
const data = new Uint8Array(1024 * 1024 * 2);

bench({
  name: "AES-128-ECB 2MiB Encrypt",
  runs,
  func(b) {
    const cipher = new AesEcb(key);
    b.start();
    cipher.encrypt(data);
    b.stop();
  },
});

bench({
  name: "AES-128-ECB 2MiB Decrypt",
  runs,
  func(b) {
    const cipher = new AesEcb(key);
    b.start();
    cipher.decrypt(data);
    b.stop();
  },
});

bench({
  name: "AES-128-CBC 2MiB Encrypt",
  runs,
  func(b) {
    const cipher = new AesCbc(key, iv);
    b.start();
    cipher.encrypt(data);
    b.stop();
  },
});

bench({
  name: "AES-128-CBC 2MiB Decrypt",
  runs,
  func(b) {
    const cipher = new AesCbc(key, iv);
    b.start();
    cipher.decrypt(data);
    b.stop();
  },
});

bench({
  name: "AES-128-CFB 2MiB Encrypt",
  runs,
  func(b) {
    const cipher = new AesCfb(key, iv);
    b.start();
    cipher.encrypt(data);
    b.stop();
  },
});

bench({
  name: "AES-128-CFB 2MiB Decrypt",
  runs,
  func(b) {
    const cipher = new AesCfb(key, iv);
    b.start();
    cipher.decrypt(data);
    b.stop();
  },
});

bench({
  name: "AES-128-CFB 2MiB Encrypt",
  runs,
  func(b) {
    const cipher = new AesOfb(key, iv);
    b.start();
    cipher.encrypt(data);
    b.stop();
  },
});

bench({
  name: "AES-128-CFB 2MiB Decrypt",
  runs,
  func(b) {
    const cipher = new AesOfb(key, iv);
    b.start();
    cipher.decrypt(data);
    b.stop();
  },
});

bench({
  name: "AES-128-ECB (GodCrypto) 2MiB Encrypt",
  runs,
  async func(b) {
    const cipher = new GodCryptoAES(key, { mode: "ecb" });
    b.start();
    await cipher.encrypt(data);
    b.stop();
  },
});

bench({
  name: "AES-128-ECB (GodCrypto) 2MiB Decrypt",
  runs,
  async func(b) {
    const cipher = new GodCryptoAES(key, { mode: "ecb" });
    b.start();
    await cipher.decrypt(data);
    b.stop();
  },
});

bench({
  name: "AES-128-CBC (GodCrypto) 2MiB Encrypt",
  runs,
  async func(b) {
    const cipher = new GodCryptoAES(key, {
      mode: "cbc",
      iv,
    });
    b.start();
    await cipher.encrypt(data);
    b.stop();
  },
});

bench({
  name: "AES-128-CBC (GodCrypto) 2MiB Decrypt",
  runs,
  async func(b) {
    const cipher = new GodCryptoAES(key, {
      mode: "cbc",
      iv,
    });
    b.start();
    await cipher.decrypt(data);
    b.stop();
  },
});

bench({
  name: "AES-128-CFB (GodCrypto) 2MiB Encrypt",
  runs,
  async func(b) {
    const cipher = new GodCryptoAES(key, {
      mode: "cfb",
      iv,
    });
    b.start();
    await cipher.encrypt(data);
    b.stop();
  },
});

bench({
  name: "AES-128-CFB (GodCrypto) 2MiB Decrypt",
  runs,
  async func(b) {
    const cipher = new GodCryptoAES(key, {
      mode: "cfb",
      iv,
    });
    b.start();
    await cipher.decrypt(data);
    b.stop();
  },
});

if (import.meta.main) {
  runBenchmarks(opts);
}
