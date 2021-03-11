import { bench, runBenchmarks } from "../dev_deps.ts";
import { AesCbc, AesEcb } from "../src/aes/mod.ts";
import { AES as GodCryptoAES } from "https://deno.land/x/god_crypto@v1.4.9/aes.ts";

// deno-fmt-ignore
const key = new Uint8Array([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16])
const data = new Uint8Array(1024 * 1024 * 2);

bench({
  name: "AES-128-ECB 2MiB Encrypt",
  runs: 50,
  func(b) {
    const cipher = new AesEcb(key);
    b.start();
    cipher.encrypt(data);
    b.stop();
  },
});

bench({
  name: "AES-128-ECB 2MiB Decrypt",
  runs: 50,
  func(b) {
    const cipher = new AesEcb(key);
    b.start();
    cipher.decrypt(data);
    b.stop();
  },
});

bench({
  name: "AES-128-CBC 2MiB Encrypt",
  runs: 50,
  func(b) {
    const cipher = new AesCbc(key, new Uint8Array(16));
    b.start();
    cipher.encrypt(data);
    b.stop();
  },
});

bench({
  name: "AES-128-CBC 2MiB Decrypt",
  runs: 50,
  func(b) {
    const cipher = new AesCbc(key, new Uint8Array(16));
    b.start();
    cipher.decrypt(data);
    b.stop();
  },
});

bench({
  name: "AES-128-ECB (GodCrypto) 2MiB Encrypt",
  runs: 5, // takes too long
  async func(b) {
    const cipher = new GodCryptoAES(key, { mode: "ecb" });
    b.start();
    await cipher.encrypt(data);
    b.stop();
  },
});

bench({
  name: "AES-128-ECB (GodCrypto) 2MiB Decrypt",
  runs: 5, // takes too long
  async func(b) {
    const cipher = new GodCryptoAES(key, { mode: "ecb" });
    b.start();
    await cipher.decrypt(data);
    b.stop();
  },
});

bench({
  name: "AES-128-CBC (GodCrypto) 2MiB Encrypt",
  runs: 5, // takes too long
  async func(b) {
    const cipher = new GodCryptoAES(key, {
      mode: "cbc",
      iv: new Uint8Array(16),
    });
    b.start();
    await cipher.encrypt(data);
    b.stop();
  },
});

bench({
  name: "AES-128-CBC (GodCrypto) 2MiB Decrypt",
  runs: 5, // takes too long
  async func(b) {
    const cipher = new GodCryptoAES(key, {
      mode: "cbc",
      iv: new Uint8Array(16),
    });
    b.start();
    await cipher.decrypt(data);
    b.stop();
  },
});

runBenchmarks();
