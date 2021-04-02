import { bench, runBenchmarks } from "../dev_deps.ts";
import { Cast5 } from "../cast5.ts";
import { Cbc, Cfb, Ctr, Ecb, Ofb } from "../block-modes.ts";
import { args } from "./utils/benchmarkArgs.ts";

const { runs: _runs, ...opts } = args;
const runs = _runs || 25;

const key = new Uint8Array(16);
const iv = new Uint8Array(Cast5.BLOCK_SIZE);
const data = new Uint8Array(1024 * 1024 * 2);

bench({
  name: "CAST5-ECB 2MiB Encrypt",
  runs,
  func(b) {
    const cipher = new Ecb(Cast5, key);
    b.start();
    cipher.encrypt(data);
    b.stop();
  },
});

bench({
  name: "CAST5-ECB 2MiB Decrypt",
  runs,
  func(b) {
    const cipher = new Ecb(Cast5, key);
    b.start();
    cipher.decrypt(data);
    b.stop();
  },
});

bench({
  name: "CAST5-CBC 2MiB Encrypt",
  runs,
  func(b) {
    const cipher = new Cbc(Cast5, key, iv);

    b.start();
    cipher.encrypt(data);
    b.stop();
  },
});

bench({
  name: "CAST5-CBC 2MiB Decrypt",
  runs,
  func(b) {
    const bf = new Cbc(Cast5, key, iv);
    b.start();
    bf.decrypt(data);
    b.stop();
  },
});

bench({
  name: "CAST5-CFB 2MiB Encrypt",
  runs,
  func(b) {
    const cipher = new Cfb(Cast5, key, iv);

    b.start();
    cipher.encrypt(data);
    b.stop();
  },
});

bench({
  name: "CAST5-CFB 2MiB Decrypt",
  runs,
  func(b) {
    const cipher = new Cfb(Cast5, key, iv);
    b.start();
    cipher.decrypt(data);
    b.stop();
  },
});

bench({
  // Encryption and decryption are the same
  name: "CAST5-OFB 2MiB Encrypt/Decrypt",
  runs,
  func(b) {
    const cipher = new Ofb(Cast5, key, iv);
    b.start();
    cipher.encrypt(data);
    b.stop();
  },
});

bench({
  name: "CAST5-CTR 2MiB Encrypt/Decrypt",
  runs,
  func(b) {
    const cipher = new Ctr(Cast5, key, iv);
    b.start();
    cipher.encrypt(data);
    b.stop();
  },
});

if (import.meta.main) {
  runBenchmarks(opts);
}
