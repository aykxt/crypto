import { bench, runBenchmarks } from "../dev_deps.ts";
import { Des } from "../des.ts";
import { Cbc, Cfb, Ctr, Ecb, Ofb } from "../block-modes.ts";
import { args } from "./utils/benchmarkArgs.ts";

const { runs: _runs, ...opts } = args;
const runs = _runs || 25;

const key = new Uint8Array(8);
const iv = new Uint8Array(Des.BLOCK_SIZE);
const data = new Uint8Array(1024 * 1024 * 2);

bench({
  name: "DES-ECB 2MiB Encrypt",
  runs,
  func(b) {
    const cipher = new Ecb(Des, key);
    b.start();
    cipher.encrypt(data);
    b.stop();
  },
});

bench({
  name: "DES-ECB 2MiB Decrypt",
  runs,
  func(b) {
    const cipher = new Ecb(Des, key);
    b.start();
    cipher.decrypt(data);
    b.stop();
  },
});

bench({
  name: "DES-CBC 2MiB Encrypt",
  runs,
  func(b) {
    const cipher = new Cbc(Des, key, iv);
    b.start();
    cipher.encrypt(data);
    b.stop();
  },
});

bench({
  name: "DES-CBC 2MiB Decrypt",
  runs,
  func(b) {
    const cipher = new Cbc(Des, key, iv);
    b.start();
    cipher.decrypt(data);
    b.stop();
  },
});

bench({
  name: "DES-CFB 2MiB Encrypt",
  runs,
  func(b) {
    const cipher = new Cfb(Des, key, iv);
    b.start();
    cipher.encrypt(data);
    b.stop();
  },
});

bench({
  name: "DES-CFB 2MiB Decrypt",
  runs,
  func(b) {
    const cipher = new Cfb(Des, key, iv);
    b.start();
    cipher.decrypt(data);
    b.stop();
  },
});

bench({
  name: "DES-OFB 2MiB Encrypt/Decrypt",
  runs,
  func(b) {
    const cipher = new Ofb(Des, key, iv);
    b.start();
    cipher.encrypt(data);
    b.stop();
  },
});

bench({
  name: "DES-CTR 2MiB Encrypt/Decrypt",
  runs,
  func(b) {
    const cipher = new Ctr(Des, key, iv);
    b.start();
    cipher.encrypt(data);
    b.stop();
  },
});

if (import.meta.main) {
  runBenchmarks(opts);
}
