import { bench, runBenchmarks } from "../dev_deps.ts";
import { TripleDes } from "../tdes.ts";
import { Cbc, Cfb, Ctr, Ecb, Ofb } from "../block-modes.ts";
import { args } from "./utils/benchmarkArgs.ts";

const { runs: _runs, ...opts } = args;
const runs = _runs || 25;

const key = new Uint8Array(24);
const iv = new Uint8Array(TripleDes.BLOCK_SIZE);
const data = new Uint8Array(1024 * 1024 * 2);

bench({
  name: "3DES-ECB 2MiB Encrypt",
  runs,
  func(b) {
    const cipher = new Ecb(TripleDes, key);
    b.start();
    cipher.encrypt(data);
    b.stop();
  },
});

bench({
  name: "3DES-ECB 2MiB Decrypt",
  runs,
  func(b) {
    const cipher = new Ecb(TripleDes, key);
    b.start();
    cipher.decrypt(data);
    b.stop();
  },
});

bench({
  name: "3DES-CBC 2MiB Encrypt",
  runs,
  func(b) {
    const cipher = new Cbc(TripleDes, key, iv);
    b.start();
    cipher.encrypt(data);
    b.stop();
  },
});

bench({
  name: "3DES-CBC 2MiB Decrypt",
  runs,
  func(b) {
    const cipher = new Cbc(TripleDes, key, iv);
    b.start();
    cipher.decrypt(data);
    b.stop();
  },
});

bench({
  name: "3DES-CFB 2MiB Encrypt",
  runs,
  func(b) {
    const cipher = new Cfb(TripleDes, key, iv);
    b.start();
    cipher.encrypt(data);
    b.stop();
  },
});

bench({
  name: "3DES-CFB 2MiB Decrypt",
  runs,
  func(b) {
    const cipher = new Cfb(TripleDes, key, iv);
    b.start();
    cipher.decrypt(data);
    b.stop();
  },
});

bench({
  name: "3DES-OFB 2MiB Encrypt/Decrypt",
  runs,
  func(b) {
    const cipher = new Ofb(TripleDes, key, iv);
    b.start();
    cipher.encrypt(data);
    b.stop();
  },
});

bench({
  name: "3DES-CTR 2MiB Encrypt/Decrypt",
  runs,
  func(b) {
    const cipher = new Ctr(TripleDes, key, iv);
    b.start();
    cipher.encrypt(data);
    b.stop();
  },
});

if (import.meta.main) {
  runBenchmarks(opts);
}
