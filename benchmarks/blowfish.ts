import { bench, runBenchmarks } from "../dev_deps.ts";
import { BlowfishCbc, BlowfishEcb } from "../src/blowfish/mod.ts";
import { parseBenchmarkArgs } from "./utils/parseBenchmarkArgs.ts";

const { runs: _runs, ...opts } = parseBenchmarkArgs();
const runs = _runs || 25;

const key = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
const iv = new Uint8Array(8);
const data = new Uint8Array(1024 * 1024 * 2);

bench({
  name: "Blowfish-ECB 2MiB Encrypt",
  runs,
  func(b) {
    const cipher = new BlowfishEcb(key);
    b.start();
    cipher.encrypt(data);
    b.stop();
  },
});

bench({
  name: "Blowfish-ECB 2MiB Decrypt",
  runs,
  func(b) {
    const cipher = new BlowfishEcb(key);
    b.start();
    cipher.decrypt(data);
    b.stop();
  },
});

bench({
  name: "Blowfish-CBC 2MiB Encrypt",
  runs,
  func(b) {
    const cipher = new BlowfishCbc(key, iv);

    b.start();
    cipher.encrypt(data);
    b.stop();
  },
});

bench({
  name: "Blowfish-CBC 2MiB Decrypt",
  runs,
  func(b) {
    const bf = new BlowfishCbc(key, iv);
    b.start();
    bf.decrypt(data);
    b.stop();
  },
});

if (import.meta.main) {
  runBenchmarks(opts);
}
