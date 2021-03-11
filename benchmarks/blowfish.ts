import { bench, runBenchmarks } from "../dev_deps.ts";
import { BlowfishCbc, BlowfishEcb } from "../src/blowfish/mod.ts";

const key = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
const data = new Uint8Array(1024 * 1024 * 2);

bench({
  name: "Blowfish-ECB 2MiB Encrypt",
  runs: 50,
  func(b) {
    const bf = new BlowfishEcb(key);
    b.start();
    bf.encrypt(data);
    b.stop();
  },
});

bench({
  name: "Blowfish-ECB 2MiB Decrypt",
  runs: 50,
  func(b) {
    const bf = new BlowfishEcb(key);
    b.start();
    bf.decrypt(data);
    b.stop();
  },
});

bench({
  name: "Blowfish-CBC 2MiB Encrypt",
  runs: 50,
  func(b) {
    const bf = new BlowfishCbc(
      key,
      new Uint8Array(8),
    );

    b.start();
    bf.encrypt(data);
    b.stop();
  },
});

bench({
  name: "Blowfish-CBC 2MiB Decrypt",
  runs: 50,
  func(b) {
    const bf = new BlowfishCbc(
      key,
      new Uint8Array(8),
    );
    b.start();
    bf.decrypt(data);
    b.stop();
  },
});

runBenchmarks();
