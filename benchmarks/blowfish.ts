import {
  bench,
  runBenchmarks,
} from "https://deno.land/std@0.74.0/testing/bench.ts";
import { Blowfish } from "../src/blowfish/mod.ts";

bench({
  name: "BF-ECB 2MiB",
  runs: 50,
  func(b) {
    const data = new Uint8Array(1024 * 1024 * 2);
    const bf = new Blowfish("abcdefgh");
    b.start();
    const enc = bf.encrypt(data);
    bf.decrypt(enc);
    b.stop();
  },
});

bench({
  name: "BF-CBC 2MiB",
  runs: 50,
  func(b) {
    const data = new Uint8Array(1024 * 1024 * 2);
    const bf = new Blowfish(
      "abcdefgh",
      {
        mode: Blowfish.MODE.CBC,
        iv: new Uint8Array([10, 20, 30, 40, 50, 60, 70, 80]),
      },
    );
    b.start();
    const enc = bf.encrypt(data);
    bf.decrypt(enc);
    b.stop();
  },
});

runBenchmarks();
