import {
  bench,
  runBenchmarks,
} from "https://deno.land/std@0.74.0/testing/bench.ts";
import { AES } from "../src/aes/mod.ts";

bench({
  name: "AES-ECB 2MiB",
  runs: 50,
  func(b) {
    const data = new Uint8Array(1024 * 1024 * 2);
    const bf = new AES("abcdefghijklmnop");
    b.start();
    const enc = bf.encrypt(data);
    bf.decrypt(enc);
    b.stop();
  },
});

bench({
  name: "AES-CBC 2MiB",
  runs: 50,
  func(b) {
    const data = new Uint8Array(1024 * 1024 * 2);
    const bf = new AES(
      "abcdefghijklmnop",
      {
        mode: AES.MODE.CBC,
        // deno-fmt-ignore
        iv: new Uint8Array([10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140, 150, 160]),
        padding: AES.PADDING.NONE,
      },
    );
    b.start();
    const enc = bf.encrypt(data);
    bf.decrypt(enc);
    b.stop();
  },
});

runBenchmarks();
