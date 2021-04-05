import { runBenchmarks } from "../dev_deps.ts";
import { args } from "./utils/benchmarkArgs.ts";
import "./aes.ts";
import "./blowfish.ts";
import "./cast5.ts";
import "./des.ts";

const { runs: _, ...opts } = args;

runBenchmarks(opts);
