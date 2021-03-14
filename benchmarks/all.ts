import { runBenchmarks } from "../dev_deps.ts";
import { args } from "./utils/benchmarkArgs.ts";
import "./aes.ts";
import "./blowfish.ts";

const { runs: _, ...opts } = args;

runBenchmarks(opts);
