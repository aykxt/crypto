import { runBenchmarks } from "../dev_deps.ts";
import { parseBenchmarkArgs } from "./utils/parseBenchmarkArgs.ts";
import "./aes.ts";
import "./blowfish.ts";

const { runs: _, ...opts } = parseBenchmarkArgs();

runBenchmarks(opts);
