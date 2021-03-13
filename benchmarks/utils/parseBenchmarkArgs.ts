import { parseArgs } from "../../dev_deps.ts";

interface BenchmarkArgs {
  runs?: number;
  only?: RegExp;
  skip?: RegExp;
  silent: boolean;
}

let args: BenchmarkArgs | undefined;

export function parseBenchmarkArgs(): BenchmarkArgs {
  if (args) return args;
  const flags = parseArgs(Deno.args, {
    string: ["only", "skip"],
    boolean: "silent",
  });

  args = {
    runs: typeof flags.runs === "number" ? flags.runs : undefined,
    only: flags.only ? new RegExp(flags.only) : undefined,
    skip: flags.skip ? new RegExp(flags.skip) : undefined,
    silent: flags.silent as boolean,
  };

  return args;
}
