import { parseArgs } from "../../dev_deps.ts";

const flags = parseArgs(Deno.args, {
  string: ["only", "skip"],
  boolean: "silent",
});

export const args = {
  runs: typeof flags.runs === "number" ? flags.runs : undefined,
  only: flags.only ? new RegExp(flags.only) : undefined,
  skip: flags.skip ? new RegExp(flags.skip) : undefined,
  silent: flags.silent as boolean,
};
