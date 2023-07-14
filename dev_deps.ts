export { parse as parseArgs } from "https://deno.land/std@0.194.0/flags/mod.ts";
export {
  assertEquals,
  assertThrows
} from "https://deno.land/std@0.194.0/testing/asserts.ts";
export {
  bench,
  runBenchmarks
} from "https://deno.land/std@0.92.0/testing/bench.ts";
// export {
//   decodeString as decodeHex,
//   encodeToString as encodeHex,
// } from "https://deno.land/x/std@0.92.0/encoding/hex.ts";
import { decode, encode } from "https://deno.land/std@0.194.0/encoding/hex.ts";

export function decodeHex(hex: string): Uint8Array {
  return decode(new TextEncoder().encode(hex));
}

export function encodeHex(bytes: Uint8Array): string {
  return new TextDecoder().decode(encode(bytes));
}
