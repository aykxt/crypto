export {
  assertEquals,
  assertThrows,
} from "https://deno.land/std@0.194.0/testing/asserts.ts";
import { decode, encode } from "https://deno.land/std@0.194.0/encoding/hex.ts";

export function decodeHex(hex: string): Uint8Array {
  return decode(new TextEncoder().encode(hex));
}

export function encodeHex(bytes: Uint8Array): string {
  return new TextDecoder().decode(encode(bytes));
}
