import { hmac } from "../hmac.ts";
import { assertEquals, encodeToHex } from "../dev_deps.ts";

const encoder = new TextEncoder();
const key = encoder.encode("secret");
const data = encoder.encode("hello world!");

Deno.test("HMAC-SHA1", () => {
  assertEquals(
    encodeToHex(hmac("sha1", key, data)),
    "a4df5f9d237ab0ca3241f042bcf6059a4ef491c4",
  );
});

Deno.test("HMAC-SHA256", () => {
  assertEquals(
    encodeToHex(hmac("sha256", key, data)),
    "72069731bf291b463aecb218bc227abce3d403d76da67faef2d48d3cb43b2f54",
  );
});

Deno.test("HMAC-SHA512", () => {
  assertEquals(
    encodeToHex(hmac("sha512", key, data)),
    "563069fb7c8512ffe6ced927289ac5e6f30a360c1099c61b62e3a91636a2563c95524ab5a0f4fe41f86e990a9f732dbf60d4f6c85761dafbd4953c24c758f936",
  );
});
