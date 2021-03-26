import { pbkdf2 } from "../src/pbkdf2/mod.ts";
import { assertEquals, encodeToHex } from "../dev_deps.ts";

Deno.test("PBKDF2 HMAC-SHA1", () => {
  // https://tools.ietf.org/html/rfc6070#section-2
  const te = new TextEncoder();

  const password = te.encode("password");
  const salt = te.encode("salt");

  const dk = pbkdf2("sha1", password, salt, 1, 20);

  assertEquals(encodeToHex(dk), "0c60c80f961f0e71f3a9b524af6012062fe037a6");
});
