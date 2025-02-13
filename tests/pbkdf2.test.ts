import { assertEquals } from "@std/assert";
import { decodeHex } from "@std/encoding/hex";
import { pbkdf2 } from "../src/pbkdf2/mod.ts";

// https://tools.ietf.org/html/rfc6070#section-2
Deno.test("[KDF] PBKDF2 HMAC-SHA1", () => {
  const te = new TextEncoder();

  // deno-fmt-ignore
  const testData: [string, string, number, number, string][] = [
    ["password", "salt", 1, 20, "0c60c80f961f0e71f3a9b524af6012062fe037a6"],
    ["password", "salt", 2, 20, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"],
    ["password", "salt", 4096, 20, "4b007901b765489abead49d926f721d065a429c1"],
    // takes too long
    //["password", "salt", 16777216, 20, "eefe3d61cd4da4e4e9945b3d6ba2158c2634e984"],
    ["passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 25, "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038"],
    ["pass\0word", "sa\0lt", 4096, 16, "56fa6aa75548099dcc37d7f03425e0c3"],
  ]

  for (const [password, salt, iterations, keyLen, output] of testData) {
    const dk = pbkdf2(
      "sha1",
      te.encode(password),
      te.encode(salt),
      iterations,
      keyLen,
    );
    assertEquals(dk, decodeHex(output));
  }
});
