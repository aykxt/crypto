import { assertEquals, assertThrows, decodeHex } from "../dev_deps.ts";
import { TripleDes } from "../tdes.ts";

Deno.test("[Block Cipher] 3DES", () => {
  // deno-fmt-ignore
  const testData = [
    // 64 bit key
    // https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-20.pdf (Appendix A.1)
    ["0101010101010101", "8000000000000000", "95F8A5E5DD31D900"],
    ["0101010101010101", "4000000000000000", "DD7F121CA5015619"],
    ["0101010101010101", "2000000000000000", "2E8653104F3834EA"],
    // 128 bit key
    // https://www.cosic.esat.kuleuven.be/nessie/testvectors/bc/des/Triple-Des-2-Key-128-64.unverified.test-vectors
    ["80000000000000000000000000000000", "0000000000000000", "FAFD5084374FCE34"],
    ["40000000000000000000000000000000", "0000000000000000", "60CC37B7B537A1DC"],
    ["20000000000000000000000000000000", "0000000000000000", "BE3E7304FE92C2BC"],
    // 192 bit key
    // https://www.cosic.esat.kuleuven.be/nessie/testvectors/bc/des/Triple-Des-3-Key-192-64.unverified.test-vectors
    ["800000000000000000000000000000000000000000000000", "0000000000000000", "95A8D72813DAA94D"],
    ["400000000000000000000000000000000000000000000000", "0000000000000000", "0EEC1487DD8C26D5"],
    ["200000000000000000000000000000000000000000000000", "0000000000000000", "7AD16FFB79C45926"],
  ];

  for (const [key, plaintext, ciphertext] of testData) {
    const des = new TripleDes(decodeHex(key));
    const data = decodeHex(plaintext);
    const dataView = new DataView(data.buffer);

    des.encryptBlock(dataView, 0);
    assertEquals(data, decodeHex(ciphertext));

    des.decryptBlock(dataView, 0);
    assertEquals(data, decodeHex(plaintext));
  }

  assertThrows(
    () => {
      new TripleDes(new Uint8Array(26));
    },
    Error,
    "Invalid key size (must be either 8, 16 or 24 bytes)",
  );
});
