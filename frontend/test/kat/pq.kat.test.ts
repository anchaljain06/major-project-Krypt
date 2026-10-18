/**
 * Known-answer tests for the post-quantum wrappers in src/crypto/pq.ts.
 * Every vector goes through OUR wrapper (with its length checks), not through
 * noble directly, so a wrapper bug shows up here.
 */
import { describe, expect, it } from "vitest";
import { mldsaVerify, mlkem1024 } from "../../src/crypto/pq";
import { hex, loadVectors, unhex, vectorPath } from "./vectors";

const kemFor = (parameterSet: string) => {
  if (parameterSet === "ML-KEM-1024") return mlkem1024;
  throw new Error(`unexpected parameter set ${parameterSet}`);
};

// --- NIST ACVP ----------------------------------------------------------------

interface AcvpKemTest {
  tcId: number;
  ek?: string;
  dk?: string;
  m?: string;
  c?: string;
  k?: string;
  testPassed?: boolean;
}
interface AcvpKemGroup {
  tgId: number;
  parameterSet: string;
  function: "encapsulation" | "decapsulation" | "encapsulationKeyCheck" | "decapsulationKeyCheck";
  tests: AcvpKemTest[];
}

describe("NIST ACVP ML-KEM-encapDecap-FIPS203 (ML-KEM-1024)", () => {
  const { groups } = loadVectors<{ groups: AcvpKemGroup[] }>("acvp-mlkem-encapdecap.json");
  for (const g of groups) {
    const kem = kemFor(g.parameterSet);
    it(`tg ${g.tgId} ${g.parameterSet} ${g.function} (${g.tests.length} cases)`, () => {
      for (const t of g.tests) {
        const label = `tc ${t.tcId}`;
        switch (g.function) {
          case "encapsulation": {
            const { cipherText, sharedSecret } = kem.encapsulateDerand(unhex(t.ek!), unhex(t.m!));
            expect(hex(cipherText), label).toBe(t.c!.toLowerCase());
            expect(hex(sharedSecret), label).toBe(t.k!.toLowerCase());
            break;
          }
          case "decapsulation": {
            const ss = kem.decapsulate(unhex(t.c!), unhex(t.dk!));
            expect(hex(ss), label).toBe(t.k!.toLowerCase());
            break;
          }
          case "encapsulationKeyCheck":
            expect(kem.checkEncapsulationKey(unhex(t.ek!)), label).toBe(t.testPassed);
            break;
          case "decapsulationKeyCheck":
            expect(kem.checkDecapsulationKey(unhex(t.dk!)), label).toBe(t.testPassed);
            break;
        }
      }
    });
  }
});

interface AcvpSigVerTest {
  tcId: number;
  pk: string;
  message: string;
  context: string;
  signature: string;
  testPassed: boolean;
}

describe("NIST ACVP ML-DSA-sigVer-FIPS204 (ML-DSA-87, external/pure)", () => {
  const { groups } = loadVectors<{ groups: { tgId: number; tests: AcvpSigVerTest[] }[] }>("acvp-mldsa87-sigver.json");
  for (const g of groups) {
    it(`tg ${g.tgId} (${g.tests.length} cases, with context strings)`, () => {
      for (const t of g.tests) {
        const ok = mldsaVerify(unhex(t.pk), unhex(t.message), unhex(t.signature), unhex(t.context));
        expect(ok, `tc ${t.tcId}`).toBe(t.testPassed);
      }
    });
  }
});

// --- Wycheproof -----------------------------------------------------------------

interface WyKemTest {
  tcId: number;
  parameterSet: string;
  seed?: string;
  ek?: string;
  m?: string;
  c: string;
  K: string;
  result: "valid" | "invalid" | "acceptable";
  flags: string[];
}

{
  const p = "1024";
  const file = `wycheproof-mlkem-${p}.json`;
  describe.skipIf(!vectorPath(file))(`Wycheproof mlkem_${p}_test (keygen from seed + decaps)`, () => {
    it("all cases", () => {
      const { tests } = loadVectors<{ tests: WyKemTest[] }>(file);
      for (const t of tests) {
        const kem = kemFor(t.parameterSet);
        const label = `tc ${t.tcId} ${t.flags.join(",")}`;
        const run = () => {
          const { publicKey, secretKey } = kem.keygenDerand(unhex(t.seed!));
          if (t.ek) expect(hex(publicKey), label).toBe(t.ek);
          return hex(kem.decapsulate(unhex(t.c), secretKey));
        };
        if (t.result === "valid") {
          expect(run(), label).toBe(t.K);
        } else {
          // Invalid cases are malformed inputs (wrong lengths, bad seeds): they must throw.
          expect(run, label).toThrow();
        }
      }
    });
  });

  const encFile = `wycheproof-mlkem-${p}-encaps.json`;
  describe.skipIf(!vectorPath(encFile))(`Wycheproof mlkem_${p}_encaps_test`, () => {
    it("all cases", () => {
      const { tests } = loadVectors<{ tests: WyKemTest[] }>(encFile);
      for (const t of tests) {
        const kem = kemFor(t.parameterSet);
        const label = `tc ${t.tcId} ${t.flags.join(",")}`;
        const run = () => kem.encapsulateDerand(unhex(t.ek!), unhex(t.m!));
        if (t.result === "valid") {
          const { cipherText, sharedSecret } = run();
          expect(hex(cipherText), label).toBe(t.c);
          expect(hex(sharedSecret), label).toBe(t.K);
        } else {
          expect(run, label).toThrow();
        }
      }
    });
  });
}

interface WyDsaTest {
  tcId: number;
  msg: string;
  sig: string;
  ctx?: string;
  result: "valid" | "invalid";
  flags: string[];
}

describe.skipIf(!vectorPath("wycheproof-mldsa87-verify.json"))("Wycheproof mldsa_87_verify_test", () => {
  it("all cases", () => {
    const { groups } = loadVectors<{ groups: { publicKey: string; tests: WyDsaTest[] }[] }>(
      "wycheproof-mldsa87-verify.json",
    );
    let n = 0;
    for (const g of groups) {
      for (const t of g.tests) {
        const ok = mldsaVerify(unhex(g.publicKey), unhex(t.msg), unhex(t.sig), t.ctx ? unhex(t.ctx) : undefined);
        expect(ok, `tc ${t.tcId} ${t.flags.join(",")}`).toBe(t.result === "valid");
        n++;
      }
    }
    expect(n).toBeGreaterThan(200);
  });
});
