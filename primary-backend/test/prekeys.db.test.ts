import { randomUUID } from "crypto";
import { afterAll, describe, expect, it } from "vitest";

// Optional DB-backed test. Runs only with TEST_DATABASE_URL pointing at a
// throwaway, fully migrated Postgres, e.g.:
//   docker run -d --rm -p 55432:5432 -e POSTGRES_PASSWORD=pw postgres:16-alpine
//   DATABASE_URL=... npx prisma migrate deploy
//   TEST_DATABASE_URL=postgresql://postgres:pw@localhost:55432/postgres npm test
const url = process.env.TEST_DATABASE_URL;

describe.skipIf(!url)("one-time prekey claim (Postgres)", async () => {
  if (!url) return;
  process.env.DATABASE_URL = url;
  const { prisma } = await import("../src/db.js");
  const { claimOneTimePrekey } = await import("../src/prekeys.js");

  const username = `opk-test-${randomUUID().slice(0, 8)}`;
  const user = await prisma.user.create({
    data: { username, srpSalt: "00", srpVerifier: "00", identityKeyPub: "IK" },
  });

  afterAll(async () => {
    await prisma.user.delete({ where: { id: user.id } }); // cascades to prekeys
    await prisma.$disconnect();
  });

  it("hands out each OPK exactly once under concurrency, oldest first", async () => {
    const N = 25;
    for (let i = 0; i < N; i++) {
      await prisma.oneTimePrekey.create({
        data: { userId: user.id, keyId: i, publicKey: `pk${i}`, signature: `sig${i}` },
      });
    }

    const claims = await Promise.all(
      Array.from({ length: N + 5 }, () => claimOneTimePrekey(user.id)),
    );
    const got = claims.filter((c) => c !== null).map((c) => c!.keyId);
    expect(got).toHaveLength(N);
    expect(new Set(got).size).toBe(N);
    expect(claims.filter((c) => c === null)).toHaveLength(5);
    expect(await prisma.oneTimePrekey.count({ where: { userId: user.id } })).toBe(0);
  });
});
