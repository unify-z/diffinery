/**
 * Password sign-in (src/auth/password.ts) and the first-run wizard (src/web/setup.tsx).
 *
 * The wizard exists for an instance with no email transport and no Cloudflare Access, where an
 * invite link, an administrator's sign-in link and a passkey all need someone who is already in.
 */
import { describe, expect, it } from "vitest";
import { app } from "../../src/app.js";
import { web } from "../../src/web/routes.js";
import { hashPassword, MAX_PASSWORD_LENGTH, MIN_PASSWORD_LENGTH, needsRehash, passwordProblem, verifyPassword } from "../../src/auth/password.js";
import type { Env } from "../../src/env.js";

const ORIGIN = "https://diffinery.example";

describe("password hashing", () => {
  it("verifies the password it hashed, and only that one", async () => {
    const stored = await hashPassword("correct horse battery");
    expect(await verifyPassword("correct horse battery", stored)).toBe(true);
    expect(await verifyPassword("correct horse batterY", stored)).toBe(false);
    expect(await verifyPassword("", stored)).toBe(false);
  });

  it("salts every hash, so one password gives a different value each time", async () => {
    const [a, b] = await Promise.all([hashPassword("same password twice"), hashPassword("same password twice")]);
    expect(a).not.toEqual(b);
    expect(await verifyPassword("same password twice", a)).toBe(true);
    expect(await verifyPassword("same password twice", b)).toBe(true);
  });

  it("writes a self-describing value, and refuses anything else", async () => {
    const stored = await hashPassword("a long enough password");
    expect(stored).toMatch(/^pbkdf2-sha256\$\d+\$[A-Za-z0-9_-]+\$[A-Za-z0-9_-]+$/);
    for (const bad of ["", "plain", "pbkdf2-sha256$1$c2FsdA$aGFzaA", "md5$1000$c2FsdA$aGFzaA", "pbkdf2-sha256$99999999$c2FsdA$aGFzaA", null, undefined]) {
      expect(await verifyPassword("a long enough password", bad as string | null | undefined)).toBe(false);
    }
  });

  it("asks for a rehash only when the iteration count went up", async () => {
    expect(needsRehash(await hashPassword("another good password"))).toBe(false);
    expect(needsRehash("pbkdf2-sha256$1000$c2FsdA$aGFzaA")).toBe(true);
    expect(needsRehash("pbkdf2-sha256$210000$c2FsdA$aGFzaA")).toBe(false);
  });
});

describe("password rules", () => {
  it("asks for length, not punctuation", () => {
    expect(passwordProblem("short")).toMatch(/at least 10/);
    // No punctuation or symbol is required at the minimum length.
    expect(passwordProblem("abcdefghij")).toBeNull();
    expect(passwordProblem("correct horse battery staple")).toBeNull();
    expect(passwordProblem("x".repeat(MAX_PASSWORD_LENGTH + 1))).toMatch(/at most/);
    // But repetition alone is refused, whatever its length.
    expect(passwordProblem("x".repeat(MIN_PASSWORD_LENGTH))).toMatch(/different characters/);
    expect(passwordProblem("aaaaaaaaaaaa")).toMatch(/different characters/);
  });
});

describe("the first-run wizard", () => {
  // index.ts mounts the web UI last; do the same here (it can't load Durable Objects under Node).
  app.route("/", web);
  // A D1 with no rows: no account exists, so the instance still needs setting up.
  const stmt = { bind: () => stmt, all: async () => ({ results: [] }), first: async () => null, run: async () => ({ success: true, meta: {} }) };
  const env = { PUBLIC_URL: ORIGIN, DB: { prepare: () => stmt } } as unknown as Env;
  const ctx = { waitUntil() {}, passThroughOnException() {}, props: {} } as unknown as ExecutionContext;
  const get = (path: string, headers: Record<string, string> = {}) => app.fetch(new Request(`${ORIGIN}${path}`, { headers: { accept: "text/html", ...headers } }), env, ctx);

  it("sends a browser to /setup until an account exists", async () => {
    const r = await get("/");
    expect([301, 302, 303, 307, 308]).toContain(r.status);
    expect(r.headers.get("location")).toBe("/setup");
  });

  it("serves the wizard", async () => {
    const r = await get("/setup");
    expect(r.status).toBe(200);
    const html = await r.text();
    expect(html).toContain("Set up Diffinery");
    // The three fields it needs, and no password echoed anywhere.
    for (const name of ["login", "email", "password", "confirm"]) expect(html).toContain(`name="${name}"`);
  });

  it("leaves the docs and the project's own pages reachable", async () => {
    // They need no account, so setup does not stand in their way.
    for (const path of ["/docs/quickstart", "/features", "/compare/github"]) {
      const r = await get(path);
      expect(r.headers.get("location"), path).not.toBe("/setup");
    }
  });

  it("does not redirect API or git clients", async () => {
    const r = await app.fetch(new Request(`${ORIGIN}/api/v3/meta`, { headers: { accept: "application/json" } }), env, ctx);
    expect(r.headers.get("location")).not.toBe("/setup");
  });
});
