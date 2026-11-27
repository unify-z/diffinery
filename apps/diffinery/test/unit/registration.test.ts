/**
 * Self-service registration (auth/registration.ts, web/registration.tsx, auth/signup.ts).
 *
 * The policy lives in one D1 row that a site administrator edits. These tests run against the real
 * migrations (testD1), so a missing or hand-edited row is what the code actually reads. They cover:
 * the defaults, what the switch and the ways in do, that the server refuses what the page hides,
 * pending accounts, the audit trail, Turnstile, the SIGNUP=open override, and the rule that /setup
 * and invitations never depend on any of it.
 */
import { describe, expect, it } from "vitest";
import { app } from "../../src/app.js";
import { web } from "../../src/web/routes.js";
import type { Env } from "../../src/env.js";
import type { Account } from "../../src/lib/directory.js";
import { Directory } from "../../src/lib/directory.js";
import { DEFAULT_POLICY, methodProblem, parsePolicy, policyFromForm, readRegistrationPolicy, registrationPolicy, registrationProblem, registrationSummary, saveRegistrationPolicy, turnstileProblem, type RegistrationPolicy } from "../../src/auth/registration.js";
import { Signups, normalEmail } from "../../src/auth/signup.js";
import { HttpError } from "../../src/lib/util.js";
import { testD1 } from "./stubs/d1.js";

// index.ts mounts the web UI last; do the same here (it can't load Durable Objects under Node). Mounted once: Hono
// refuses a route added after the first request.
app.route("/", web);

const PUB = "https://diffinery.example";
/** Local development: Turnstile is skipped here, as sign-up does on the local machine (auth/signup.ts turnstileMode). */
const LOCAL = "http://localhost:8787";
const MASTER_KEY = btoa(String.fromCharCode(...new Uint8Array(32).fill(9)));
const at = "2026-10-01T00:00:00.000Z";

/** A migrated D1 with an administrator and an audit sink. */
function setup(over: Record<string, unknown> = {}) {
  const DB = testD1();
  DB.sqlite.prepare("INSERT INTO accounts (id, login, kind, email, status, site_admin, created_at) VALUES (?, ?, 'user', ?, 'active', 1, ?)").run("u-root", "root", "root@example.com", at);
  const audits: Array<{ action: string; detail?: { before?: unknown; after?: unknown } }> = [];
  const dir = { audit: async (e: (typeof audits)[number]) => void audits.push(e) } as unknown as Directory;
  // The e-mail transport is an EMAIL binding unless a test says otherwise.
  const env = { DB, PUBLIC_URL: PUB, MASTER_KEY, EMAIL: {} as SendEmail, ...over } as unknown as Env;
  const admin = DB.sqlite.prepare("SELECT * FROM accounts WHERE id = 'u-root'").get() as unknown as Account;
  return { env, DB, audits, dir, admin };
}

const save = (s: ReturnType<typeof setup>, p: Partial<RegistrationPolicy>) =>
  saveRegistrationPolicy(s.env, s.dir, { ...DEFAULT_POLICY, ...p }, s.admin);

describe("the stored policy", () => {
  it("an empty table reads as the defaults: closed, invite-only", async () => {
    const { env, DB } = setup();
    // The migration inserts a row; an installation without it must read the same.
    DB.sqlite.prepare("DELETE FROM registration_policy").run();
    const p = await readRegistrationPolicy(env);
    expect(p).toEqual(DEFAULT_POLICY);
    const r = await registrationPolicy(env);
    expect(r.enabled).toBe(false);
    expect(r.methods).toEqual([]);
    expect(registrationSummary(r)).toMatch(/Closed/);
  });

  it("the migration's row is the defaults too", async () => {
    const { env } = setup();
    expect(await readRegistrationPolicy(env)).toMatchObject({ enabled: false, methods: [], newAccountStatus: "active", turnstile: "inherit", requireEmailVerification: false });
  });

  it("a hand-edited row never grants more than it says", () => {
    expect(parsePolicy({ enabled: 1, methods: '["password","root","email_code"]', require_email_verification: 0, new_account_status: "root", turnstile: "off", updated_at: null, updated_by: null })).toMatchObject({
      enabled: true,
      methods: ["email_code", "password"],
      newAccountStatus: "active",
      turnstile: "inherit",
    });
    expect(parsePolicy({ enabled: 1, methods: "not json", require_email_verification: 1, new_account_status: "pending", turnstile: "require", updated_at: null, updated_by: null }).methods).toEqual([]);
  });

  it("a missing table reads as closed, not as an error", async () => {
    const env = { DB: { prepare: () => ({ first: async () => Promise.reject(new Error("D1_ERROR: no such table: registration_policy")) }) } } as unknown as Env;
    expect(await readRegistrationPolicy(env)).toEqual(DEFAULT_POLICY);
  });

  it("is read fresh: closing it is in force on the very next read", async () => {
    const s = setup();
    await save(s, { enabled: true, methods: ["password"] });
    expect((await registrationPolicy(s.env)).enabled).toBe(true);
    // Changed underneath (another isolate saved it): the next read sees it, with no cache in between.
    s.DB.sqlite.prepare("UPDATE registration_policy SET enabled = 0").run();
    expect((await registrationPolicy(s.env)).enabled).toBe(false);
  });
});

describe("the switch and the ways in", () => {
  it("open with only password: that way is offered, the others are refused", async () => {
    const s = setup();
    await save(s, { enabled: true, methods: ["password"] });
    const r = await registrationPolicy(s.env);
    expect(r.methods).toEqual(["password"]);
    expect(methodProblem(r, "password")).toBeNull();
    expect(methodProblem(r, "passkey")).toMatch(/Passkey sign-up is turned off/);
    expect(methodProblem(r, "email_code")).toMatch(/Emailed code sign-up is turned off/);
  });

  it("open but no passkey and no emailed code: those entry points refuse", async () => {
    const s = setup();
    await save(s, { enabled: true, methods: ["password"] });
    const r = await registrationPolicy(s.env);
    for (const m of ["passkey", "email_code"] as const) expect(methodProblem(r, m)).not.toBeNull();
  });

  it("the master switch off refuses every way, even when methods are still stored", async () => {
    const s = setup();
    await save(s, { enabled: false, methods: ["password", "passkey", "email_code"] });
    const r = await registrationPolicy(s.env);
    expect(r.policy.methods).toEqual(["email_code", "passkey", "password"]);
    expect(r.enabled).toBe(false);
    for (const m of ["password", "passkey", "email_code"] as const) expect(methodProblem(r, m)).toMatch(/Registration is closed/);
  });

  it("a way that needs email is not offered on an instance with no email transport", async () => {
    const s = setup({ EMAIL: undefined });
    // Saved while email existed, then the transport went away: the read must still refuse the emailed code.
    s.DB.sqlite.prepare("INSERT INTO registration_policy (id, enabled, methods, require_email_verification, new_account_status, turnstile) VALUES (1, 1, ?, 0, 'active', 'inherit') ON CONFLICT (id) DO UPDATE SET enabled = 1, methods = excluded.methods").run(JSON.stringify(["email_code", "passkey"]));
    const r = await registrationPolicy(s.env);
    expect(r.methods).toEqual(["passkey"]);
    expect(methodProblem(r, "email_code")).toMatch(/can't send a sign-up code/);
  });

  it("turning on a way that needs email without an email transport is refused when saving", async () => {
    const s = setup({ EMAIL: undefined });
    await expect(save(s, { enabled: true, methods: ["email_code"] })).rejects.toMatchObject({ status: 422 });
    await expect(save(s, { enabled: true, methods: ["password"], requireEmailVerification: true })).rejects.toMatchObject({ status: 422 });
    // Passkey and password without verification need no email.
    await expect(save(s, { enabled: true, methods: ["passkey", "password"] })).resolves.toBeTruthy();
  });

  it("an open switch with no way in is refused when saving", async () => {
    const s = setup();
    await expect(save(s, { enabled: true, methods: [] })).rejects.toMatchObject({ status: 422 });
    expect(registrationProblem(s.env, { ...DEFAULT_POLICY, enabled: true })).toMatch(/at least one way/);
  });

  it("the admin form drops unknown values rather than trusting them", () => {
    const form = { b: (n: string) => n === "enabled", all: (n: string) => (n === "methods" ? ["password", "root", "passkey"] : []), s: (n: string) => (n === "turnstile" ? "off" : n === "new_account_status" ? "superuser" : "") };
    expect(policyFromForm(form)).toMatchObject({ enabled: true, methods: ["passkey", "password"], newAccountStatus: "active", turnstile: "inherit" });
  });
});

describe("the environment override (SIGNUP=open)", () => {
  it("adds the emailed-code way and keeps registration on, but never removes the page's choices", async () => {
    const s = setup({ SIGNUP: "open" });
    const r = await registrationPolicy(s.env);
    expect(r.forcedByEnv).toBe(true);
    expect(r.enabled).toBe(true);
    expect(r.methods).toEqual(["email_code"]);
    await save(s, { enabled: false, methods: ["passkey"] });
    const again = await registrationPolicy(s.env);
    expect(again.enabled).toBe(true);
    expect(again.methods).toEqual(["email_code", "passkey"]);
    expect(registrationSummary(again)).toMatch(/SIGNUP=open is set/);
  });

  it("an instance without SIGNUP=open is unaffected by it", async () => {
    const s = setup();
    expect((await registrationPolicy(s.env)).forcedByEnv).toBe(false);
  });
});

describe("Turnstile", () => {
  it("require without keys refuses sign-up with a readable reason", async () => {
    const s = setup({ PUBLIC_URL: PUB, TURNSTILE_SITE_KEY: undefined, TURNSTILE_SECRET: undefined });
    await save(s, { enabled: true, methods: ["passkey"], turnstile: "require" });
    const r = await registrationPolicy(s.env);
    expect(r.turnstile.mode).toBe("missing");
    expect(turnstileProblem(r)).toMatch(/requires Turnstile, but it has no TURNSTILE_SITE_KEY/);
  });

  it("inherit uses the instance's keys when present", async () => {
    const s = setup({ TURNSTILE_SITE_KEY: "site", TURNSTILE_SECRET: "secret" });
    const r = await registrationPolicy(s.env);
    expect(r.turnstile).toEqual({ mode: "verify", siteKey: "site" });
  });

  it("the check is never switched off from the page", () => {
    expect(["inherit", "require"]).toEqual(expect.arrayContaining([DEFAULT_POLICY.turnstile]));
    expect(parsePolicy({ enabled: 1, methods: "[]", require_email_verification: 0, new_account_status: "active", turnstile: "off", updated_at: null, updated_by: null }).turnstile).toBe("inherit");
  });
});

describe("pending accounts", () => {
  it("a pending password account is created, signs in later, and can't use the site", async () => {
    const s = setup();
    await save(s, { enabled: true, methods: ["password"], newAccountStatus: "pending" });
    const dir = new Directory(s.env);
    const acct = await dir.userForEmail("newbie@example.com", { login: "newbie", passwordHash: "pbkdf2-sha256$1000$c2FsdA$aGFzaA", active: false });
    expect(acct.status).toBe("pending");
    expect(acct.password_hash).toBe("pbkdf2-sha256$1000$c2FsdA$aGFzaA");
    // The request-level gate refuses writes from a pending account (principal.ts requireAccount).
    const { requireAccount } = await import("../../src/auth/principal.js");
    const c = { get: () => ({ type: "account", account: acct, via: "session" }) } as unknown as Parameters<typeof requireAccount>[0];
    expect(() => requireAccount(c)).toThrow(HttpError);
    expect(() => requireAccount(c)).toThrow(/waiting for an invite/);
  });

  it("an active account can use the site", async () => {
    const s = setup();
    const dir = new Directory(s.env);
    const acct = await dir.userForEmail("ready@example.com", { login: "ready", active: true });
    expect(acct.status).toBe("active");
  });
});

describe("the audit trail", () => {
  it("a policy save is audited with what it was and what it is", async () => {
    const s = setup();
    await save(s, { enabled: true, methods: ["password"] });
    expect(s.audits).toHaveLength(1);
    expect(s.audits[0]!.action).toBe("registration.policy.update");
    expect(s.audits[0]!.detail?.before).toMatchObject({ enabled: false, methods: [] });
    expect(s.audits[0]!.detail?.after).toMatchObject({ enabled: true, methods: ["password"] });
  });

  it("the stored row records who saved it and when", async () => {
    const s = setup();
    await save(s, { enabled: true, methods: ["password"] });
    const row = s.DB.sqlite.prepare("SELECT updated_by, updated_at FROM registration_policy").get() as { updated_by: string; updated_at: string };
    expect(row.updated_by).toBe("root");
    expect(Date.parse(row.updated_at)).toBeGreaterThan(0);
  });

  it("the single row is replaced, never duplicated", async () => {
    const s = setup();
    await save(s, { enabled: true, methods: ["password"] });
    await save(s, { enabled: true, methods: ["passkey"] });
    expect((s.DB.sqlite.prepare("SELECT count(*) AS n FROM registration_policy").get() as { n: number }).n).toBe(1);
  });
});

describe("the emailed-code path", () => {
  it("a code is still checked and counted with the policy on", async () => {
    const s = setup();
    await save(s, { enabled: true, methods: ["email_code"] });
    const signups = new Signups(s.env);
    const { code } = await signups.issue("new@example.com", "203.0.113.9");
    const wrong = String((Number(code) + 1) % 1_000_000).padStart(6, "0");
    expect(await signups.check("new@example.com", wrong)).toEqual({ ok: false, left: 4 });
    expect(await signups.check("new@example.com", code)).toEqual({ ok: true, pending: null });
  });

  it("a password sign-up's code carries the password, hashed, and no plaintext", async () => {
    const s = setup();
    const signups = new Signups(s.env);
    const { code } = await signups.issue("pw@example.com", "203.0.113.9", { login: "pw", name: null, passwordHash: "pbkdf2-sha256$210000$c2FsdA$aGFzaA", method: "password" });
    const row = s.DB.sqlite.prepare("SELECT * FROM signup_codes").get() as Record<string, unknown>;
    expect(JSON.stringify(row)).not.toContain(code);
    const r = await signups.check("pw@example.com", code);
    expect(r).toMatchObject({ ok: true, pending: { login: "pw", method: "password", passwordHash: "pbkdf2-sha256$210000$c2FsdA$aGFzaA" } });
  });

  it("an address is normalised before it is compared", () => {
    expect(normalEmail("  Ada@Example.COM ")).toBe("ada@example.com");
  });
});

describe("/setup and invitations do not depend on registration", () => {
  // A fresh instance (no account) with registration closed: /setup must still answer, whatever the policy says.
  it("/setup serves the wizard while the policy is closed, and redirects once an account exists", async () => {
    const ctx = { waitUntil() {}, passThroughOnException() {}, props: {} } as unknown as ExecutionContext;
    // No account yet: a D1 whose account lookups find nothing, and whose policy row says closed.
    const empty = { bind: () => empty, all: async () => ({ results: [] }), first: async () => null, run: async () => ({ success: true, meta: {} }) };
    const fresh = { PUBLIC_URL: PUB, DB: { prepare: () => empty } } as unknown as Env;
    const wizard = await app.fetch(new Request(`${PUB}/setup`, { headers: { accept: "text/html" } }), fresh, ctx);
    expect(wizard.status).toBe(200);
    expect(await wizard.text()).toContain("Set up Diffinery");
    // With an account, /setup leads to sign-in whatever the policy: it never reopens.
    const s = setup();
    s.DB.sqlite.prepare("UPDATE registration_policy SET enabled = 0").run();
    const done = await app.fetch(new Request(`${PUB}/setup`, { headers: { accept: "text/html" }, redirect: "manual" }), s.env, ctx);
    expect(done.headers.get("location")).toBe("/login");
  });

  it("nothing in the setup wizard reads the registration policy", async () => {
    const { readFileSync } = await import("node:fs");
    const src = readFileSync(new URL("../../src/web/setup.tsx", import.meta.url), "utf8");
    expect(src).not.toMatch(/SIGNUP|signupOpen|registrationPolicy|registration/);
  });

  it("an invitation still creates an account while registration is closed", async () => {
    const s = setup();
    s.DB.sqlite.prepare("UPDATE registration_policy SET enabled = 0").run();
    expect((await registrationPolicy(s.env)).enabled).toBe(false);
    const dir = new Directory(s.env);
    s.DB.sqlite.prepare("INSERT INTO invites (id, email, role, token_hash, invited_by, created_at, expires_at) VALUES ('i1', 'guest@example.com', 'member', 'h1', 'u-root', ?, '2999-01-01T00:00:00.000Z')").run(at);
    const acct = await dir.userForEmail("guest@example.com", { login: "guest" });
    expect(acct.status).toBe("active");
  });
});

describe("the sign-up pages follow the policy", () => {
  it("closed: /signup answers 404, or leads to early access when Turnstile is set up", async () => {
    const s = setup({ PUBLIC_URL: PUB, TURNSTILE_SITE_KEY: "site", TURNSTILE_SECRET: "secret" });
    const ctx = { waitUntil() {}, passThroughOnException() {}, props: {} } as unknown as ExecutionContext;
    const get = (p: string) => app.fetch(new Request(`${PUB}${p}`, { headers: { accept: "text/html", cookie: "" }, redirect: "manual" } as RequestInit), s.env, ctx);
    // An installed instance, so /setup doesn't intervene.
    s.DB.sqlite.prepare("UPDATE registration_policy SET enabled = 0").run();
    const closed = await get("/signup");
    expect([302, 404]).toContain(closed.status);
    if (closed.status === 302) expect(closed.headers.get("location")).toBe("/early-access");
    expect((await get("/signup/password")).status).toBe(404);
  });

  it("open with password only: /signup/password is served, the passkey page is not", async () => {
    const s = setup({ PUBLIC_URL: PUB, TURNSTILE_SITE_KEY: "site", TURNSTILE_SECRET: "secret" });
    await save(s, { enabled: true, methods: ["password"] });
    const ctx = { waitUntil() {}, passThroughOnException() {}, props: {} } as unknown as ExecutionContext;
    const get = (p: string) => app.fetch(new Request(`${PUB}${p}`, { headers: { accept: "text/html" } }), s.env, ctx);
    const pw = await get("/signup/password");
    expect(pw.status).toBe(200);
    const html = await pw.text();
    expect(html).toContain('name="password"');
    expect(html).not.toMatch(/type="checkbox"|<select/);
    // The passkey page is not served while passkey sign-up is off: the browser gets the password page instead.
    const passkey = await get("/signup/passkey");
    const passkeyHtml = await passkey.text();
    expect(passkeyHtml).not.toMatch(/data-passkey="register"/);
    expect(passkeyHtml).toContain('name="password"');
    // A passkey ticket posted to the passkey endpoint is refused too.
    // A valid CSRF pair, so the refusal that answers is the policy's own, not the form check's.
    const token = "csrf-token-for-the-test-0001";
    const body = `email=a%40example.com&_csrf=${token}`;
    const posted = await app.fetch(new Request(`${PUB}/signup/passkey`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", "content-length": String(body.length), accept: "text/html", cookie: `dfy_csrf=${token}` }, body }), s.env, ctx);
    expect(posted.status).toBe(403);
    expect(await posted.text()).toMatch(/Passkey sign-up is turned off/);
  });

  it("the login page offers no sign-up when closed", async () => {
    const s = setup({ PUBLIC_URL: PUB, TURNSTILE_SITE_KEY: "site", TURNSTILE_SECRET: "secret" });
    const ctx = { waitUntil() {}, passThroughOnException() {}, props: {} } as unknown as ExecutionContext;
    const html = await (await app.fetch(new Request(`${PUB}/login`, { headers: { accept: "text/html" } }), s.env, ctx)).text();
    expect(html).toMatch(/invite-only/);
    expect(html).not.toMatch(/href="\/signup"/);
  });
});

describe("refusals on the form", () => {
  const ctx = { waitUntil() {}, passThroughOnException() {}, props: {} } as unknown as ExecutionContext;
  const post = (s: ReturnType<typeof setup>, path: string, fields: Record<string, string>) => {
    const token = "csrf-token-for-the-test-0002";
    const body = new URLSearchParams({ ...fields, _csrf: token }).toString();
    return app.fetch(new Request(`${PUB}${path}`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", "content-length": String(body.length), accept: "text/html", cookie: `dfy_csrf=${token}` }, body }), s.env, ctx);
  };
  const pw = { login: "bee", password: "correct horse battery", confirm: "correct horse battery" };

  it("a password sign-up that needs Turnstile and has no keys says so on the page, with 503, and creates nothing", async () => {
    const s = setup({ PUBLIC_URL: PUB, TURNSTILE_SITE_KEY: undefined, TURNSTILE_SECRET: undefined });
    await save(s, { enabled: true, methods: ["password"], turnstile: "require" });
    const r = await post(s, "/signup/password", { email: "b@example.com", ...pw });
    expect(r.status).toBe(503);
    expect(await r.text()).toMatch(/requires Turnstile, but it has no TURNSTILE_SITE_KEY/);
    expect(s.DB.sqlite.prepare("SELECT count(*) AS n FROM accounts WHERE email = 'b@example.com'").get()).toEqual({ n: 0 });
  });

  it("a password below the minimum is refused on the page and nothing is stored", async () => {
    const s = setup({ PUBLIC_URL: LOCAL });
    await save(s, { enabled: true, methods: ["password"] });
    const r = await post(s, "/signup/password", { email: "c@example.com", login: "cee", password: "short", confirm: "short" });
    expect(r.status).toBe(422);
    expect(await r.text()).toMatch(/at least 10 characters/);
    expect(s.DB.sqlite.prepare("SELECT count(*) AS n FROM accounts WHERE email = 'c@example.com'").get()).toEqual({ n: 0 });
  });

  it("a password sign-up creates an active account with the password stored, and signs it in", async () => {
    const s = setup({ PUBLIC_URL: LOCAL });
    await save(s, { enabled: true, methods: ["password"] });
    const r = await post(s, "/signup/password", { email: "dee@example.com", login: "dee", name: "Dee", ...pw });
    expect(r.status).toBe(303);
    expect(r.headers.get("location")).toBe("/");
    const row = s.DB.sqlite.prepare("SELECT status, password_hash FROM accounts WHERE email = 'dee@example.com'").get() as { status: string; password_hash: string };
    expect(row.status).toBe("active");
    expect(row.password_hash).toMatch(/^pbkdf2-sha256\$/);
    expect(row.password_hash).not.toContain("correct horse");
  });

  it("with pending new accounts, a password sign-up creates a pending account that can't use the site", async () => {
    const s = setup({ PUBLIC_URL: LOCAL });
    await save(s, { enabled: true, methods: ["password"], newAccountStatus: "pending" });
    await post(s, "/signup/password", { email: "eve@example.com", login: "eve", ...pw });
    const row = s.DB.sqlite.prepare("SELECT status FROM accounts WHERE email = 'eve@example.com'").get() as { status: string };
    expect(row.status).toBe("pending");
  });
});

describe("an address nobody proved grants nothing", () => {
  const ctx = { waitUntil() {}, passThroughOnException() {}, props: {} } as unknown as ExecutionContext;
  const post = (s: ReturnType<typeof setup>, path: string, fields: Record<string, string>) => {
    const token = "csrf-token-for-the-test-0009";
    const body = new URLSearchParams({ ...fields, _csrf: token }).toString();
    return app.fetch(new Request(`${PUB}${path}`.replace(PUB, String(s.env.PUBLIC_URL)), { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", "content-length": String(body.length), accept: "text/html", cookie: `dfy_csrf=${token}` }, body }), s.env, ctx);
  };
  const pw = { password: "correct horse battery", confirm: "correct horse battery" };
  const account = (s: ReturnType<typeof setup>, email: string) => s.DB.sqlite.prepare("SELECT * FROM accounts WHERE lower(email) = ?").get(email) as Record<string, unknown> | undefined;

  it("a password sign-up with a bootstrap administrator's address does not make a site administrator", async () => {
    const s = setup({ PUBLIC_URL: LOCAL, BOOTSTRAP_ADMINS: "ops@example.com" });
    await save(s, { enabled: true, methods: ["password"] });
    const r = await post(s, "/signup/password", { email: "ops@example.com", login: "ops", ...pw });
    expect(r.status).toBe(303);
    expect(account(s, "ops@example.com")).toMatchObject({ site_admin: 0, email_unverified: 1 });
  });

  it("an unproven account doesn't take the invitations sent to its address", async () => {
    const s = setup({ PUBLIC_URL: LOCAL });
    s.DB.sqlite.prepare("INSERT INTO accounts (id, login, kind, status, created_at) VALUES ('o1', 'acme', 'org', 'active', ?)").run(at);
    s.DB.sqlite.prepare("INSERT INTO invites (id, org_id, email, role, token_hash, invited_by, created_at, expires_at) VALUES ('i9', 'o1', 'victim@example.com', 'admin', 'h9', 'u-root', ?, '2999-01-01T00:00:00.000Z')").run(at);
    await save(s, { enabled: true, methods: ["password"], newAccountStatus: "pending" });
    await post(s, "/signup/password", { email: "victim@example.com", login: "mallory", ...pw });
    const a = account(s, "victim@example.com")!;
    // Created as the policy says (pending), not activated by the invitation, and not a member.
    expect(a).toMatchObject({ status: "pending", email_unverified: 1 });
    expect(s.DB.sqlite.prepare("SELECT count(*) AS n FROM org_members WHERE user_id = ?").get(a.id)).toEqual({ n: 0 });
    expect(s.DB.sqlite.prepare("SELECT accepted_at FROM invites WHERE id = 'i9'").get()).toEqual({ accepted_at: null });
    const dir = new Directory(s.env);
    const me = (await dir.account(a.id as string))!;
    expect(await dir.invitesFor(me)).toEqual([]);
    await expect(dir.answerInvite("i9", me, true)).rejects.toMatchObject({ status: 404 });
  });

  it("whoever proves the address later gets it; the unproven account keeps its login", async () => {
    const s = setup({ PUBLIC_URL: LOCAL });
    await save(s, { enabled: true, methods: ["password"] });
    await post(s, "/signup/password", { email: "real@example.com", login: "squatter", ...pw });
    const dir = new Directory(s.env);
    // The real owner arrives with proof (an invitation's emailed link, Access, an emailed code).
    const owner = await dir.userForEmail("real@example.com", { login: "real" });
    expect(owner.login).toBe("real");
    expect(owner.email_unverified).toBe(0);
    expect(s.DB.sqlite.prepare("SELECT email FROM accounts WHERE login = 'squatter'").get()).toEqual({ email: null });
  });

  it("a proven account is not taken over by a later unproven sign-up", async () => {
    const s = setup({ PUBLIC_URL: LOCAL });
    await save(s, { enabled: true, methods: ["password"] });
    const r = await post(s, "/signup/password", { email: "root@example.com", login: "notroot", ...pw });
    expect(r.status).toBe(409);
    expect(account(s, "root@example.com")).toMatchObject({ login: "root", site_admin: 1 });
  });

  it("with email verification on, the page reads the same for a taken and a free address", async () => {
    const s = setup({ PUBLIC_URL: LOCAL });
    await save(s, { enabled: true, methods: ["password"], requireEmailVerification: true });
    const taken = await post(s, "/signup/password", { email: "root@example.com", login: "x1", ...pw });
    const free = await post(s, "/signup/password", { email: "nobody@example.com", login: "x2", ...pw });
    expect(taken.status).toBe(200);
    expect(free.status).toBe(200);
    expect(await taken.text()).toMatch(/We sent a code to <b>root@example\.com<\/b>/);
    expect(await free.text()).toMatch(/We sent a code to <b>nobody@example\.com<\/b>/);
    // The taken address's code carries no password: entering it can't create anything.
    const rows = s.DB.sqlite.prepare("SELECT email, password_hash FROM signup_codes ORDER BY email").all();
    expect(rows).toEqual([
      { email: "nobody@example.com", password_hash: expect.stringMatching(/^pbkdf2-sha256\$/) },
      { email: "root@example.com", password_hash: null },
    ]);
  });

  it("a code-confirmed password sign-up creates a proven account", async () => {
    const s = setup({ PUBLIC_URL: LOCAL });
    await save(s, { enabled: true, methods: ["password"], requireEmailVerification: true });
    const signups = new Signups(s.env);
    const { code } = await signups.issue("ok@example.com", "198.51.100.7", { login: "okay", name: null, passwordHash: "pbkdf2-sha256$210000$c2FsdA$aGFzaA", method: "password" });
    const r = await post(s, "/signup/verify", { email: "ok@example.com", code });
    expect(r.status).toBe(303);
    expect(account(s, "ok@example.com")).toMatchObject({ login: "okay", email_unverified: 0, status: "active" });
    // The used code no longer holds the hash.
    expect(s.DB.sqlite.prepare("SELECT password_hash FROM signup_codes").get()).toEqual({ password_hash: null });
  });
});

describe("the page itself", () => {
  it("the Registration tab is a site-administration tab, in the admin list", async () => {
    const { ADMIN_TABS } = await import("../../src/web/account.js");
    expect(ADMIN_TABS).toContain("registration");
  });

  it("the page uses Kumo components, never a native checkbox or select", async () => {
    const { readFileSync } = await import("node:fs");
    const src = readFileSync(new URL("../../src/web/registration.tsx", import.meta.url), "utf8");
    expect(src).not.toMatch(/<select|type="checkbox"|type="radio"/);
    expect(src).toMatch(/KCheckbox/);
    expect(src).toMatch(/KSelect/);
  });
});
