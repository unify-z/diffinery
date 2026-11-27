/**
 * Self-service registration (auth/registration.ts, web/registration.tsx, auth/signup.ts).
 *
 * The policy lives in one D1 row that a site administrator edits. These tests run against the real
 * migrations (testD1), so a missing or hand-edited row is what the code actually reads. They cover:
 * the defaults, what the switch and the ways in do, that the server refuses what the page hides,
 * pending accounts, the audit trail, Turnstile, the SIGNUP=open override, and the rule that /setup
 * and invitations never depend on any of it.
 */
import { describe, expect, it, vi } from "vitest";
import { app } from "../../src/app.js";
import { web } from "../../src/web/routes.js";
import type { Env } from "../../src/env.js";
import type { Account } from "../../src/lib/directory.js";
import { Directory } from "../../src/lib/directory.js";
import { DEFAULT_POLICY, emailTransport, methodProblem, parsePolicy, policyFromForm, readRegistrationPolicy, registrationPolicy, registrationProblem, registrationSummary, saveRegistrationPolicy, signupProblem, type RegistrationPolicy } from "../../src/auth/registration.js";
import { capConfiguration, normalCapEndpoint, normalCapSiteKey, normalTurnstileSiteKey, readCaptchaSettings, turnstileCheck, turnstileConfiguration, verifyCaptcha } from "../../src/auth/captcha.js";
import { encryptSecret } from "../../src/lib/crypto.js";
import { readInstanceSettings } from "../../src/lib/instance.js";
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
  // An email transport and Turnstile keys unless a test says otherwise: the deployed norm, so a
  // save that opens registration has a way in and a bot check to work with.
  const env = { DB, PUBLIC_URL: PUB, MASTER_KEY, EMAIL: {} as SendEmail, TURNSTILE_SITE_KEY: "0x4AAAAAAAsite", TURNSTILE_SECRET: "turnstile-secret", ...over } as unknown as Env;
  const admin = DB.sqlite.prepare("SELECT * FROM accounts WHERE id = 'u-root'").get() as unknown as Account;
  /** Put the instance in a mode without going through the page. */
  const instance = (mode: "demo" | "production", requireEmailForSignup = true) => DB.sqlite.prepare("UPDATE instance_settings SET mode = ?, require_email_for_signup = ?").run(mode, requireEmailForSignup ? 1 : 0);
  return { env, DB, audits, dir, admin, instance };
}

const save = (s: ReturnType<typeof setup>, p: Partial<RegistrationPolicy>) =>
  saveRegistrationPolicy(s.env, s.dir, { ...DEFAULT_POLICY, ...p }, s.admin);

/**
 * A policy written straight into the row, past the checks: what an instance looks like when the
 * keys or the email transport it relied on disappear after the page was saved.
 */
const stored = (s: ReturnType<typeof setup>, p: Partial<RegistrationPolicy>) =>
  s.DB.sqlite
    .prepare("INSERT INTO registration_policy (id, enabled, methods, new_account_status, provider) VALUES (1, ?, ?, ?, ?) ON CONFLICT (id) DO UPDATE SET enabled = excluded.enabled, methods = excluded.methods, new_account_status = excluded.new_account_status, provider = excluded.provider")
    .run(p.enabled === false ? 0 : 1, JSON.stringify(p.methods ?? ["passkey"]), p.newAccountStatus ?? "active", p.provider ?? "auto");

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
    expect(await readRegistrationPolicy(env)).toMatchObject({ enabled: false, methods: [], newAccountStatus: "active", provider: "auto" });
  });

  it("a hand-edited row never grants more than it says", () => {
    expect(parsePolicy({ enabled: 1, methods: '["password","root","email_code"]', new_account_status: "root", provider: "off", updated_at: null, updated_by: null })).toMatchObject({
      enabled: true,
      methods: ["email_code", "password"],
      newAccountStatus: "active",
      provider: "auto",
    });
    expect(parsePolicy({ enabled: 1, methods: "not json", new_account_status: "pending", provider: "cap", updated_at: null, updated_by: null }).methods).toEqual([]);
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
    s.DB.sqlite.prepare("INSERT INTO registration_policy (id, enabled, methods, new_account_status, provider) VALUES (1, 1, ?, 'active', 'none') ON CONFLICT (id) DO UPDATE SET enabled = 1, methods = excluded.methods, provider = 'none'").run(JSON.stringify(["email_code", "passkey"]));
    const r = await registrationPolicy(s.env);
    expect(r.methods).toEqual(["passkey"]);
    expect(methodProblem(r, "email_code")).toMatch(/can't send a sign-up code/);
    expect(await emailTransport(s.env)).toBe(false);
  });

  it("the emailed-code way can't be turned on without an email transport", async () => {
    const s = setup({ EMAIL: undefined });
    await expect(save(s, { enabled: true, methods: ["email_code"] })).rejects.toMatchObject({ status: 422 });
    await expect(save(s, { enabled: true, methods: ["passkey", "password"] })).resolves.toBeTruthy();
  });

  it("a production instance needs an email transport before registration opens", async () => {
    const s = setup({ EMAIL: undefined, SMTP_URL: undefined });
    s.instance("production");
    await expect(save(s, { enabled: true, methods: ["password"] })).rejects.toMatchObject({ status: 422 });
    // Saved while email worked, then it went away: the read refuses, with the reason.
    stored(s, { enabled: true, methods: ["password"] });
    const r = await registrationPolicy(s.env);
    expect(r.enabled).toBe(false);
    expect(r.blockedBy).toBe("email");
    expect(signupProblem(r)).toMatch(/no email transport.*demo mode/);
  });

  it("demo mode lets a bare instance open registration, for trying it out", async () => {
    const s = setup({ EMAIL: undefined, SMTP_URL: undefined });
    s.instance("demo");
    await expect(save(s, { enabled: true, methods: ["password"] })).resolves.toBeTruthy();
    const r = await registrationPolicy(s.env);
    expect(r.enabled).toBe(true);
    expect(r.emailRequired).toBe(false);
  });

  it("production with email set up opens as usual", async () => {
    const s = setup({ SMTP_URL: "smtps://user@mail.example.com:465", SMTP_PASSWORD: "pw" });
    s.instance("production");
    await expect(save(s, { enabled: true, methods: ["email_code", "password"] })).resolves.toBeTruthy();
    const r = await registrationPolicy(s.env);
    expect(r.enabled).toBe(true);
    expect(r.methods).toEqual(["email_code", "password"]);
  });

  it("an open switch with no way in is refused when saving", async () => {
    const s = setup();
    await expect(save(s, { enabled: true, methods: [] })).rejects.toMatchObject({ status: 422 });
    expect(registrationProblem({ ...DEFAULT_POLICY, enabled: true }, { email: true, emailRequired: false, captcha: { kind: "none", field: "cf-turnstile-response", missing: null } })).toMatch(/at least one way/);
  });

  it("the admin form drops unknown values rather than trusting them", () => {
    const form = { b: (n: string) => n === "enabled", all: (n: string) => (n === "methods" ? ["password", "root", "passkey"] : []), s: (n: string) => (n === "provider" ? "off" : n === "new_account_status" ? "superuser" : "") };
    expect(policyFromForm(form)).toMatchObject({ enabled: true, methods: ["passkey", "password"], newAccountStatus: "active", provider: "auto" });
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

describe("the bot check", () => {
  const noKeys = { PUBLIC_URL: PUB, TURNSTILE_SITE_KEY: undefined, TURNSTILE_SECRET: undefined };
  const capEnv = { CAP_ENDPOINT: "https://cap.example.com", CAP_SITE_KEY: "sitekey1", CAP_SECRET: "s3cret" };

  it("auto takes cap.js when it is set up, else Turnstile, else nothing", async () => {
    const withBoth = setup({ ...capEnv, TURNSTILE_SITE_KEY: "site", TURNSTILE_SECRET: "secret" });
    await save(withBoth, { enabled: true, methods: ["passkey"], provider: "auto" });
    const r1 = await registrationPolicy(withBoth.env);
    expect(r1.captcha.kind).toBe("cap");
    expect(r1.captcha.capApiEndpoint).toBe("https://cap.example.com/sitekey1/");
    expect(r1.captcha.field).toBe("cap-token");

    const turnstileOnly = setup({ TURNSTILE_SITE_KEY: "site", TURNSTILE_SECRET: "secret" });
    await save(turnstileOnly, { enabled: true, methods: ["passkey"], provider: "auto" });
    const r2 = await registrationPolicy(turnstileOnly.env);
    expect(r2.captcha).toMatchObject({ kind: "turnstile", siteKey: "site", field: "cf-turnstile-response" });

    // Nothing set up on a deployed instance: opening registration is refused, and a stored policy
    // reports the missing keys instead of letting a script through.
    const bare = noKeysSetup();
    await expect(save(bare, { enabled: true, methods: ["passkey"], provider: "auto" })).rejects.toMatchObject({ status: 422 });
    stored(bare, { enabled: true, methods: ["passkey"], provider: "auto" });
    const r3 = await registrationPolicy(bare.env);
    expect(r3.captcha.missing).toMatch(/TURNSTILE_SITE_KEY/);
    expect(r3.blockedBy).toBe("captcha");
  });

  it("a chosen provider that isn't set up refuses, and the page says so", async () => {
    const s = noKeysSetup();
    await expect(save(s, { enabled: true, methods: ["passkey"], provider: "turnstile" })).rejects.toMatchObject({ status: 422 });
    stored(s, { enabled: true, methods: ["passkey"], provider: "turnstile" });
    const r = await registrationPolicy(s.env);
    expect(r.enabled).toBe(false);
    expect(r.blockedBy).toBe("captcha");
    expect(signupProblem(r)).toMatch(/requires Turnstile|has no TURNSTILE_SITE_KEY/);
    expect(registrationSummary(r)).toMatch(/TURNSTILE_SITE_KEY|Turnstile/);
  });

  it("cap chosen without a server refuses with the variables it needs", async () => {
    const s = setup({ ...noKeys });
    await expect(save(s, { enabled: true, methods: ["passkey"], provider: "cap" })).rejects.toMatchObject({ status: 422 });
    stored(s, { enabled: true, methods: ["passkey"], provider: "cap" });
    const r = await registrationPolicy(s.env);
    expect(r.blockedBy).toBe("captcha");
    expect(signupProblem(r)).toMatch(/CAP_ENDPOINT, CAP_SITE_KEY and CAP_SECRET/);
  });

  it("none is allowed and verifies nothing", async () => {
    const s = setup({ ...noKeys });
    await save(s, { enabled: true, methods: ["password"], provider: "none" });
    const r = await registrationPolicy(s.env);
    expect(r.enabled).toBe(true);
    expect(r.captcha.kind).toBe("none");
  });

  it("the local machine without keys stays open (no check) as before", async () => {
    const s = setup({ PUBLIC_URL: LOCAL, TURNSTILE_SITE_KEY: undefined, TURNSTILE_SECRET: undefined });
    const r = await registrationPolicy(s.env);
    expect(r.captcha.kind).toBe("none");
  });

  it("a cap.js token is checked with the site key's secret at /siteverify", async () => {
    const calls: Array<{ url: string; body: string }> = [];
    vi.stubGlobal("fetch", async (url: string, init: RequestInit) => {
      calls.push({ url, body: String(init.body) });
      return Response.json({ success: true });
    });
    try {
      const s = setup({ ...capEnv });
      await save(s, { enabled: true, methods: ["passkey"], provider: "cap" });
      const r = await registrationPolicy(s.env);
      expect(r.captcha.kind).toBe("cap");
      const cap = await capConfiguration(s.env);
      expect(cap).toMatchObject({ endpoint: "https://cap.example.com", siteKey: "sitekey1", secret: "s3cret", source: "environment" });
      expect(await verifyCaptcha(r.captcha, cap, "token-abc", "203.0.113.9")).toBe(true);
      expect(calls[0]!.url).toBe("https://cap.example.com/sitekey1/siteverify");
      expect(JSON.parse(calls[0]!.body)).toEqual({ secret: "s3cret", response: "token-abc" });
      vi.stubGlobal("fetch", async () => Response.json({ success: false }));
      expect(await verifyCaptcha(r.captcha, cap, "token-abc", null)).toBe(false);
      expect(await verifyCaptcha(r.captcha, cap, "", null)).toBe(false);
      vi.stubGlobal("fetch", async () => {
        throw new Error("down");
      });
      expect(await verifyCaptcha(r.captcha, cap, "token-abc", null)).toBe(false);
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("cap.js set in Settings beats the deployment's variables", async () => {
    const s = setup({ ...capEnv });
    const sealed = await encryptSecret(s.env, "captcha:cap", "stored-secret");
    s.DB.sqlite.prepare("INSERT INTO captcha_settings (id, cap_endpoint, cap_site_key, cap_secret, updated_at, updated_by) VALUES (1, ?, ?, ?, ?, ?) ON CONFLICT (id) DO UPDATE SET cap_endpoint = excluded.cap_endpoint, cap_site_key = excluded.cap_site_key, cap_secret = excluded.cap_secret").run("https://cap.internal.example", "savedkey", sealed, at, "root");
    const cap = await capConfiguration(s.env);
    expect(cap).toMatchObject({ endpoint: "https://cap.internal.example", siteKey: "savedkey", secret: "stored-secret", source: "settings" });
  });

  it("Turnstile keys set in Settings beat the deployment's pair, and clearing them falls back", async () => {
    const s = setup({ TURNSTILE_SITE_KEY: "env-site", TURNSTILE_SECRET: "env-secret" });
    const sealed = await encryptSecret(s.env, "captcha:turnstile", "stored-turnstile-secret");
    s.DB.sqlite.prepare("UPDATE captcha_settings SET turnstile_site_key = ?, turnstile_secret = ? WHERE id = 1").run("0x4AAAAAAAsaved", sealed);
    expect(await turnstileConfiguration(s.env)).toEqual({ siteKey: "0x4AAAAAAAsaved", secret: "stored-turnstile-secret", source: "settings" });
    await save(s, { enabled: true, methods: ["passkey"], provider: "turnstile" });
    expect((await registrationPolicy(s.env)).captcha).toMatchObject({ kind: "turnstile", siteKey: "0x4AAAAAAAsaved" });
    // The secret is sealed, never stored as it was typed.
    expect((s.DB.sqlite.prepare("SELECT turnstile_secret FROM captcha_settings").get() as { turnstile_secret: string }).turnstile_secret).toMatch(/^v2\./);
    // An empty site key goes back to the deployment's variables.
    s.DB.sqlite.prepare("UPDATE captcha_settings SET turnstile_site_key = NULL, turnstile_secret = NULL WHERE id = 1").run();
    expect(await turnstileConfiguration(s.env)).toEqual({ siteKey: "env-site", secret: "env-secret", source: "environment" });
  });

  it("the public forms (early access, contact, security reports) use the stored Turnstile too", async () => {
    const bare = noKeysSetup();
    expect(await turnstileCheck(bare.env)).toEqual({ mode: "missing" });
    const sealed = await encryptSecret(bare.env, "captcha:turnstile", "stored-turnstile-secret");
    bare.DB.sqlite.prepare("UPDATE captcha_settings SET turnstile_site_key = ?, turnstile_secret = ? WHERE id = 1").run("0x4AAAAAAAsaved", sealed);
    expect(await turnstileCheck(bare.env)).toEqual({ mode: "verify", siteKey: "0x4AAAAAAAsaved", secret: "stored-turnstile-secret", source: "settings" });
  });

  it("a half a pair is refused, and an empty server or site key clears the saved one", async () => {
    const s = setup({ PUBLIC_URL: LOCAL, DEV_AUTH: "root@example.com", TURNSTILE_SITE_KEY: undefined, TURNSTILE_SECRET: undefined, CAP_ENDPOINT: undefined, CAP_SITE_KEY: undefined, CAP_SECRET: undefined });
    const ctx = { waitUntil() {}, passThroughOnException() {}, props: {} } as unknown as ExecutionContext;
    const token = "csrf-token-for-the-bot-check-2";
    const form = (path: string, fields: Array<[string, string]>) => {
      const body = new URLSearchParams([...fields, ["_csrf", token]]).toString();
      return app.fetch(new Request(`${LOCAL}${path}`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", "content-length": String(body.length), accept: "text/html", cookie: `dfy_csrf=${token}` }, body }), s.env, ctx);
    };
    // A site key with no secret anywhere would silently fall back to nothing: refused, nothing stored.
    await form("/settings/admin/bot-check/turnstile", [["turnstile_site_key", "0x4AAAAAAAsaved"], ["turnstile_secret", ""]]);
    expect(await readCaptchaSettings(s.env)).toMatchObject({ turnstileSiteKey: null });
    // A whole pair is kept, and the saved secret survives a save that leaves it empty.
    await form("/settings/admin/bot-check/turnstile", [["turnstile_site_key", "0x4AAAAAAAsaved"], ["turnstile_secret", "turnstile-secret"]]);
    await form("/settings/admin/bot-check/turnstile", [["turnstile_site_key", "0x4AAAAAAAsaved"], ["turnstile_secret", ""]]);
    expect(await turnstileConfiguration(s.env)).toMatchObject({ siteKey: "0x4AAAAAAAsaved", secret: "turnstile-secret", source: "settings" });
    // An empty site key clears the pair, so the deployment's variables apply again (none here).
    await form("/settings/admin/bot-check/turnstile", [["turnstile_site_key", ""], ["turnstile_secret", ""]]);
    expect(await readCaptchaSettings(s.env)).toMatchObject({ turnstileSiteKey: null, turnstileSealedSecret: null });
    expect(await turnstileConfiguration(s.env)).toBeNull();
    // cap.js: a server without a secret is refused, and an empty server clears the pair.
    await form("/settings/admin/bot-check/cap", [["cap_endpoint", "https://cap.internal.example"], ["cap_site_key", "savedkey"], ["cap_secret", ""]]);
    expect(await readCaptchaSettings(s.env)).toMatchObject({ capEndpoint: null });
    await form("/settings/admin/bot-check/cap", [["cap_endpoint", "https://cap.internal.example"], ["cap_site_key", "savedkey"], ["cap_secret", "cap-secret"]]);
    expect(await capConfiguration(s.env)).toMatchObject({ endpoint: "https://cap.internal.example", secret: "cap-secret", source: "settings" });
    await form("/settings/admin/bot-check/cap", [["cap_endpoint", ""], ["cap_site_key", "savedkey"], ["cap_secret", ""]]);
    expect(await readCaptchaSettings(s.env)).toMatchObject({ capEndpoint: null, capSiteKey: null, capSealedSecret: null });
  });

  it("saving Registration keeps the bot check chosen on Bot check", async () => {
    const s = setup({ PUBLIC_URL: LOCAL, DEV_AUTH: "root@example.com" });
    const ctx = { waitUntil() {}, passThroughOnException() {}, props: {} } as unknown as ExecutionContext;
    const token = "csrf-token-for-the-bot-check-3";
    const form = (path: string, fields: Array<[string, string]>) => {
      const body = new URLSearchParams([...fields, ["_csrf", token]]).toString();
      return app.fetch(new Request(`${LOCAL}${path}`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", "content-length": String(body.length), accept: "text/html", cookie: `dfy_csrf=${token}` }, body }), s.env, ctx);
    };
    await form("/settings/admin/bot-check", [["provider", "none"]]);
    expect((await readRegistrationPolicy(s.env)).provider).toBe("none");
    // The Registration form has no provider field now: it must not reset the choice to Automatic.
    await form("/settings/admin/registration", [["methods", "passkey"], ["new_account_status", "active"]]);
    expect((await readRegistrationPolicy(s.env)).provider).toBe("none");
    expect((await readRegistrationPolicy(s.env)).methods).toEqual(["passkey"]);
  });

  it("a cap.js sign-up page allows the capd origin in its content security policy", async () => {
    const s = setup({ ...capEnv });
    const sealed = await encryptSecret(s.env, "captcha:cap", "stored-secret");
    s.DB.sqlite.prepare("UPDATE captcha_settings SET cap_endpoint = ?, cap_site_key = ?, cap_secret = ? WHERE id = 1").run("https://cap.internal.example", "savedkey", sealed);
    await save(s, { enabled: true, methods: ["password"], provider: "cap" });
    const ctx = { waitUntil() {}, passThroughOnException() {}, props: {} } as unknown as ExecutionContext;
    const page = await app.fetch(new Request(`${PUB}/signup/password`, { headers: { accept: "text/html" } }), s.env, ctx);
    expect(page.status).toBe(200);
    // The widget fetches `${endpoint}/${siteKey}/api/...`: without that origin in connect-src the browser blocks it.
    const csp = page.headers.get("content-security-policy") ?? "";
    expect(csp).toContain("connect-src");
    expect(csp).toMatch(/connect-src[^;]*https:\/\/cap\.internal\.example/);
    expect(await page.text()).toContain("data-cap-api-endpoint");
  });

  it("a Turnstile site key must look like one", () => {
    expect(normalTurnstileSiteKey("")).toBeNull();
    expect(normalTurnstileSiteKey("0x4AAAAAAA / sted")).toBeNull();
    expect(normalTurnstileSiteKey(" 0x4AAAAAAAabc ")).toBe("0x4AAAAAAAabc");
  });

  it("the Bot check page saves both providers' keys and the provider itself", async () => {
    const s = setup({ PUBLIC_URL: LOCAL, DEV_AUTH: "root@example.com", TURNSTILE_SITE_KEY: undefined, TURNSTILE_SECRET: undefined, CAP_ENDPOINT: undefined, CAP_SITE_KEY: undefined, CAP_SECRET: undefined });
    const ctx = { waitUntil() {}, passThroughOnException() {}, props: {} } as unknown as ExecutionContext;
    const token = "csrf-token-for-the-bot-check-1";
    const form = (path: string, fields: Record<string, string>) => {
      const body = new URLSearchParams({ ...fields, _csrf: token }).toString();
      return app.fetch(new Request(`${LOCAL}${path}`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", "content-length": String(body.length), accept: "text/html", cookie: `dfy_csrf=${token}` }, body }), s.env, ctx);
    };
    const page = await app.fetch(new Request(`${LOCAL}/settings/admin/bot-check`, { headers: { accept: "text/html" } }), s.env, ctx);
    expect(page.status).toBe(200);
    const html = await page.text();
    expect(html).toContain('name="provider"');
    expect(html).toContain('name="turnstile_site_key"');
    expect(html).toContain('name="cap_endpoint"');
    // One page, three forms: both providers' keys, then which check runs.
    expect((await form("/settings/admin/bot-check/turnstile", { turnstile_site_key: "0x4AAAAAAAsaved", turnstile_secret: "TURNSTILE-PLAINTEXT-1" })).status).toBe(303);
    expect((await form("/settings/admin/bot-check/cap", { cap_endpoint: "https://cap.internal.example", cap_site_key: "savedkey", cap_secret: "CAP-PLAINTEXT-1" })).status).toBe(303);
    expect((await form("/settings/admin/bot-check", { provider: "turnstile" })).status).toBe(303);
    const r = await registrationPolicy(s.env);
    expect(r.policy.provider).toBe("turnstile");
    // The provider save kept the rest of the policy as it was: registration is still closed.
    expect(r.policy.enabled).toBe(false);
    expect(r.captcha).toMatchObject({ kind: "turnstile", siteKey: "0x4AAAAAAAsaved" });
    expect(await capConfiguration(s.env)).toMatchObject({ endpoint: "https://cap.internal.example", siteKey: "savedkey", secret: "CAP-PLAINTEXT-1", source: "settings" });
    // Neither secret is ever sent back to a page.
    const again = await (await app.fetch(new Request(`${LOCAL}/settings/admin/bot-check`, { headers: { accept: "text/html" } }), s.env, ctx)).text();
    expect(again).not.toContain("TURNSTILE-PLAINTEXT-1");
    expect(again).not.toContain("CAP-PLAINTEXT-1");
    expect(again).toContain('value="0x4AAAAAAAsaved"');
  });

  it("the Bot check POSTs need a site administrator and a CSRF token", async () => {
    const s = setup({ PUBLIC_URL: LOCAL, TURNSTILE_SITE_KEY: "site", TURNSTILE_SECRET: "secret" });
    const ctx = { waitUntil() {}, passThroughOnException() {}, props: {} } as unknown as ExecutionContext;
    const token = "csrf-token-for-the-bot-check-4";
    const send = (path: string, cookie: string, csrf: string) => {
      const body = new URLSearchParams({ provider: "turnstile", _csrf: csrf }).toString();
      return app.fetch(new Request(`${LOCAL}${path}`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", "content-length": String(body.length), accept: "text/html", cookie }, body }), s.env, ctx);
    };
    // Without the CSRF cookie/token pair, nothing changes.
    expect((await send("/settings/admin/bot-check", "", "nope")).status).toBe(403);
    // A valid pair but no session: signed out is not a site administrator (401 sign-in required, 403 for the rest).
    expect([401, 403]).toContain((await send("/settings/admin/bot-check", `dfy_csrf=${token}`, token)).status);
    expect((await readRegistrationPolicy(s.env)).provider).toBe("auto");
  });

  it("a cap.js server must be https (or loopback) and a site key must look like one", () => {
    expect(normalCapEndpoint("http://cap.example.com")).toBeNull();
    expect(normalCapEndpoint("https://cap.example.com/")).toBe("https://cap.example.com");
    expect(normalCapEndpoint("http://localhost:3000")).toBe("http://localhost:3000");
    expect(normalCapEndpoint("javascript:alert(1)")).toBeNull();
    expect(normalCapEndpoint("https://cap.example.com/?x=1")).toBeNull();
    expect(normalCapSiteKey("ab")).toBeNull();
    expect(normalCapSiteKey("space key")).toBeNull();
    expect(normalCapSiteKey("AbC123")).toBe("AbC123");
  });
});

/** An instance that isn't the local machine and has no bot check configured at all. */
function noKeysSetup() {
  return setup({ PUBLIC_URL: PUB, TURNSTILE_SITE_KEY: undefined, TURNSTILE_SECRET: undefined, CAP_ENDPOINT: undefined, CAP_SITE_KEY: undefined, CAP_SECRET: undefined });
}

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
    expect(await signups.check("new@example.com", code)).toEqual({ ok: true });
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
    stored(s, { enabled: true, methods: ["password"], provider: "turnstile" });
    const r = await post(s, "/signup/password", { email: "b@example.com", ...pw });
    expect(r.status).toBe(503);
    expect(await r.text()).toMatch(/set to check sign-ups with Cloudflare Turnstile, but it has no TURNSTILE_SITE_KEY and TURNSTILE_SECRET/);
    expect(s.DB.sqlite.prepare("SELECT count(*) AS n FROM accounts WHERE email = 'b@example.com'").get()).toEqual({ n: 0 });
  });

  it("a password below the minimum is refused on the page and nothing is stored", async () => {
    const s = setup({ PUBLIC_URL: LOCAL, TURNSTILE_SITE_KEY: undefined, TURNSTILE_SECRET: undefined });
    await save(s, { enabled: true, methods: ["password"] });
    const r = await post(s, "/signup/password", { email: "c@example.com", login: "cee", password: "short", confirm: "short" });
    expect(r.status).toBe(422);
    expect(await r.text()).toMatch(/at least 10 characters/);
    expect(s.DB.sqlite.prepare("SELECT count(*) AS n FROM accounts WHERE email = 'c@example.com'").get()).toEqual({ n: 0 });
  });

  it("a password sign-up creates an active account with the password stored, and signs it in", async () => {
    const s = setup({ PUBLIC_URL: LOCAL, TURNSTILE_SITE_KEY: undefined, TURNSTILE_SECRET: undefined });
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
    const s = setup({ PUBLIC_URL: LOCAL, TURNSTILE_SITE_KEY: undefined, TURNSTILE_SECRET: undefined });
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
    const s = setup({ PUBLIC_URL: LOCAL, BOOTSTRAP_ADMINS: "ops@example.com", TURNSTILE_SITE_KEY: undefined, TURNSTILE_SECRET: undefined });
    await save(s, { enabled: true, methods: ["password"] });
    const r = await post(s, "/signup/password", { email: "ops@example.com", login: "ops", ...pw });
    expect(r.status).toBe(303);
    expect(account(s, "ops@example.com")).toMatchObject({ site_admin: 0, email_unverified: 1 });
  });

  it("an unproven account doesn't take the invitations sent to its address", async () => {
    const s = setup({ PUBLIC_URL: LOCAL, TURNSTILE_SITE_KEY: undefined, TURNSTILE_SECRET: undefined });
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
    const s = setup({ PUBLIC_URL: LOCAL, TURNSTILE_SITE_KEY: undefined, TURNSTILE_SECRET: undefined });
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
    const s = setup({ PUBLIC_URL: LOCAL, TURNSTILE_SITE_KEY: undefined, TURNSTILE_SECRET: undefined });
    await save(s, { enabled: true, methods: ["password"] });
    const r = await post(s, "/signup/password", { email: "root@example.com", login: "notroot", ...pw });
    expect(r.status).toBe(409);
    expect(account(s, "root@example.com")).toMatchObject({ login: "root", site_admin: 1 });
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
