/**
 * Demo mode and production mode (lib/instance.ts): what an instance advertises.
 *
 * A fresh instance is demo, so an upgrade changes nothing an instance shows. Production is a Git
 * host of its own: no project marketing in the footer, header or docs, no project pages, and no
 * project endpoints, while the docs, the GitHub-compatible API, GraphQL and git stay.
 */
import { describe, expect, it } from "vitest";
import { app } from "../../src/app.js";
import { web } from "../../src/web/routes.js";
import type { Env } from "../../src/env.js";
import type { Account } from "../../src/lib/directory.js";
import type { Directory } from "../../src/lib/directory.js";
import { DEFAULT_INSTANCE, MODE_LABEL, instanceSummary, isProduction, parseInstanceSettings, readInstanceSettings, saveInstanceSettings } from "../../src/lib/instance.js";
import { testD1 } from "./stubs/d1.js";

// index.ts mounts the web UI last; do the same here, once (Hono refuses routes after a request).
app.route("/", web);

const PUB = "https://diffinery.example";
const at = "2026-10-01T00:00:00.000Z";

function setup(mode: "demo" | "production" = "demo") {
  const DB = testD1();
  DB.sqlite.prepare("INSERT INTO accounts (id, login, kind, email, status, site_admin, created_at) VALUES ('u-root', 'root', 'user', 'root@example.com', 'active', 1, ?)").run(at);
  DB.sqlite.prepare("UPDATE instance_settings SET mode = ?").run(mode);
  const audits: Array<{ action: string; detail?: unknown }> = [];
  const dir = { audit: async (e: (typeof audits)[number]) => void audits.push(e) } as unknown as Directory;
  const env = { DB, PUBLIC_URL: PUB, MASTER_KEY: btoa("k".repeat(32)), RATE_LIMITS: undefined } as unknown as Env;
  const admin = DB.sqlite.prepare("SELECT * FROM accounts WHERE id = 'u-root'").get() as unknown as Account;
  return { env, DB, dir, admin, audits };
}

const ctx = { waitUntil() {}, passThroughOnException() {}, props: {} } as unknown as ExecutionContext;
const get = (env: Env, path: string) => app.fetch(new Request(`${PUB}${path}`, { headers: { accept: "text/html" }, redirect: "manual" }), env, ctx);

describe("the stored setting", () => {
  it("a fresh instance is demo, so an upgrade changes nothing", async () => {
    const s = setup();
    expect(await readInstanceSettings(s.env)).toMatchObject({ mode: "demo", requireEmailForSignup: true });
    expect(await isProduction(s.env)).toBe(false);
  });

  it("unknown or missing values read as the defaults", () => {
    expect(parseInstanceSettings(null)).toEqual(DEFAULT_INSTANCE);
    expect(parseInstanceSettings({ mode: "production", require_email_for_signup: 0, updated_at: null, updated_by: null })).toMatchObject({ mode: "production", requireEmailForSignup: false });
    expect(parseInstanceSettings({ mode: "staging", require_email_for_signup: 1, updated_at: null, updated_by: null }).mode).toBe("demo");
    expect(MODE_LABEL.production).toBe("Production");
  });

  it("saving is audited with what it was and what it is", async () => {
    const s = setup();
    await saveInstanceSettings(s.env, s.dir, { mode: "production", requireEmailForSignup: false }, s.admin);
    expect(s.audits[0]).toMatchObject({ action: "instance.settings.update", detail: { before: { mode: "demo" }, after: { mode: "production" } } });
    expect(instanceSummary(await readInstanceSettings(s.env))).toMatch(/Production/);
  });
});

describe("what each mode serves", () => {
  it("demo serves the project's pages and marketing", async () => {
    const s = setup("demo");
    expect((await get(s.env, "/features")).status).toBe(200);
    expect((await get(s.env, "/mcp")).status).not.toBe(404);
  });

  it("production answers 404 for the project's pages", async () => {
    const s = setup("production");
    for (const path of ["/features", "/compare/github", "/about", "/blog", "/performance"]) {
      expect((await get(s.env, path)).status, path).toBe(404);
    }
  });

  it("production keeps the API and the instance's own pages", async () => {
    const s = setup("production");
    const meta = await app.fetch(new Request(`${PUB}/api/v3/meta`, { headers: { accept: "application/json" } }), s.env, ctx);
    expect(meta.status).toBe(200);
    expect((await get(s.env, "/login")).status).toBe(200);
  });

  it("production keeps how the CLI and agents reach the instance", async () => {
    // /mcp and the Diffinery-specific API are this instance's own functionality, not marketing:
    // hiding them would break the CLI and MCP clients against a production instance.
    const prod = setup("production");
    const mcp = await app.fetch(new Request(`${PUB}/mcp`, { headers: { accept: "application/json" } }), prod.env, ctx);
    expect(mcp.status).not.toBe(404);
    const emails = await app.fetch(new Request(`${PUB}/api/v3/diffinery/emails`, { headers: { accept: "application/json" } }), prod.env, ctx);
    expect(emails.status).toBe(401);
    // The GitHub-compatible API still answers (401 without credentials, not 404).
    expect((await app.fetch(new Request(`${PUB}/api/v3/user`, { headers: { accept: "application/json" } }), prod.env, ctx)).status).toBe(401);
  });

  it("production also hides the docs, their Markdown and llms.txt", async () => {
    const prod = setup("production");
    for (const path of ["/docs", "/docs/quickstart", "/docs/quickstart.md", "/llms.txt", "/llms-full.txt", "/index.md", "/features.md"]) {
      expect((await get(prod.env, path)).status, path).toBe(404);
    }
    const demo = setup("demo");
    for (const path of ["/docs", "/docs/quickstart", "/llms.txt"]) {
      expect((await get(demo.env, path)).status, path).toBe(200);
    }
  });

  it("production still serves the instance's own pages and its sitemap", async () => {
    const prod = setup("production");
    expect((await get(prod.env, "/login")).status).toBe(200);
    const sitemap = await (await app.fetch(new Request(`${PUB}/sitemap.xml`), prod.env, ctx)).text();
    expect(sitemap).not.toMatch(/\/docs\//);
    expect(sitemap).not.toMatch(/\/features</);
  });


});
