/**
 * Instance-wide settings (Settings → Site administration → Instance, migration 0047).
 *
 * One row with the two answers a Git host's operator needs and a project's own instance doesn't:
 *
 * - `mode`: "demo" or "production". Demo is what this repository is — a place to try the thing:
 *   the pages say so and link to it. Production is any real instance someone runs: the project's
 *   marketing (footer, "Deploy your own", Product/Compare links, Star on GitHub) and the project's
 *   own product pages are off, the docs and the API index stay, and nothing advertises the
 *   software it happens to run on.
 * - `requireEmailForSignup`: registration needs an email transport before it can be switched on,
 *   because the emailed code and address confirmation are the only ways to prove an address.
 *   Demo mode relaxes it, so a bare instance can be tried out.
 *
 * Like the registration policy, this is read per request and never cached across requests, so a
 * change is in force on the next one. A missing row, a missing table (a code deploy that raced its
 * migration) or a broken read falls back to demo mode: the safe, upgrade-compatible answer for a
 * page that only decides what to advertise.
 */
import type { Env } from "../env.js";
import type { Account, Directory } from "../lib/directory.js";
import { HttpError, now } from "../lib/util.js";

export const INSTANCE_MODES = ["demo", "production"] as const;
export type InstanceMode = (typeof INSTANCE_MODES)[number];

export const MODE_LABEL: Record<InstanceMode, string> = { demo: "Demo", production: "Production" };

export const MODE_NOTE: Record<InstanceMode, string> = {
  demo: "A place to try Diffinery: pages link to the project, the footer says what this is, and first-run setup never asks for an email transport.",
  production: "A real Git host: no project marketing, no GitHub link, no product or comparison pages. The docs, the API and the repositories are unaffected.",
};

export interface InstanceSettings {
  mode: InstanceMode;
  requireEmailForSignup: boolean;
  updatedAt: string | null;
  updatedBy: string | null;
}

export const DEFAULT_INSTANCE: InstanceSettings = Object.freeze({ mode: "demo" as InstanceMode, requireEmailForSignup: true, updatedAt: null, updatedBy: null });

type SettingsRow = { mode: string | null; require_email_for_signup: number | boolean | null; updated_at: string | null; updated_by: string | null };

const truthy = (v: unknown): boolean => v === 1 || v === true || v === "1";

/** A row (or none) as settings. Unknown values read as the defaults, never as more. */
export function parseInstanceSettings(row: SettingsRow | null | undefined): InstanceSettings {
  if (!row) return DEFAULT_INSTANCE;
  const mode = (INSTANCE_MODES as readonly string[]).includes(row.mode ?? "") ? (row.mode as InstanceMode) : "demo";
  return { mode, requireEmailForSignup: row.require_email_for_signup === null || row.require_email_for_signup === undefined ? true : truthy(row.require_email_for_signup), updatedAt: row.updated_at ?? null, updatedBy: row.updated_by ?? null };
}

/** The settings as stored. Never throws: a page's marketing is not worth a 500. */
export async function readInstanceSettings(env: Pick<Env, "DB">): Promise<InstanceSettings> {
  try {
    return parseInstanceSettings(await env.DB.prepare("SELECT * FROM instance_settings WHERE id = 1").first<SettingsRow>());
  } catch (e) {
    console.error("instance_settings unreadable; treating the instance as demo", e);
    return DEFAULT_INSTANCE;
  }
}

/** Whether this instance is a production Git host (no project marketing, no product pages). */
export async function isProduction(env: Pick<Env, "DB">): Promise<boolean> {
  return (await readInstanceSettings(env)).mode === "production";
}

/** Store the settings and audit what changed. */
export async function saveInstanceSettings(env: Pick<Env, "DB">, dir: Pick<Directory, "audit">, next: Pick<InstanceSettings, "mode" | "requireEmailForSignup">, by: Pick<Account, "id" | "login">): Promise<InstanceSettings> {
  if (!(INSTANCE_MODES as readonly string[]).includes(next.mode)) throw new HttpError(422, "Unknown mode.");
  const before = await readInstanceSettings(env);
  const at = now();
  await env.DB.prepare(
    "INSERT INTO instance_settings (id, mode, require_email_for_signup, updated_at, updated_by) VALUES (1, ?, ?, ?, ?) " +
      "ON CONFLICT (id) DO UPDATE SET mode = excluded.mode, require_email_for_signup = excluded.require_email_for_signup, updated_at = excluded.updated_at, updated_by = excluded.updated_by",
  )
    .bind(next.mode, next.requireEmailForSignup ? 1 : 0, at, by.login)
    .run();
  await dir.audit({ actorId: by.id, actorLogin: by.login, action: "instance.settings.update", detail: { before: { mode: before.mode, requireEmailForSignup: before.requireEmailForSignup }, after: { mode: next.mode, requireEmailForSignup: next.requireEmailForSignup } } });
  return { ...next, updatedAt: at, updatedBy: by.login };
}

/** One sentence for the admin page. */
export function instanceSummary(s: InstanceSettings): string {
  return s.mode === "production"
    ? "Production: this reads as its own Git host. No project marketing, no GitHub link, no product or comparison pages; the docs and the API stay."
    : "Demo: pages say this is Diffinery, link to the project and keep the product and comparison pages, so nobody mistakes it for a service that hides what it runs on.";
}
