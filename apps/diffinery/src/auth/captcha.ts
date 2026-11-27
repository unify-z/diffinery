/**
 * The bot check in front of the instances's anonymous forms: Cloudflare Turnstile, cap.js (a
 * self-hosted proof-of-work CAPTCHA), or none at all.
 *
 * Turnstile's keys are Worker variables (TURNSTILE_SITE_KEY and the TURNSTILE_SECRET secret), as
 * before. cap.js needs a server of its own (`capd`, docs: capjs.js.org): the instance is given one
 * with CAP_ENDPOINT, CAP_SITE_KEY and the CAP_SECRET secret, or a site administrator sets one in
 * Settings → Site administration → Registration and it is stored here, sealed with MASTER_KEY, so
 * cap.js can be turned on and changed without a deploy. The stored one wins when it is complete.
 *
 * The provider is a column of the registration policy (migration 0047). "auto" takes cap.js when
 * it is configured, then Turnstile, then nothing; a provider that is chosen but not configured is
 * reported as missing, and the form refuses with a readable reason rather than letting a script
 * through.
 *
 * A cap.js token is verified against `${endpoint}/${siteKey}/siteverify` with the site key's secret
 * (never the capd ADMIN_KEY), single use, exactly as its documentation describes:
 * `POST {secret, response} -> {success}`.
 */
import type { Env } from "../env.js";
import { decryptSecret } from "../lib/crypto.js";
import { loopback } from "./dev.js";
import { turnstileMode, verifyTurnstile } from "./signup.js";

/** The providers a site administrator can choose. */
export const CAPTCHA_PROVIDERS = ["auto", "turnstile", "cap", "none"] as const;
export type CaptchaProviderChoice = (typeof CAPTCHA_PROVIDERS)[number];

/** The provider actually in force on a request. */
export type CaptchaKind = "turnstile" | "cap" | "none";

export const PROVIDER_LABEL: Record<CaptchaProviderChoice, string> = {
  auto: "Automatic (cap.js if set up, else Turnstile, else none)",
  turnstile: "Cloudflare Turnstile",
  cap: "cap.js (self-hosted proof of work)",
  none: "None",
};

/** The pinned widget version: one version, reviewed, so an upstream release never changes this instance's page. */
export const CAP_WIDGET_VERSION = "0.1.64";
export const CAP_WIDGET_URL = `https://cdn.jsdelivr.net/npm/@cap.js/widget@${CAP_WIDGET_VERSION}/cap.min.js`;
/** The widget's own dependencies (wasm solvers, pako) come from the same CDN. */
export const CAP_WIDGET_ORIGIN = "https://cdn.jsdelivr.net";

/** cap.js settings a site administrator saved (captcha_settings, migration 0047). The secret is sealed. */
export interface CapSettings {
  endpoint: string | null;
  siteKey: string | null;
  /** Sealed envelope, or null. Never sent to a page. */
  sealedSecret: string | null;
  updatedAt: string | null;
  updatedBy: string | null;
}

export const EMPTY_CAP: CapSettings = Object.freeze({ endpoint: null, siteKey: null, sealedSecret: null, updatedAt: null, updatedBy: null });

type CapRow = { cap_endpoint: string | null; cap_site_key: string | null; cap_secret: string | null; updated_at: string | null; updated_by: string | null };

/** A cap.js endpoint worth calling: https, or http on this machine (local development). */
export function normalCapEndpoint(v: unknown): string | null {
  if (typeof v !== "string") return null;
  const s = v.trim().replace(/\/+$/, "");
  if (!s || s.length > 300) return null;
  try {
    const u = new URL(s);
    if (u.protocol !== "https:" && !(u.protocol === "http:" && loopback(u.origin))) return null;
    // The widget talks to `${endpoint}/${siteKey}/`, so an endpoint is an origin plus an optional path.
    return u.origin + (u.pathname === "/" ? "" : u.pathname) + (u.search || u.hash ? "" : "");
  } catch {
    return null;
  }
}

/** A cap.js site key: a short, opaque token (capd hands out something like `abc123`). */
export function normalCapSiteKey(v: unknown): string | null {
  if (typeof v !== "string") return null;
  const s = v.trim();
  return /^[A-Za-z0-9_-]{4,80}$/.test(s) ? s : null;
}

/** The stored cap.js settings (empty when the table has no row, which is the default). */
export async function readCapSettings(env: Pick<Env, "DB">): Promise<CapSettings> {
  try {
    const row = await env.DB.prepare("SELECT * FROM captcha_settings WHERE id = 1").first<CapRow>();
    return row ? { endpoint: row.cap_endpoint, siteKey: row.cap_site_key, sealedSecret: row.cap_secret, updatedAt: row.updated_at, updatedBy: row.updated_by } : EMPTY_CAP;
  } catch (e) {
    if (!/no such table/i.test(String(e))) throw e;
    return EMPTY_CAP;
  }
}

/** A complete cap.js setup: where to send the browser, which site key, and the secret to verify with. */
export interface CapConfiguration {
  endpoint: string;
  siteKey: string;
  secret: string;
  /** "settings" when a site administrator saved it, "environment" when it came from the deployment. */
  source: "settings" | "environment";
}

/**
 * cap.js as this instance has it: the saved settings when they are complete, else the deployment's
 * variables, else null. A saved set that is incomplete falls back to the variables rather than
 * leaving a half-configured provider.
 */
export async function capConfiguration(env: Env): Promise<CapConfiguration | null> {
  const saved = await readCapSettings(env);
  const savedEndpoint = normalCapEndpoint(saved.endpoint);
  const savedKey = normalCapSiteKey(saved.siteKey);
  if (savedEndpoint && savedKey && saved.sealedSecret) {
    const secret = await decryptSecret(env, "captcha:cap", saved.sealedSecret).catch(() => null);
    if (secret) return { endpoint: savedEndpoint, siteKey: savedKey, secret, source: "settings" };
  }
  const endpoint = normalCapEndpoint(env.CAP_ENDPOINT);
  const siteKey = normalCapSiteKey(env.CAP_SITE_KEY);
  if (endpoint && siteKey && env.CAP_SECRET) return { endpoint, siteKey, secret: env.CAP_SECRET, source: "environment" };
  return null;
}

/** What a page has to render for the check in force. */
export interface Captcha {
  /** Which check runs on this request. */
  kind: CaptchaKind;
  /** The site key for the widget, when there is one. */
  siteKey?: string;
  /** cap.js: the widget's API base, `${endpoint}/${siteKey}/`. */
  capApiEndpoint?: string;
  /** The form field the browser fills in. */
  field: "cf-turnstile-response" | "cap-token";
  /** Why nothing can be shown although a check was wanted (a provider chosen but not set up). */
  missing: string | null;
}

const TURNSTILE_FIELD = "cf-turnstile-response" as const;
const CAP_FIELD = "cap-token" as const;

/**
 * The check in force, given the policy's choice and what this instance has set up. It never turns
 * a chosen check into none: an unconfigured provider is `missing`, and callers refuse.
 */
export function resolveCaptcha(env: Pick<Env, "TURNSTILE_SITE_KEY" | "TURNSTILE_SECRET" | "PUBLIC_URL">, choice: CaptchaProviderChoice, cap: CapConfiguration | null): Captcha {
  const turnstile = env.TURNSTILE_SITE_KEY && env.TURNSTILE_SECRET ? { siteKey: env.TURNSTILE_SITE_KEY } : null;
  const choose = (kind: CaptchaKind): Captcha => {
    if (kind === "turnstile") return turnstile ? { kind, siteKey: turnstile.siteKey, field: TURNSTILE_FIELD, missing: null } : { kind, field: TURNSTILE_FIELD, missing: "This instance is set to check sign-ups with Cloudflare Turnstile, but it has no TURNSTILE_SITE_KEY and TURNSTILE_SECRET." };
    if (kind === "cap") return cap ? { kind, siteKey: cap.siteKey, capApiEndpoint: `${cap.endpoint}/${cap.siteKey}/`, field: CAP_FIELD, missing: null } : { kind, field: CAP_FIELD, missing: "This instance is set to check sign-ups with cap.js, but it has no CAP_ENDPOINT, CAP_SITE_KEY and CAP_SECRET (or the same set in Settings → Registration)." };
    return { kind: "none", field: TURNSTILE_FIELD, missing: null };
  };
  if (choice === "turnstile") return choose("turnstile");
  if (choice === "cap") return choose("cap");
  if (choice === "none") return choose("none");
  // Automatic: whatever is set up, cap.js first.
  if (cap) return choose("cap");
  if (turnstile) return choose("turnstile");
  // Local development without keys keeps the old behaviour: no check, so sign-up can be tried.
  if (turnstileMode(env) === "skip") return choose("none");
  return choose("turnstile");
}

/** The readable reason a configured-but-unset provider stops a form, or null. */
export function captchaProblem(captcha: Captcha): string | null {
  return captcha.missing ? `${captcha.missing} Ask its administrators for an invitation.` : null;
}

/** Whether `response` proves a person did the work. Any failure, and an empty answer, is a no. */
export async function verifyCaptcha(captcha: Captcha, cap: CapConfiguration | null, response: string, ip: string | null): Promise<boolean> {
  if (captcha.kind === "none") return true;
  if (captcha.kind === "turnstile") return false; // verified by the caller, which has the secret
  if (!cap) return false;
  if (!response || response.length > 2048) return false;
  const url = `${cap.endpoint}/${cap.siteKey}/siteverify`;
  try {
    const r = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ secret: cap.secret, response }) });
    if (!r.ok) return false;
    return ((await r.json()) as { success?: boolean }).success === true;
  } catch (e) {
    console.error("cap.js siteverify failed", e);
    return false;
  }
}

/** Turnstile's own verification, for the turnstile kind (kept separate: it needs its own secret). */
export async function verifyTurnstileCaptcha(env: Pick<Env, "TURNSTILE_SECRET">, response: string, ip: string | null): Promise<boolean> {
  if (!env.TURNSTILE_SECRET) return false;
  return verifyTurnstile(env.TURNSTILE_SECRET, response, ip);
}
