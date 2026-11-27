/**
 * Who may create an account on this instance (Settings → Site administration → Registration).
 *
 * Until migration 0046 the only switch was the `SIGNUP` variable, and open sign-up could only
 * create a passkey from an emailed code. This module adds a policy a site administrator edits
 * without a deploy: the switch, the ways in (emailed code, passkey, password), the status of a new
 * account, and the bot check in front of the forms (Cloudflare Turnstile, cap.js, or none).
 *
 * `registrationPolicy(env)` is the one entry point. Pages, form handlers and passkey endpoints all
 * ask it, so there is one answer. It is not cached across requests: closing registration has to
 * take effect on the very next request, and the read is a primary-key lookup in the D1 the request
 * already uses.
 *
 * It is closed by default, and a production instance refuses to open it without an email transport
 * (lib/instance.ts `requireEmailForSignup`): an instance nobody can verify an address on can't let
 * people in. Demo mode relaxes that, so a bare install can be tried.
 *
 * `SIGNUP=open` is an operator override that only adds: it turns registration on whatever the page
 * says, and keeps the emailed-code way on. It never closes anything, so an instance that was open
 * before this migration stays open, with the same flow. The page says when it applies.
 */
import type { Env } from "../env.js";
import type { Account, Directory } from "../lib/directory.js";
import { readInstanceSettings } from "../lib/instance.js";
import { HttpError, now } from "../lib/util.js";
import { mailTransport } from "../mail/send.js";
import { CAPTCHA_PROVIDERS, captchaProblem, capConfiguration, resolveCaptcha, type Captcha, type CaptchaProviderChoice } from "./captcha.js";
import { signupOpen } from "./signup.js";

/** The ways in that can be switched on separately. Invitations are not one of them: they always work. */
export const SIGNUP_METHODS = ["email_code", "passkey", "password"] as const;
export type SignupMethod = (typeof SIGNUP_METHODS)[number];

export const METHOD_LABEL: Record<SignupMethod, string> = { email_code: "Emailed code", passkey: "Passkey", password: "Password" };

export const NEW_ACCOUNT_STATUSES = ["active", "pending"] as const;
export type NewAccountStatus = (typeof NEW_ACCOUNT_STATUSES)[number];

/** What is stored in registration_policy (one row). */
export interface RegistrationPolicy {
  enabled: boolean;
  methods: SignupMethod[];
  newAccountStatus: NewAccountStatus;
  /** The bot check in front of the forms (auth/captcha.ts). */
  provider: CaptchaProviderChoice;
  updatedAt: string | null;
  /** The site administrator's login who saved it, or null while it has never been saved. */
  updatedBy: string | null;
}

/** What the migration's row says, and what an empty table reads as: closed, invite-only. */
export const DEFAULT_POLICY: RegistrationPolicy = Object.freeze({
  enabled: false,
  methods: [] as SignupMethod[],
  newAccountStatus: "active" as NewAccountStatus,
  provider: "auto" as CaptchaProviderChoice,
  updatedAt: null,
  updatedBy: null,
});

type PolicyRow = {
  enabled: number | boolean | null;
  methods: string | null;
  new_account_status: string | null;
  provider: string | null;
  updated_at: string | null;
  updated_by: string | null;
};

const truthy = (v: unknown): boolean => v === 1 || v === true || v === "1";

/** A row (or none) as a policy. Every value is checked: a hand-edited row never grants more than it says. */
export function parsePolicy(row: PolicyRow | null | undefined): RegistrationPolicy {
  if (!row) return DEFAULT_POLICY;
  let methods: SignupMethod[] = [];
  try {
    const parsed: unknown = JSON.parse(row.methods ?? "[]");
    if (Array.isArray(parsed)) methods = SIGNUP_METHODS.filter((m) => parsed.includes(m));
  } catch {
    methods = [];
  }
  const status = (NEW_ACCOUNT_STATUSES as readonly string[]).includes(row.new_account_status ?? "") ? (row.new_account_status as NewAccountStatus) : "active";
  const provider = (CAPTCHA_PROVIDERS as readonly string[]).includes(row.provider ?? "") ? (row.provider as CaptchaProviderChoice) : "auto";
  return { enabled: truthy(row.enabled), methods, newAccountStatus: status, provider, updatedAt: row.updated_at ?? null, updatedBy: row.updated_by ?? null };
}

/**
 * The policy as stored. A missing row reads as the defaults. A missing table (a code deploy that
 * reached a node before its migration) reads as closed too: the safe answer, logged.
 */
export async function readRegistrationPolicy(env: Pick<Env, "DB">): Promise<RegistrationPolicy> {
  try {
    return parsePolicy(await env.DB.prepare("SELECT * FROM registration_policy WHERE id = 1").first<PolicyRow>());
  } catch (e) {
    if (!/no such table/i.test(String(e))) throw e;
    console.error("registration_policy is missing; treating registration as closed", e);
    return DEFAULT_POLICY;
  }
}

/** The policy applied to this instance, for one request. */
export interface Registration {
  /** What is stored; the admin page edits this. */
  policy: RegistrationPolicy;
  /** `SIGNUP=open` is set: registration is on and the emailed-code way is on, whatever the page says. */
  forcedByEnv: boolean;
  /** The switch is on (the page's, or SIGNUP=open), whatever else stands in the way: the pages answer. */
  on: boolean;
  /** Registration works now: on, and nothing missing. The sign-in page links to it while it is. */
  enabled: boolean;
  /** The ways switched on, with SIGNUP=open's addition. */
  configured: SignupMethod[];
  /** The ways in offered now: configured, minus those this instance can't run (no email transport). */
  methods: SignupMethod[];
  /** Whether this instance can send email at all (an EMAIL binding, or a usable SMTP_URL). */
  email: boolean;
  /** Whether opening registration waits for an email transport (production, unless the page says otherwise). */
  emailRequired: boolean;
  newAccountStatus: NewAccountStatus;
  /** The bot check in force, and what the pages must render for it. */
  captcha: Captcha;
  /** On, but nothing can be offered until this is fixed: the sign-in page doesn't link to the forms. */
  blockedBy: "captcha" | "email" | "methods" | null;
}

/** Whether this instance can send the mail a sign-up needs: an EMAIL binding, or a usable SMTP_URL. */
export function emailTransport(env: Pick<Env, "EMAIL" | "SMTP_URL" | "SMTP_PASSWORD">): boolean {
  const t = mailTransport(env);
  // A malformed SMTP_URL is as good as none: nothing would leave.
  return !!t && !("error" in t);
}

/** The policy this request runs with. Every page and every form handler asks this one function. */
export async function registrationPolicy(env: Env): Promise<Registration> {
  const policy = await readRegistrationPolicy(env);
  const instance = await readInstanceSettings(env);
  const forcedByEnv = signupOpen(env);
  const email = emailTransport(env);
  const cap = policy.provider === "cap" || policy.provider === "auto" ? await capConfiguration(env) : null;
  const captcha = resolveCaptcha(env, policy.provider, cap);
  // SIGNUP=open adds the emailed code and never removes anything the page switched on.
  const configured = SIGNUP_METHODS.filter((m) => policy.methods.includes(m) || (forcedByEnv && m === "email_code"));
  // The emailed code is the only way in that needs email by itself.
  const emailRequired = instance.requireEmailForSignup && instance.mode === "production";
  const open = policy.enabled || forcedByEnv;
  const methods = open ? configured.filter((m) => m !== "email_code" || email) : [];
  const blockedBy: Registration["blockedBy"] = !open ? null : emailRequired && !email ? "email" : captcha.missing ? "captcha" : methods.length ? null : "methods";
  return { policy, forcedByEnv, on: open, enabled: open && !blockedBy && methods.length > 0, configured, methods, email, emailRequired, newAccountStatus: policy.newAccountStatus, captcha, blockedBy };
}

/** The readable reason sign-up stops before anyone can type anything, or null. */
export function signupProblem(r: Registration): string | null {
  if (r.blockedBy === "email") return "Registration is on, but nobody can register: this instance has no email transport, so no address can be confirmed. Set SMTP_URL (or the EMAIL binding), or run the instance in demo mode.";
  if (r.blockedBy === "captcha") return captchaProblem(r.captcha);
  return null;
}

/** Why this way in is not available now, or null when it is. */
export function methodProblem(r: Registration, method: SignupMethod): string | null {
  if (!r.on) return "Registration is closed on this instance. Ask an administrator for an invitation.";
  if (r.blockedBy) return signupProblem(r);
  if (!r.configured.includes(method)) return `${METHOD_LABEL[method]} sign-up is turned off on this instance.`;
  if (!r.methods.includes(method)) return "This instance has no email transport, so it can't send a sign-up code.";
  return null;
}

/** For a form handler: the policy when this way in is offered, or the refusal (403) the browser gets. */
export async function requireMethod(env: Env, method: SignupMethod): Promise<Registration> {
  const r = await registrationPolicy(env);
  const problem = methodProblem(r, method);
  // A switch that is on but missing its keys or email is a 503 (the instance's setup, not the
  // visitor's mistake, and the page says what to fix); a way in that is off is a 403.
  if (problem) throw new HttpError(r.on && r.blockedBy ? 503 : 403, problem);
  return r;
}

/**
 * Why a policy can't be saved, or null when it can. The page never promises a way in that can't
 * run: an on switch needs a way in, a production instance needs email to verify an address, and a
 * chosen bot check needs its keys.
 */
export function registrationProblem(env: Pick<Env, "EMAIL" | "SMTP_URL" | "SMTP_PASSWORD" | "TURNSTILE_SITE_KEY" | "TURNSTILE_SECRET" | "PUBLIC_URL">, p: RegistrationPolicy, o: { emailRequired: boolean; captcha: Captcha }): string | null {
  if (p.enabled && !p.methods.length) return "Choose at least one way for people to register, or turn registration off.";
  if (p.enabled && o.emailRequired && !emailTransport(env)) return "A production instance needs an email transport before registration can be opened, so an address can be confirmed. Set SMTP_URL (or the EMAIL binding), untick “Require email before registration” on the Instance page, or switch the instance to demo mode.";
  if (p.enabled && o.captcha.missing) return `${o.captcha.missing} Set it up, or choose another bot check.`;
  if (!emailTransport(env) && p.methods.includes("email_code")) return "This instance has no email transport (no EMAIL binding and no SMTP_URL), so it can't email a sign-up code. Untick Emailed code.";
  return null;
}

/** The policy a submitted admin form asks for. Unknown values are dropped, not trusted. */
export function policyFromForm(f: { b(name: string): boolean; all(name: string): string[]; s(name: string): string }): RegistrationPolicy {
  const chosen = f.all("methods");
  const methods = SIGNUP_METHODS.filter((m) => chosen.includes(m));
  const status = (NEW_ACCOUNT_STATUSES as readonly string[]).find((s) => s === f.s("new_account_status")) ?? "active";
  const provider = (CAPTCHA_PROVIDERS as readonly string[]).find((p) => p === f.s("provider")) ?? "auto";
  return { enabled: f.b("enabled"), methods, newAccountStatus: status as NewAccountStatus, provider: provider as CaptchaProviderChoice, updatedAt: null, updatedBy: null };
}

/**
 * Store a policy and audit the change, with what it was and what it is. One upsert on the single
 * row, so two administrators saving at once leave one row, and the next request reads the result.
 */
export async function saveRegistrationPolicy(env: Env, dir: Pick<Directory, "audit">, next: RegistrationPolicy, by: Pick<Account, "id" | "login">): Promise<RegistrationPolicy> {
  // The checks run against the policy as it will be, including the bot check it now asks for.
  const instance = await readInstanceSettings(env);
  const cap = next.provider === "cap" || next.provider === "auto" ? await capConfiguration(env) : null;
  const problem = registrationProblem(env, next, { emailRequired: instance.requireEmailForSignup && instance.mode === "production", captcha: resolveCaptcha(env, next.provider, cap) });
  if (problem) throw new HttpError(422, problem);
  const before = await readRegistrationPolicy(env);
  const at = now();
  await env.DB.prepare(
    "INSERT INTO registration_policy (id, enabled, methods, new_account_status, provider, updated_at, updated_by) VALUES (1, ?, ?, ?, ?, ?, ?) " +
      "ON CONFLICT (id) DO UPDATE SET enabled = excluded.enabled, methods = excluded.methods, new_account_status = excluded.new_account_status, provider = excluded.provider, updated_at = excluded.updated_at, updated_by = excluded.updated_by",
  )
    .bind(next.enabled ? 1 : 0, JSON.stringify(next.methods), next.newAccountStatus, next.provider, at, by.login)
    .run();
  const shape = (p: RegistrationPolicy) => ({ enabled: p.enabled, methods: p.methods, newAccountStatus: p.newAccountStatus, provider: p.provider });
  await dir.audit({ actorId: by.id, actorLogin: by.login, action: "registration.policy.update", detail: { before: shape(before), after: shape(next) } });
  return { ...next, updatedAt: at, updatedBy: by.login };
}

/** One sentence for the admin page: who can register, and what a new account becomes. */
export function registrationSummary(r: Registration): string {
  const override = r.forcedByEnv ? " SIGNUP=open is set, so registration stays on whatever this page says." : "";
  if (r.blockedBy === "email") return `Registration is on, but nobody can register: a production instance needs an email transport to confirm an address. Invitations and /setup still work.${override}`;
  if (r.blockedBy === "captcha") return `${captchaProblem(r.captcha) ?? "The bot check is not set up."} Invitations and /setup still work.${override}`;
  if (!r.enabled) {
    if (r.policy.enabled) return `Registration is on, but no way in can run on this instance right now. Invitations and /setup still work.${override}`;
    return `Closed: nobody can create an account themselves. Invitations and /setup still work.${override}`;
  }
  const ways = r.methods.map((m) => METHOD_LABEL[m].toLowerCase()).join(", ");
  const status = r.newAccountStatus === "active" ? "active as soon as it exists" : "pending until a site administrator approves it, and can't use the site before then";
  const check = r.captcha.kind === "none" ? "No bot check" : r.captcha.kind === "cap" ? "cap.js" : "Turnstile";
  return `Open: ${ways}. A new account is ${status}. ${check}.${override}`;
}
