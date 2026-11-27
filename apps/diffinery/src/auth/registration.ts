/**
 * Who may create an account on this instance (Settings → Site administration → Registration).
 *
 * Until migration 0046 the only switch was the `SIGNUP` variable, and open sign-up could only
 * create a passkey from an emailed code. This module adds a policy a site administrator edits
 * without a deploy: the switch, the ways in (emailed code, passkey, password), whether a password
 * account must confirm its address first, what a new account's status is, and whether the forms
 * check for a person with Turnstile.
 *
 * `registrationPolicy(env)` is the one entry point. Pages, form handlers and passkey endpoints all
 * ask it, so there is one answer. It is not cached across requests: closing registration has to
 * take effect on the very next request, and the read is a primary-key lookup in the D1 the request
 * already uses. A request reads it once per handler.
 *
 * `SIGNUP=open` is an operator override that only adds: it turns registration on whatever the page
 * says, and keeps the emailed-code way on. It never closes anything, so an instance that was open
 * before this migration stays open, with the same flow. The page says when it applies.
 */
import type { Env } from "../env.js";
import type { Account, Directory } from "../lib/directory.js";
import { HttpError, now } from "../lib/util.js";
import { mailTransport } from "../mail/send.js";
import { signupOpen, turnstileMode } from "./signup.js";

/** The ways in that can be switched on separately. Invitations are not one of them: they always work. */
export const SIGNUP_METHODS = ["email_code", "passkey", "password"] as const;
export type SignupMethod = (typeof SIGNUP_METHODS)[number];

export const METHOD_LABEL: Record<SignupMethod, string> = { email_code: "Emailed code", passkey: "Passkey", password: "Password" };

export const NEW_ACCOUNT_STATUSES = ["active", "pending"] as const;
export type NewAccountStatus = (typeof NEW_ACCOUNT_STATUSES)[number];

/**
 * How the sign-up forms check for a person: the instance's own Turnstile setup (inherit), or
 * refuse to sign up unless the keys are set (require). There is deliberately no "off": a public
 * instance can't drop the check from the page.
 */
export const TURNSTILE_CHOICES = ["inherit", "require"] as const;
export type TurnstileChoice = (typeof TURNSTILE_CHOICES)[number];

/** What is stored in registration_policy (one row). */
export interface RegistrationPolicy {
  enabled: boolean;
  methods: SignupMethod[];
  requireEmailVerification: boolean;
  newAccountStatus: NewAccountStatus;
  turnstile: TurnstileChoice;
  updatedAt: string | null;
  /** The site administrator's login who saved it, or null while it has never been saved. */
  updatedBy: string | null;
}

/** What an empty table reads as: closed, invite-only, as before this migration. */
export const DEFAULT_POLICY: RegistrationPolicy = Object.freeze({
  enabled: false,
  methods: [] as SignupMethod[],
  requireEmailVerification: false,
  newAccountStatus: "active" as NewAccountStatus,
  turnstile: "inherit" as TurnstileChoice,
  updatedAt: null,
  updatedBy: null,
});

type PolicyRow = {
  enabled: number | boolean | null;
  methods: string | null;
  require_email_verification: number | boolean | null;
  new_account_status: string | null;
  turnstile: string | null;
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
  const turnstile = (TURNSTILE_CHOICES as readonly string[]).includes(row.turnstile ?? "") ? (row.turnstile as TurnstileChoice) : "inherit";
  return {
    enabled: truthy(row.enabled),
    methods,
    requireEmailVerification: truthy(row.require_email_verification),
    newAccountStatus: status,
    turnstile,
    updatedAt: row.updated_at ?? null,
    updatedBy: row.updated_by ?? null,
  };
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
  /** Registration is on now, with at least one way in that can run. The sign-up pages answer while it is. */
  enabled: boolean;
  /** On, but the forms refuse (503, with the reason on the page) until this is fixed: the sign-in page doesn't link to them. */
  blockedBy: "turnstile" | null;
  /** The ways switched on, with SIGNUP=open's addition. */
  configured: SignupMethod[];
  /** The ways in offered now: configured, minus those this instance can't run (no email transport). */
  methods: SignupMethod[];
  /** Whether this instance can send email at all (an EMAIL binding, or a usable SMTP_URL). */
  email: boolean;
  requireEmailVerification: boolean;
  newAccountStatus: NewAccountStatus;
  turnstile: TurnstileSetting;
}

/** Turnstile as this request applies it: the keys to render, and whether the server checks. */
export interface TurnstileSetting {
  /** "verify": check the token. "skip": local development without keys. "missing": refuse sign-up. */
  mode: "verify" | "skip" | "missing";
  siteKey?: string;
}

/** Whether this instance can send the mail a sign-up needs: an EMAIL binding, or a usable SMTP_URL. */
export function emailTransport(env: Pick<Env, "EMAIL" | "SMTP_URL" | "SMTP_PASSWORD">): boolean {
  const t = mailTransport(env);
  // A malformed SMTP_URL is as good as none: nothing would leave.
  return !!t && !("error" in t);
}

/** Turnstile as the policy chose it. */
export function turnstileSetting(env: Pick<Env, "TURNSTILE_SITE_KEY" | "TURNSTILE_SECRET" | "PUBLIC_URL">, choice: TurnstileChoice): TurnstileSetting {
  if (choice === "require" && !(env.TURNSTILE_SITE_KEY && env.TURNSTILE_SECRET)) return { mode: "missing" };
  const mode = turnstileMode(env);
  return { mode, siteKey: mode === "verify" ? env.TURNSTILE_SITE_KEY : undefined };
}

/** The policy this request runs with. Every page and every form handler asks this one function. */
export async function registrationPolicy(env: Env): Promise<Registration> {
  const policy = await readRegistrationPolicy(env);
  const forcedByEnv = signupOpen(env);
  const email = emailTransport(env);
  // SIGNUP=open adds the emailed code and never removes anything the page switched on.
  const configured = SIGNUP_METHODS.filter((m) => policy.methods.includes(m) || (forcedByEnv && m === "email_code"));
  // The password way needs the address confirmed first when the policy says so; without email
  // that means it can't run at all, rather than making unconfirmed accounts.
  const possible = (m: SignupMethod): boolean => (m === "email_code" ? email : m === "password" && policy.requireEmailVerification ? email : true);
  const open = policy.enabled || forcedByEnv;
  const turnstile = turnstileSetting(env, policy.turnstile);
  const methods = open ? configured.filter(possible) : [];
  return {
    policy,
    forcedByEnv,
    enabled: methods.length > 0,
    // Without Turnstile keys every form refuses (the check is never weakened), so the sign-in page must not link to it.
    blockedBy: methods.length > 0 && turnstile.mode === "missing" ? "turnstile" : null,
    configured,
    methods,
    email,
    requireEmailVerification: policy.requireEmailVerification,
    newAccountStatus: policy.newAccountStatus,
    turnstile,
  };
}

/** The readable reason sign-up stops for Turnstile, or null when it doesn't. */
export function turnstileProblem(r: Registration): string | null {
  if (r.turnstile.mode !== "missing") return null;
  return r.policy.turnstile === "require"
    ? "Registration on this instance requires Turnstile, but it has no TURNSTILE_SITE_KEY and TURNSTILE_SECRET. Ask its administrators for an invitation."
    : "Sign-up needs Turnstile configured: this instance has no TURNSTILE_SITE_KEY and TURNSTILE_SECRET. Ask its administrators for an invitation.";
}

/** Why this way in is not available now, or null when it is. */
export function methodProblem(r: Registration, method: SignupMethod): string | null {
  if (!r.enabled) return "Registration is closed on this instance. Ask an administrator for an invitation.";
  if (!r.configured.includes(method)) return `${METHOD_LABEL[method]} sign-up is turned off on this instance.`;
  if (!r.methods.includes(method)) {
    return method === "password" && r.requireEmailVerification
      ? "This instance has no email transport, so it can't confirm an address before creating an account."
      : "This instance has no email transport, so it can't send a sign-up code.";
  }
  return null;
}

/** For a form handler: the policy when this way in is offered, or the refusal (403) the browser gets. */
export async function requireMethod(env: Env, method: SignupMethod): Promise<Registration> {
  const r = await registrationPolicy(env);
  const problem = methodProblem(r, method);
  if (problem) throw new HttpError(403, problem);
  return r;
}

/**
 * Why a policy can't be saved, or null when it can. The page never promises a way in that can't
 * run: an on switch needs a way in, and the ways that need email need an email transport.
 */
export function registrationProblem(env: Pick<Env, "EMAIL" | "SMTP_URL" | "SMTP_PASSWORD">, p: RegistrationPolicy): string | null {
  const email = emailTransport(env);
  if (p.enabled && !p.methods.length) return "Choose at least one way for people to register, or turn registration off.";
  if (!email && p.methods.includes("email_code")) return "This instance has no email transport (no EMAIL binding and no SMTP_URL), so it can't email a sign-up code. Untick Emailed code.";
  if (!email && p.requireEmailVerification && p.methods.includes("password")) return "This instance has no email transport, so it can't confirm an email address. Untick Require email verification, or set up email first.";
  return null;
}

/** The policy a submitted admin form asks for. Unknown values are dropped, not trusted. */
export function policyFromForm(f: { b(name: string): boolean; all(name: string): string[]; s(name: string): string }): RegistrationPolicy {
  const chosen = f.all("methods");
  const methods = SIGNUP_METHODS.filter((m) => chosen.includes(m));
  const status = (NEW_ACCOUNT_STATUSES as readonly string[]).find((s) => s === f.s("new_account_status")) ?? "active";
  const turnstile = (TURNSTILE_CHOICES as readonly string[]).find((t) => t === f.s("turnstile")) ?? "inherit";
  return { enabled: f.b("enabled"), methods, requireEmailVerification: f.b("require_email_verification"), newAccountStatus: status as NewAccountStatus, turnstile: turnstile as TurnstileChoice, updatedAt: null, updatedBy: null };
}

/**
 * Store a policy and audit the change, with what it was and what it is. One upsert on the single
 * row, so two administrators saving at once leave one row, and the next request reads the result.
 */
export async function saveRegistrationPolicy(env: Pick<Env, "DB" | "EMAIL" | "SMTP_URL" | "SMTP_PASSWORD">, dir: Pick<Directory, "audit">, next: RegistrationPolicy, by: Pick<Account, "id" | "login">): Promise<RegistrationPolicy> {
  const problem = registrationProblem(env, next);
  if (problem) throw new HttpError(422, problem);
  const before = await readRegistrationPolicy(env);
  const at = now();
  await env.DB.prepare(
    "INSERT INTO registration_policy (id, enabled, methods, require_email_verification, new_account_status, turnstile, updated_at, updated_by) VALUES (1, ?, ?, ?, ?, ?, ?, ?) " +
      "ON CONFLICT (id) DO UPDATE SET enabled = excluded.enabled, methods = excluded.methods, require_email_verification = excluded.require_email_verification, new_account_status = excluded.new_account_status, turnstile = excluded.turnstile, updated_at = excluded.updated_at, updated_by = excluded.updated_by",
  )
    .bind(next.enabled ? 1 : 0, JSON.stringify(next.methods), next.requireEmailVerification ? 1 : 0, next.newAccountStatus, next.turnstile, at, by.login)
    .run();
  const shape = (p: RegistrationPolicy) => ({ enabled: p.enabled, methods: p.methods, requireEmailVerification: p.requireEmailVerification, newAccountStatus: p.newAccountStatus, turnstile: p.turnstile });
  await dir.audit({ actorId: by.id, actorLogin: by.login, action: "registration.policy.update", detail: { before: shape(before), after: shape(next) } });
  return { ...next, updatedAt: at, updatedBy: by.login };
}

/** One sentence for the admin page: who can register, and what a new account becomes. */
export function registrationSummary(r: Registration): string {
  const override = r.forcedByEnv ? " SIGNUP=open is set, so registration stays on whatever this page says." : "";
  if (r.blockedBy === "turnstile") return `Registration is on, but nobody can register: this instance has no TURNSTILE_SITE_KEY and TURNSTILE_SECRET, and sign-up refuses without the bot check. The sign-in page says invite-only until the keys are set. Invitations and /setup still work.${override}`;
  if (!r.enabled) {
    if (r.policy.enabled) return "Registration is on, but no way in can run on this instance right now (see the ways above). Invitations and /setup still work.";
    return "Closed: nobody can create an account themselves. Invitations and /setup still work.";
  }
  const ways = r.methods.map((m) => METHOD_LABEL[m].toLowerCase()).join(", ");
  const verify = r.methods.includes("password") && r.requireEmailVerification ? " (passwords need the address confirmed by a code)" : "";
  const status = r.newAccountStatus === "active" ? "active as soon as it exists" : "pending until a site administrator approves it, and can't use the site before then";
  return `Open: ${ways}${verify}. A new account is ${status}.${r.forcedByEnv ? " SIGNUP=open is set, so registration stays on whatever this page says." : ""}`;
}
