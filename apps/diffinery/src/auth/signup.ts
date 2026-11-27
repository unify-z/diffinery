import { loopback } from "./dev.js";
import type { Env } from "../env.js";
import type { Account } from "../lib/directory.js";
import type { SignupMethod } from "./registration.js";
import { hmacSha256, matchesAnyKey, signingSecrets } from "../lib/crypto.js";
import { HttpError, b64url, newId, now, randomToken, sha256 } from "../lib/util.js";

/**
 * Sign-up codes and tickets. Someone asks for a code at /signup, proves they read mail at the
 * address by entering it, and gets a short-lived ticket that lets them pick a username and finish
 * the account (a passkey, or the password typed before the code). Off, the instance stays
 * invite-only. Who may start this, and by which way in, is the registration policy
 * (auth/registration.ts); this file only stores the codes, their counters and the tickets.
 *
 * `SIGNUP=open` still forces sign-up open (see signupOpen); the policy decides the rest.
 * Codes and tickets are stored only as hashes.
 */

export const CODE_MINUTES = 10;
export const TICKET_MINUTES = 30;
/** Codes entered for one code, right or wrong; after this many it stops working. */
export const MAX_CODE_ATTEMPTS = 5;
/** Sign-up emails (a code, or the "you already have an account" note) per address and per IP address in 24 hours. */
export const CODES_PER_EMAIL_PER_DAY = 5;
export const CODES_PER_IP_PER_DAY = 20;

export const TURNSTILE_SCRIPT = "https://challenges.cloudflare.com/turnstile/v0/api.js";
export const TURNSTILE_ORIGIN = "https://challenges.cloudflare.com";
const SITEVERIFY = "https://challenges.cloudflare.com/turnstile/v0/siteverify";

export function signupOpen(env: Pick<Env, "SIGNUP">): boolean {
  return env.SIGNUP === "open";
}

/**
 * How sign-up, and a security report from someone not signed in (web/security-reports.tsx), check
 * for a person: "verify" with Turnstile, "skip" in local development
 * (PUBLIC_URL on this machine) without it, and "missing" when a deployed instance has no
 * Turnstile keys, which refuses sign-up rather than leave it open to scripts.
 */
export function turnstileMode(env: Pick<Env, "TURNSTILE_SITE_KEY" | "TURNSTILE_SECRET" | "PUBLIC_URL">): "verify" | "skip" | "missing" {
  if (env.TURNSTILE_SITE_KEY && env.TURNSTILE_SECRET) return "verify";
  return loopback(env.PUBLIC_URL) ? "skip" : "missing";
}

/** Ask Cloudflare whether the widget's token is good. Any failure counts as no. */
export async function verifyTurnstile(secret: string, token: string, ip: string | null): Promise<boolean> {
  if (!token || token.length > 2048) return false;
  const body = new URLSearchParams({ secret, response: token });
  if (ip) body.set("remoteip", ip);
  try {
    const r = await fetch(SITEVERIFY, { method: "POST", body });
    if (!r.ok) return false;
    return ((await r.json()) as { success?: boolean }).success === true;
  } catch (e) {
    console.error("turnstile siteverify failed", e);
    return false;
  }
}

/** An address worth sending a code to, lower-cased; null when it isn't one. */
export function normalEmail(v: string): string | null {
  const e = v.trim().toLowerCase();
  return e.length <= 254 && /^[^\s@<>()",;]+@[^\s@<>()",;]+\.[^\s@<>()",;]+$/.test(e) ? e : null;
}

/** Six random digits, each code equally likely. */
export function newCode(): string {
  const buf = new Uint32Array(1);
  // 4,294,000,000 is the largest multiple of a million below 2^32: drawing below it avoids modulo bias.
  for (;;) {
    crypto.getRandomValues(buf);
    if (buf[0]! < 4_294_000_000) return String(buf[0]! % 1_000_000).padStart(6, "0");
  }
}

/**
 * The stored form of a code: an HMAC keyed from MASTER_KEY over the code's row id and the
 * code, so a copy of the database alone can't try the million codes.
 */
export async function codeHash(env: Pick<Env, "MASTER_KEY" | "MASTER_KEY_PREV" | "PUBLIC_URL">, id: string, code: string): Promise<string> {
  return codeHashWith(codeSecrets(env)[0]!, id, code);
}

/** Whether `code` is the one stored as `hash`, keyed with MASTER_KEY or, while it is being rotated, MASTER_KEY_PREV. */
export async function codeMatches(env: Pick<Env, "MASTER_KEY" | "MASTER_KEY_PREV" | "PUBLIC_URL">, id: string, code: string, hash: string): Promise<boolean> {
  return matchesAnyKey(codeSecrets(env), hash, (s) => codeHashWith(s, id, code));
}

function codeSecrets(env: Pick<Env, "MASTER_KEY" | "MASTER_KEY_PREV" | "PUBLIC_URL">): string[] {
  // Local development has no MASTER_KEY unless one is passed; production always does.
  return signingSecrets(env, loopback(env.PUBLIC_URL) ? "diffinery-dev-signup" : null, "MASTER_KEY is not set, so sign-up codes can't be stored");
}

const codeHashWith = async (secret: string, id: string, code: string): Promise<string> => b64url(await hmacSha256(`diffinery-signup-code-v1:${secret}`, `${id}:${code}`));

const minutes = (n: number): string => new Date(Date.now() + n * 60_000).toISOString();

/** The registration typed before a code was sent, when the address had to be confirmed first. */
export type PendingSignup = { login: string; name: string | null; passwordHash: string; method: SignupMethod };

export type CodeCheck = { ok: true; pending: PendingSignup | null } | { ok: false; left: number };

/** Sign-up codes and tickets in D1. */
export class Signups {
  constructor(private env: Env) {}

  private get db() {
    return this.env.DB;
  }

  /**
   * The person account using this address, whatever its case. `proven`: only one whose address was
   * proven; a flow that proves the address itself (an emailed code) takes it over from an unproven one.
   */
  async accountFor(email: string, o: { proven?: boolean } = {}): Promise<Account | null> {
    const a = await this.db.prepare("SELECT * FROM accounts WHERE kind = 'user' AND lower(email) = ? LIMIT 1").bind(email.toLowerCase()).first<Account>();
    return a && o.proven && a.email_unverified ? null : a;
  }

  /**
   * A new code for `email`, requested from `ip`, after the daily limits; older codes for the
   * address stop working. An address that already has an account gets a code too, which is
   * never sent: wrong guesses then answer exactly as they would for a new address.
   *
   * `pending` holds the registration typed before the code was sent, for a method that needs the
   * address confirmed first: the password is stored hashed, and the account is created when the
   * code is entered. The emailed-code flow stores nothing and asks for a username afterwards.
   */
  async issue(email: string, ip: string, pending?: PendingSignup): Promise<{ code: string; expiresAt: string }> {
    const since = new Date(Date.now() - 86400_000).toISOString();
    const sent = await this.db
      .prepare("SELECT (SELECT count(*) FROM signup_codes WHERE email = ? AND created_at > ?) AS email, (SELECT count(*) FROM signup_codes WHERE ip = ? AND created_at > ?) AS ip")
      .bind(email, since, ip, since)
      .first<{ email: number; ip: number }>();
    if ((sent?.email ?? 0) >= CODES_PER_EMAIL_PER_DAY) throw new HttpError(429, `We have sent several codes to ${email} today. Check that inbox (and its spam folder), or try again tomorrow.`);
    if ((sent?.ip ?? 0) >= CODES_PER_IP_PER_DAY) throw new HttpError(429, "Too many sign-ups from your network today. Try again tomorrow.");
    const id = newId();
    const code = newCode();
    const at = now();
    const expiresAt = minutes(CODE_MINUTES);
    await this.db.batch([
      this.db.prepare("UPDATE signup_codes SET expires_at = ?, password_hash = NULL, login = NULL, name = NULL WHERE email = ? AND used_at IS NULL AND expires_at > ?").bind(at, email, at),
      this.db
        .prepare("INSERT INTO signup_codes (id, email, ip, code_hash, created_at, expires_at, login, name, password_hash, method) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
        .bind(id, email, ip, await codeHash(this.env, id, code), at, expiresAt, pending?.login ?? null, pending?.name ?? null, pending?.passwordHash ?? null, pending?.method ?? null),
      // Rows older than a day no longer count towards any limit.
      this.db.prepare("DELETE FROM signup_codes WHERE created_at < ?").bind(since),
    ]);
    return { code, expiresAt };
  }

  /**
   * Check a code against the address's live one. Every try counts, so at most
   * MAX_CODE_ATTEMPTS codes are ever compared; a right one works once.
   */
  async check(email: string, code: string): Promise<CodeCheck> {
    if (!/^\d{6}$/.test(code)) throw new HttpError(422, "Enter the 6-digit code from the email.");
    const t = now();
    const row = await this.db
      .prepare(
        "UPDATE signup_codes SET attempts = attempts + 1 WHERE id = (SELECT id FROM signup_codes WHERE email = ? AND used_at IS NULL AND expires_at > ? ORDER BY created_at DESC LIMIT 1) AND attempts < ? RETURNING id, code_hash, attempts, login, name, password_hash, method",
      )
      .bind(email, t, MAX_CODE_ATTEMPTS)
      .first<{ id: string; code_hash: string; attempts: number; login: string | null; name: string | null; password_hash: string | null; method: string | null }>();
    if (!row) return { ok: false, left: 0 };
    if (await codeMatches(this.env, row.id, code, row.code_hash)) {
      // A used code keeps no password hash or names: they move to the account or nowhere.
      const r = await this.db.prepare("UPDATE signup_codes SET used_at = ?, password_hash = NULL, login = NULL, name = NULL WHERE id = ? AND used_at IS NULL").bind(t, row.id).run();
      if ((r.meta.changes ?? 0) > 0) {
        // The registration typed before the code, when there was one: only a password sign-up stores it.
        const pending: PendingSignup | null = row.login && row.password_hash && row.method === "password" ? { login: row.login, name: row.name, passwordHash: row.password_hash, method: "password" } : null;
        return { ok: true, pending };
      }
    }
    return { ok: false, left: Math.max(0, MAX_CODE_ATTEMPTS - row.attempts) };
  }

  /** A single-use ticket for a verified (or, for the passkey method, self-declared) address; returns the token for the passkey form. */
  async createTicket(email: string, via: SignupMethod = "email_code"): Promise<string> {
    const token = randomToken(32);
    await this.db.batch([
      this.db.prepare("DELETE FROM signup_tickets WHERE expires_at < ?").bind(now()),
      this.db.prepare("INSERT INTO signup_tickets (id, token_hash, email, created_at, expires_at, via) VALUES (?, ?, ?, ?, ?, ?)").bind(newId(), await sha256(token), email, now(), minutes(TICKET_MINUTES), via),
    ]);
    return token;
  }

  /** An unused, unexpired ticket by its token. */
  async ticket(token: string): Promise<{ hash: string; email: string; via: SignupMethod } | null> {
    if (!/^[A-Za-z0-9_-]{20,64}$/.test(token)) return null;
    const hash = await sha256(token);
    const row = await this.db.prepare("SELECT email, via FROM signup_tickets WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?").bind(hash, now()).first<{ email: string; via: string | null }>();
    return row ? { hash, email: row.email, via: row.via === "passkey" ? "passkey" : "email_code" } : null;
  }

  /** Mark a ticket used; false when it was used first or expired. */
  async useTicket(hash: string): Promise<boolean> {
    const r = await this.db.prepare("UPDATE signup_tickets SET used_at = ? WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?").bind(now(), hash, now()).run();
    return (r.meta.changes ?? 0) > 0;
  }
}
