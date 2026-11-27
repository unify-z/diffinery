/**
 * Passwords.
 *
 * Diffinery signs people in with passkeys (src/web/auth.tsx). A password is the second way in, for
 * an instance that has no email (Cloudflare Email Sending or SMTP) and no Cloudflare Access: there,
 * an invite link and an administrator's sign-in link are the only other ways to create the first
 * credential, and both need someone who is already in. `/setup` (src/web/setup.tsx) uses this.
 *
 * This is a deliberate departure from "passkeys first, no passwords" (docs/PREFERENCES.md). Keep a
 * password an *addition*: an account with a passkey keeps it, and `/login` offers both.
 *
 * The KDF is PBKDF2-HMAC-SHA256, which the runtime provides in WebCrypto with no dependency. The
 * stored value is self-describing (`pbkdf2-sha256$<iterations>$<salt>$<hash>`, both base64url), so a
 * later iteration increase verifies old hashes and re-hashes them on the next successful sign-in.
 */
import { b64url, fromB64url, randomToken } from "../lib/util.js";

const SCHEME = "pbkdf2-sha256";
/** OWASP's 2023 floor for PBKDF2-HMAC-SHA256. WebCrypto does this in well under a tenth of a second. */
const ITERATIONS = 210_000;
const SALT_BYTES = 16;
const HASH_BITS = 256;

export const MIN_PASSWORD_LENGTH = 10;
export const MAX_PASSWORD_LENGTH = 200;

/** Why a password cannot be used, or null when it can. */
export function passwordProblem(password: string): string | null {
  if (password.length < MIN_PASSWORD_LENGTH) return `Use at least ${MIN_PASSWORD_LENGTH} characters.`;
  if (password.length > MAX_PASSWORD_LENGTH) return `Use at most ${MAX_PASSWORD_LENGTH} characters.`;
  // Length is what matters (NIST SP 800-63B); these only reject the obvious.
  if (/^[\x20-\x7e]*$/.test(password) && new Set(password).size < 5) return "Use more than a handful of different characters.";
  return null;
}

async function derive(password: string, salt: Uint8Array, iterations: number): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations }, key, HASH_BITS);
  return new Uint8Array(bits);
}

/** The value stored in accounts.password_hash. */
export async function hashPassword(password: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
  const hash = await derive(password, salt, ITERATIONS);
  return `${SCHEME}$${ITERATIONS}$${b64url(salt)}$${b64url(hash)}`;
}

/** Whether `password` matches `stored`. A malformed or unknown hash is never a match. */
export async function verifyPassword(password: string, stored: string | null | undefined): Promise<boolean> {
  if (!stored) return false;
  const [scheme, iterations, salt, hash] = stored.split("$");
  if (scheme !== SCHEME || !iterations || !salt || !hash) return false;
  const rounds = Number(iterations);
  if (!Number.isInteger(rounds) || rounds < 1000 || rounds > 10_000_000) return false;
  const expected = fromB64url(hash);
  const actual = await derive(password, fromB64url(salt), rounds);
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}

/** Whether `stored` should be re-hashed after a successful sign-in (the iteration count went up). */
export function needsRehash(stored: string): boolean {
  const rounds = Number(stored.split("$")[1]);
  return !Number.isFinite(rounds) || rounds < ITERATIONS;
}

function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

/**
 * A password nobody can use, derived from a random secret, so a sign-in attempt for an account that
 * has no password costs the same as one for an account that does. Without it, "no such user" answers
 * in microseconds and "wrong password" in milliseconds, which tells an attacker who exists.
 */
const DUMMY = hashPassword(randomToken(32));

export function dummyHash(): Promise<string> {
  return DUMMY;
}
