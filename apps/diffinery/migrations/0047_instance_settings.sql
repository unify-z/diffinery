-- Two instance-wide settings pages, and the bot-check provider for registration.
--
-- A fresh instance is demo mode and closed to sign-up. "Production mode" is the profile of any
-- real Git host: no project marketing in the footer, header or docs, no GitHub star button, and
-- none of the project's own product pages (they are still served by diffinery.com). Demo mode is
-- what this repository is: a place to try the thing.
CREATE TABLE IF NOT EXISTS instance_settings (
  id INTEGER PRIMARY KEY CHECK (id = 1),   -- one row, ever
  mode TEXT NOT NULL DEFAULT 'demo' CHECK (mode IN ('demo', 'production')),
  -- Registration needs an email transport to be switched on (the admin page refuses without one);
  -- demo mode relaxes that, so a bare instance can be tried out.
  require_email_for_signup INTEGER NOT NULL DEFAULT 1 CHECK (require_email_for_signup IN (0, 1)),
  updated_at TEXT,
  updated_by TEXT
);

-- Demo mode until an administrator says otherwise: upgraded instances keep the marketing pages
-- and the demo affordances they had, and nobody's sign-up behaviour changes.
INSERT INTO instance_settings (id, mode) VALUES (1, 'demo') ON CONFLICT (id) DO NOTHING;

-- Which bot check sign-up and the other anonymous forms use:
--   turnstile (Cloudflare's, the keys in the Worker's variables),
--   cap       (cap.js, a self-hosted proof-of-work CAPTCHA),
--   none      (no check at all: rate limits and the daily email limits still apply),
--   auto      (cap.js when it is configured, else Turnstile when it is, else nothing).
ALTER TABLE registration_policy ADD COLUMN provider TEXT NOT NULL DEFAULT 'auto' CHECK (provider IN ('auto', 'turnstile', 'cap', 'none'));

-- Proving an address is what the emailed-code way (and an invitation, and email recovery) is for.
-- The password way doesn't: it creates an account whose address nobody proved, which already grants
-- nothing (accounts.email_unverified, migration 0046). So the "a code first, then the password"
-- variant goes away, with the columns it needed.
ALTER TABLE registration_policy DROP COLUMN require_email_verification;
ALTER TABLE signup_codes DROP COLUMN login;
ALTER TABLE signup_codes DROP COLUMN name;
ALTER TABLE signup_codes DROP COLUMN password_hash;

-- cap.js needs a server to issue and verify challenges. The instance may be given one in the
-- Worker's variables (CAP_ENDPOINT, CAP_SITE_KEY, CAP_SECRET); a site administrator can also set
-- one here, which wins, so cap.js can be turned on without a deploy. The secret is sealed with
-- MASTER_KEY (lib/crypto.ts): this table holds no plaintext secret.
CREATE TABLE IF NOT EXISTS captcha_settings (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  cap_endpoint TEXT,
  cap_site_key TEXT,
  cap_secret TEXT,                          -- sealed envelope, never the secret itself
  updated_at TEXT,
  updated_by TEXT
);

INSERT INTO captcha_settings (id) VALUES (1) ON CONFLICT (id) DO NOTHING;
