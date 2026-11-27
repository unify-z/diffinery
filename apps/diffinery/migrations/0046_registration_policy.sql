-- Self-service registration, set from Settings → Site administration → Registration
-- (src/auth/registration.ts). Until now only the SIGNUP variable opened sign-up, and it could
-- only create a passkey. The policy is one row with one column per setting: a site administrator
-- reads and edits it as a form, and a key/value blob would make neither a CHECK constraint nor a
-- migration of one setting possible.
--
-- The row is not the only source of truth: SIGNUP=open still forces sign-up open (it can open,
-- never close), so an instance that was open before this migration stays open with the same
-- emailed-code flow. An empty table reads as the defaults below (closed, invite-only).
CREATE TABLE IF NOT EXISTS registration_policy (
  id INTEGER PRIMARY KEY CHECK (id = 1),                -- one row, ever
  enabled INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
  methods TEXT NOT NULL DEFAULT '[]',                   -- JSON array: password, passkey, email_code
  require_email_verification INTEGER NOT NULL DEFAULT 0 CHECK (require_email_verification IN (0, 1)),
  new_account_status TEXT NOT NULL DEFAULT 'active' CHECK (new_account_status IN ('active', 'pending')),
  turnstile TEXT NOT NULL DEFAULT 'inherit' CHECK (turnstile IN ('inherit', 'require')),
  updated_at TEXT,
  updated_by TEXT                                       -- the site administrator's login
);

INSERT INTO registration_policy (id) VALUES (1) ON CONFLICT (id) DO NOTHING;

-- A sign-up code can carry the registration typed before the code was sent, for the password
-- method with "require email verification" on: the account is created when the code is entered,
-- with the password already hashed here. NULL for the emailed-code flow, which asks for the
-- username and passkey after the code instead.
ALTER TABLE signup_codes ADD COLUMN login TEXT;
ALTER TABLE signup_codes ADD COLUMN name TEXT;
ALTER TABLE signup_codes ADD COLUMN password_hash TEXT;
ALTER TABLE signup_codes ADD COLUMN method TEXT;

-- 1 for an account whose address nobody proved: made through the passkey way, or the password way
-- without email verification. Such an account never becomes a bootstrap administrator, never gets
-- invitations sent to its address, and gives the address up to whoever proves it later (an invite's
-- emailed proof, an emailed sign-up code, Cloudflare Access). 0 for every other account, so every
-- account that exists before this migration keeps what it has.
ALTER TABLE accounts ADD COLUMN email_unverified INTEGER NOT NULL DEFAULT 0;

-- How a sign-up ticket was started: 'email_code' (a code arrived by email) or 'passkey' (the
-- passkey method, which can create an account without a code). The audit entry says which.
ALTER TABLE signup_tickets ADD COLUMN via TEXT;
