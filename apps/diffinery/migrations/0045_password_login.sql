-- Password sign-in, an addition to passkeys (src/auth/password.ts, docs/accounts/passwords.md).
-- A null hash means the account signs in with a passkey only, as before. The hash is a versioned
-- PBKDF2 string, so the iteration count can be raised later without invalidating existing passwords.
ALTER TABLE accounts ADD COLUMN password_hash TEXT;

-- When the password last changed: a password change signs out the account's other browsers.
ALTER TABLE accounts ADD COLUMN password_updated_at TEXT;
