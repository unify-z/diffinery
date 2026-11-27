-- Two settings pages that were deployment-only until now: the bot check's Cloudflare Turnstile
-- keys, and the SMTP server.
--
-- Cloudflare Turnstile's keys were Worker variables only (TURNSTILE_SITE_KEY and the
-- TURNSTILE_SECRET secret). They sit beside cap.js's now, in captcha_settings, so a site
-- administrator changes either provider on Settings → Site administration → Bot check without a
-- deploy. The secret is sealed with MASTER_KEY (lib/crypto.ts): this table holds no plaintext
-- secret. An empty column falls back to the deployment's variables.
ALTER TABLE captcha_settings ADD COLUMN turnstile_site_key TEXT;
ALTER TABLE captcha_settings ADD COLUMN turnstile_secret TEXT;   -- sealed envelope, never the secret itself

-- SMTP was Worker variables only (SMTP_URL and the SMTP_PASSWORD secret). A site administrator can
-- set both on Settings → Site administration → Email, which wins over the variables, so an instance
-- whose mail provider changes is fixed from the page instead of a deploy. The password is sealed
-- with MASTER_KEY; the URL never carries a password (smtp.ts refuses one).
CREATE TABLE IF NOT EXISTS smtp_settings (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  smtp_url TEXT,                            -- smtps://user@host:465, or smtp://user@host:587
  smtp_password TEXT,                       -- sealed envelope, never the password itself
  updated_at TEXT,
  updated_by TEXT
);

INSERT INTO smtp_settings (id) VALUES (1) ON CONFLICT (id) DO NOTHING;
