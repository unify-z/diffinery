/** @jsxImportSource hono/jsx */
/**
 * Settings → Site administration → Registration: who may create an account on this instance
 * (auth/registration.ts). A site administrator switches self-service registration on or off, picks
 * the ways in, and sets what a new account becomes. The page says when SIGNUP=open overrides it,
 * and shows what the saved policy means in one sentence.
 *
 * Kumo components only (KCheckbox, KSelect), never a native checkbox or select (AGENTS.md).
 */
import type { Child, FC } from "hono/jsx";
import { HttpError } from "../lib/util.js";
import type { Account } from "../lib/directory.js";
import type { AppContext } from "../auth/principal.js";
import { METHOD_LABEL, SIGNUP_METHODS, policyFromForm, registrationPolicy, registrationSummary, saveRegistrationPolicy, type Registration, type SignupMethod } from "../auth/registration.js";
import { csrfToken } from "./csrf.js";
import { KCheckbox, KSelect } from "./kumo.js";
import { Form, Time, post, act, type WebApp } from "./ui.js";
import type { SettingsTab } from "./account.js";

const METHOD_NOTE: Record<SignupMethod, string> = {
  email_code: "Someone enters their address, gets a 6-digit code by email, then picks a username and creates a passkey. Needs email (an EMAIL binding or SMTP_URL).",
  passkey: "Someone picks a username and creates a passkey on the sign-up page. No email is sent, so the address is not confirmed: it doesn't make a bootstrap administrator or accept invitations, and the page tells whether an address already has an account.",
  password: "Someone picks a username and a password. Unless “Require email verification” is on, no email is sent and the address is not confirmed, as with Passkey. With it on, a code is emailed first and the account is created when it is entered.",
};

const STATUS_OPTIONS = [
  { value: "active", label: "Active: can use the site at once" },
  { value: "pending", label: "Pending: waits for a site administrator to approve it" },
];

const TURNSTILE_OPTIONS = [
  { value: "inherit", label: "As the instance is set up (Turnstile keys, or none in local development)" },
  { value: "require", label: "Required: refuse sign-up unless TURNSTILE_SITE_KEY and TURNSTILE_SECRET are set" },
];

/** The page body. Shows the stored policy, what applies now, and why a way in may be off. */
export const RegistrationAdmin: FC<{ r: Registration; t: string }> = ({ r, t }) => {
  const p = r.policy;
  const emailOk = r.email;
  return (
    <>
      <h1>Registration</h1>
      <p class="muted">
        Who may create an account on this instance without an invitation. Invitations and first-run setup at <span class="mono">/setup</span> always work, whatever is set here. Every change is in the <a href="/settings/audit">audit log</a>.
      </p>

      <div class="flash notice" role="status">
        <b>Now:</b> {registrationSummary(r)}
      </div>

      {r.forcedByEnv ? (
        <div class="flash error" role="status" data-env-override="SIGNUP">
          <b>SIGNUP=open is set in the deployment</b>, which keeps registration on and the emailed-code way on whatever is saved here. It can only open registration, never close it. To close it, remove <span class="mono">SIGNUP</span> from the deployment's variables and restart.
        </div>
      ) : null}

      <Form action="/settings/admin/registration" t={t} class="box">
        <div class="head">
          <h2>Registration</h2>
          {r.enabled ? <span class="badge green">open</span> : <span class="badge">closed</span>}
        </div>
        <div class="body fbody">
          <div class="fchecks">
            <KCheckbox name="enabled" checked={p.enabled} label="Let people create accounts themselves" description="When off, the sign-in page says the instance is invite-only and /signup, /early-access sign-ups and password sign-ups all refuse. Turning it off takes effect on the next request." />
          </div>

          <div class="field">
            <label>Ways in</label>
            <div class="hint">Each one is on its own. A person can use any on that is ticked and can run here.</div>
            <div class="fchecks">
              {SIGNUP_METHODS.map((m) => {
                const unavailable = m === "email_code" && !emailOk;
                // Shows what is stored, so saving never drops it; SIGNUP=open's addition is only noted.
                const forced = r.forcedByEnv && m === "email_code";
                return (
                  <div class="field" style="margin-bottom:10px">
                    <KCheckbox name="methods" value={m} checked={p.methods.includes(m)} label={METHOD_LABEL[m]} description={METHOD_NOTE[m] + (unavailable ? " Not available on this instance: it has no email transport yet." : "") + (forced ? " On anyway while SIGNUP=open is set." : "")} />
                  </div>
                );
              })}
            </div>
            <div class="hint">Invitations are not listed: they always work, and are the only way in while none of these is on.</div>
          </div>

          <div class="fchecks">
            <KCheckbox name="require_email_verification" checked={p.requireEmailVerification} disabled={!emailOk} label="Require email verification for password sign-ups" description={emailOk ? "The password is stored, then a code is emailed; the account is created when the code is entered. Passkey and emailed-code sign-ups already confirm the address." : "Needs email (an EMAIL binding or SMTP_URL), so an address can be confirmed."} />
          </div>

          <div class="field">
            <label for="new_account_status">New account status</label>
            <KSelect id="new_account_status" name="new_account_status" label="New account status" block value={p.newAccountStatus} options={STATUS_OPTIONS} />
            <div class="hint">Pending accounts can sign in, but can't use the site until a site administrator approves them under People and invitations.</div>
          </div>

          <div class="field">
            <label for="turnstile">Bot check (Turnstile)</label>
            <KSelect id="turnstile" name="turnstile" label="Bot check" block value={p.turnstile} options={TURNSTILE_OPTIONS} />
            <div class="hint">
              {r.turnstile.mode === "missing" ? (
                <span class="badge red">Missing keys: sign-up refuses until TURNSTILE_SITE_KEY and TURNSTILE_SECRET are set.</span>
              ) : r.turnstile.mode === "verify" ? (
                <span class="badge green">Turnstile is on.</span>
              ) : (
                <span class="badge">Skipped (local development without keys).</span>
              )}
            </div>
          </div>

          <div class="factions">
            <button class="btn primary">Save registration</button>
          </div>
        </div>
      </Form>

      <div class="box">
        <div class="head">
          <h2>Last saved</h2>
        </div>
        <div class="body">
          {p.updatedAt ? (
            <p class="m0">
              Saved by <b>{p.updatedBy ?? "a site administrator"}</b> <Time at={p.updatedAt} />.
            </p>
          ) : (
            <p class="m0 muted">Never saved: registration is closed, as it has always been on this instance.</p>
          )}
        </div>
      </div>
    </>
  );
};

/** Routes for the Registration page. The page itself, and its save handler, go through the shared policy module. */
export function registerRegistrationAdmin(
  web: WebApp,
  { requireSiteAdmin, page }: { requireSiteAdmin: (c: AppContext) => Account; page: (c: AppContext, me: Account, tab: SettingsTab, title: string, body: Child, status?: number) => Response | Promise<Response> },
): void {
  web.get("/settings/admin/registration", async (c) => {
    const me = requireSiteAdmin(c);
    const r = await registrationPolicy(c.env);
    return page(c, me, "registration", "Registration", <RegistrationAdmin r={r} t={csrfToken(c)} />);
  });

  post(web, "/settings/admin/registration", async (c, f) => {
    const me = requireSiteAdmin(c);
    return act(
      c,
      "/settings/admin/registration",
      async () => {
        const next = policyFromForm(f);
        // The policy is saved as the page sent it; the checks that depend on this instance's email and Turnstile live in one place.
        if (next.enabled && !next.methods.length) throw new HttpError(422, "Choose at least one way for people to register, or turn registration off.");
        await saveRegistrationPolicy(c.env, c.get("dir"), next, me);
      },
      "Registration saved. It applies to the next request.",
    );
  });
}

