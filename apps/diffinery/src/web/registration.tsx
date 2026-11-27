/** @jsxImportSource hono/jsx */
/**
 * Settings → Site administration: Registration, and Instance.
 *
 * **Registration** (auth/registration.ts) decides who may create an account: the switch, the ways
 * in and the status of a new account. The bot check in front of the forms (Cloudflare Turnstile,
 * cap.js or none) and the keys for both providers are on Settings → Bot check (web/bot-check.tsx),
 * so both providers are edited in one place; this page says which one is in force.
 *
 * **Instance** (lib/instance.ts) decides what this instance advertises: demo mode says it is
 * Diffinery and links to the project; production mode hides every trace of the project's marketing
 * and its product pages.
 *
 * Kumo components only (KCheckbox, KSelect), never a native checkbox or select (AGENTS.md).
 */
import type { Child, FC } from "hono/jsx";
import type { Account } from "../lib/directory.js";
import type { AppContext } from "../auth/principal.js";
import { METHOD_LABEL, SIGNUP_METHODS, policyFromForm, readRegistrationPolicy, registrationPolicy, registrationSummary, saveRegistrationPolicy, type Registration, type SignupMethod } from "../auth/registration.js";
import { INSTANCE_MODES, MODE_LABEL, MODE_NOTE, instanceSummary, readInstanceSettings, saveInstanceSettings } from "../lib/instance.js";
import { csrfToken } from "./csrf.js";
import { KCheckbox, KSelect } from "./kumo.js";
import { Form, Time, post, act, type WebApp } from "./ui.js";
import type { SettingsTab } from "./account.js";

const METHOD_NOTE: Record<SignupMethod, string> = {
  email_code: "Someone enters their address, gets a 6-digit code by email, then picks a username and creates a passkey. Needs email (SMTP on Settings → Email, or the EMAIL binding).",
  passkey: "Someone picks a username and creates a passkey on the sign-up page. No email is sent, so the address is not confirmed: it doesn't make a bootstrap administrator or accept invitations, and the page tells whether an address already has an account.",
  password: "Someone picks a username and a password. No email is sent, so the address is not confirmed, as with Passkey. Add a passkey later from Settings → Passkeys and sessions.",
};

const STATUS_OPTIONS = [
  { value: "active", label: "Active: can use the site at once" },
  { value: "pending", label: "Pending: waits for a site administrator to approve it" },
];

const MODE_OPTIONS = INSTANCE_MODES.map((m) => ({ value: m, label: MODE_LABEL[m] }));

/** The page body: the policy as stored, what applies now, and why a way in may be off. */
export const RegistrationAdmin: FC<{ r: Registration; t: string }> = ({ r, t }) => {
  const p = r.policy;
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
            <KCheckbox name="enabled" checked={p.enabled} label="Let people create accounts themselves" description="When off, the sign-in page says the instance is invite-only and every sign-up page and form refuses. Turning it off takes effect on the next request." />
          </div>

          <div class="field">
            <label>Ways in</label>
            <div class="hint">Each one is on its own. A person can use any that is ticked and can run here.</div>
            <div class="fchecks">
              {SIGNUP_METHODS.map((m) => {
                const unavailable = m === "email_code" && !r.email;
                return (
                  <div class="field" style="margin-bottom:10px">
                    <KCheckbox name="methods" value={m} checked={p.methods.includes(m)} label={METHOD_LABEL[m]} description={METHOD_NOTE[m] + (unavailable ? " Not available on this instance: it has no email transport yet." : "")} />
                  </div>
                );
              })}
            </div>
            <div class="hint">Invitations are not listed: they always work, and are the only way in while none of these is on.</div>
          </div>

          <div class="field">
            <label for="new_account_status">New account status</label>
            <KSelect id="new_account_status" name="new_account_status" label="New account status" block value={p.newAccountStatus} options={STATUS_OPTIONS} />
            <div class="hint">Pending accounts can sign in, but can't use the site until a site administrator approves them under People and invitations.</div>
          </div>

          <div class="field">
            <label>Bot check</label>
            <div class="hint">
              {r.captcha.kind === "none" ? (
                <span class="badge">No check on the sign-up forms: rate limits and the daily email limits still apply.</span>
              ) : r.captcha.kind === "cap" ? (
                <span class="badge green">cap.js checks the sign-up forms.</span>
              ) : (
                <span class="badge green">Cloudflare Turnstile checks the sign-up forms.</span>
              )}{" "}
              <a href="/settings/admin/bot-check">Set up the bot check</a>: which provider runs, and the keys for Turnstile and cap.js.
              {r.captcha.missing ? (
                <>
                  {" "}
                  <span class="badge red">Not set up: {r.captcha.missing}</span>
                </>
              ) : null}
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
          {r.policy.updatedAt ? (
            <p class="m0">
              Saved by <b>{r.policy.updatedBy ?? "a site administrator"}</b> <Time at={r.policy.updatedAt} />.
            </p>
          ) : (
            <p class="m0 muted">Never saved: registration is closed, as it has always been on this instance.</p>
          )}
        </div>
      </div>
    </>
  );
};

/** Settings → Site administration → Instance: what this instance advertises. */
export const InstanceAdmin: FC<{ mode: "demo" | "production"; requireEmailForSignup: boolean; updatedAt: string | null; updatedBy: string | null; t: string; email: boolean }> = ({ mode, requireEmailForSignup, updatedAt, updatedBy, t, email }) => (
  <>
    <h1>Instance</h1>
    <p class="muted">
      What this instance says about itself. It changes the pages, not the data: repositories, issues, pull requests, tokens and the API are the same either way. Every change is in the <a href="/settings/audit">audit log</a>.
    </p>

    <div class="flash notice" role="status">
      <b>Now:</b> {instanceSummary({ mode: mode === "production" ? "production" : "demo", requireEmailForSignup, updatedAt, updatedBy })}
    </div>

    <Form action="/settings/admin/instance" t={t} class="box">
      <div class="head">
        <h2>Mode</h2>
        {mode === "production" ? <span class="badge green">production</span> : <span class="badge blue">demo</span>}
      </div>
      <div class="body fbody">
        <div class="field">
          <label for="mode">This instance is</label>
          <KSelect id="mode" name="mode" label="Mode" block value={mode} options={MODE_OPTIONS} />
          <div class="hint">{MODE_NOTE[mode === "production" ? "production" : "demo"]}</div>
        </div>
        <div class="fchecks">
          <KCheckbox
            name="require_email_for_signup"
            checked={requireEmailForSignup}
            label="Require an email transport before registration can be opened"
            description={
              email
                ? "On: Settings → Registration refuses to open sign-up until this instance can email a sign-up code, so an address can be confirmed. Your instance has email set up, so this changes nothing today."
                : "On: Settings → Registration refuses to open sign-up until this instance can email a sign-up code (an SMTP server on Settings → Email, or the EMAIL binding). Off lets people register without any email, which only suits a demo."
            }
          />
        </div>
        <div class="factions">
          <button class="btn primary">Save instance</button>
        </div>
      </div>
    </Form>

    <div class="box">
      <div class="head">
        <h2>What the mode changes</h2>
      </div>
      <div class="body">
        <dl class="kv">
          <dt>Footer and header</dt>
          <dd>Demo keeps the project footer, the Product and Compare links and the GitHub star button; production drops all three and keeps Docs, Security, Status and Contact.</dd>
          <dt>Product pages</dt>
          <dd>/features, /compare/*, /agents, /performance, /blog, /about and the other pages about Diffinery the product are served in demo mode and answer 404 in production. The docs stay in both.</dd>
          <dt>API index</dt>
          <dd>/api/v3 answers in both; <span class="mono">/api/v3/diffinery</span> and <span class="mono">/mcp</span> describe this instance and stay.</dd>
          <dt>Search engines and llms.txt</dt>
          <dd>The sitemap, robots.txt, llms.txt and the IndexNow submissions list this instance's pages and repositories, never the project's marketing pages in production.</dd>
          <dt>First run</dt>
          <dd>/setup never asks for an email transport, in either mode.</dd>
        </dl>
      </div>
    </div>

    <div class="box">
      <div class="body">
        {updatedAt ? (
          <p class="m0 muted">
            Last saved by <b>{updatedBy ?? "a site administrator"}</b> <Time at={updatedAt} />.
          </p>
        ) : (
          <p class="m0 muted">Never saved: demo mode, as every instance starts.</p>
        )}
      </div>
    </div>
  </>
);

type PageFn = (c: AppContext, me: Account, tab: SettingsTab, title: string, body: Child, status?: number) => Response | Promise<Response>;
/** The site-administration page shell (account.tsx), shared by Registration, Instance and Bot check. */
export type AdminPage = PageFn;

/** Routes for Registration and Instance. They share the site-administration page shell (account.tsx). */
export function registerRegistrationAdmin(web: WebApp, { requireSiteAdmin, page }: { requireSiteAdmin: (c: AppContext) => Account; page: PageFn }): void {
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
        // The bot check is edited on Settings → Bot check: keep the stored provider here.
        const current = await readRegistrationPolicy(c.env);
        await saveRegistrationPolicy(c.env, c.get("dir"), { ...policyFromForm(f), provider: current.provider }, me);
      },
      "Registration saved. It applies to the next request.",
    );
  });

  web.get("/settings/admin/instance", async (c) => {
    const me = requireSiteAdmin(c);
    const s = await readInstanceSettings(c.env);
    const email = (await registrationPolicy(c.env)).email;
    return page(c, me, "instance", "Instance", <InstanceAdmin mode={s.mode} requireEmailForSignup={s.requireEmailForSignup} updatedAt={s.updatedAt} updatedBy={s.updatedBy} t={csrfToken(c)} email={email} />);
  });

  post(web, "/settings/admin/instance", async (c, f) => {
    const me = requireSiteAdmin(c);
    return act(
      c,
      "/settings/admin/instance",
      async () => {
        const mode = (INSTANCE_MODES as readonly string[]).find((m) => m === f.s("mode")) === "production" ? "production" : "demo";
        await saveInstanceSettings(c.env, c.get("dir"), { mode, requireEmailForSignup: f.b("require_email_for_signup") }, me);
      },
      "Instance saved. It applies to the next page.",
    );
  });
}
