/** @jsxImportSource hono/jsx */
/**
 * Settings → Site administration → Bot check: both bot checks in one page.
 *
 * The registration policy's provider (auth/registration.ts) says which check runs in front of the
 * sign-up forms; the keys for either provider are edited here too. Cloudflare Turnstile's and
 * cap.js's settings live in one row (captcha_settings, auth/captcha.ts), sealed with MASTER_KEY, and
 * win over the deployment's variables when they are complete, so a site administrator changes
 * either without a deploy.
 *
 * The public forms outside sign-up (early access, the contact form and the security report form)
 * always use Turnstile; the page says so and the keys here are the ones they use.
 *
 * Kumo components only (KSelect), never a native select (AGENTS.md).
 */
import type { FC } from "hono/jsx";
import type { Env } from "../env.js";
import { HttpError } from "../lib/util.js";
import { encryptSecret } from "../lib/crypto.js";
import type { Account } from "../lib/directory.js";
import type { AppContext } from "../auth/principal.js";
import { CAPTCHA_PROVIDERS, PROVIDER_LABEL, capConfiguration, normalCapEndpoint, normalCapSiteKey, normalTurnstileSiteKey, readCaptchaSettings, turnstileConfiguration, type CapConfiguration, type CaptchaSettings, type TurnstileConfiguration } from "../auth/captcha.js";
import { readRegistrationPolicy, registrationPolicy, saveRegistrationPolicy, type Registration } from "../auth/registration.js";
import { csrfToken } from "./csrf.js";
import { KSelect } from "./kumo.js";
import { Form, Time, act, flash, post, type WebApp } from "./ui.js";
import type { AdminPage } from "./registration.js";

/** One sentence for the top of the page: what checks the sign-up forms now, and from where. */
function nowLine(r: Registration, cap: CapConfiguration | null, turnstile: TurnstileConfiguration | null): string {
  if (r.captcha.missing) return `Sign-up is refused until the check is set up: ${r.captcha.missing}`;
  const source = (c: { source: "settings" | "environment" } | null) => (c ? (c.source === "settings" ? ", set here" : ", from the deployment") : "");
  if (r.captcha.kind === "none") return "No bot check on the sign-up forms: rate limits and the daily email limits still apply.";
  if (r.captcha.kind === "cap") return `cap.js checks the sign-up forms${source(cap)}.`;
  return `Cloudflare Turnstile checks the sign-up forms${source(turnstile)}.`;
}

export const BotCheckAdmin: FC<{ r: Registration; t: string; saved: CaptchaSettings; cap: CapConfiguration | null; turnstile: TurnstileConfiguration | null }> = ({ r, t, saved, cap, turnstile }) => (
  <>
    <h1>Bot check</h1>
    <p class="muted">
      The check in front of the sign-up forms, and the keys for both providers. Saved here, they apply to the next form, win over the deployment's variables, and are in the <a href="/settings/audit">audit log</a>. The early access request, the contact form and the security report form always use Cloudflare Turnstile, with the keys saved on this page.
    </p>

    <div class="flash notice" role="status">
      <b>Now:</b> {nowLine(r, cap, turnstile)}
    </div>
    {saved.turnstileSiteKey && !turnstile ? <div class="flash error">The Turnstile keys saved here can't be used right now: its secret can't be opened with this MASTER_KEY, or the pair is incomplete. Save the secret again.</div> : null}
    {saved.capEndpoint && !cap ? <div class="flash error">The cap.js server saved here can't be used right now: its secret can't be opened with this MASTER_KEY, or the pair is incomplete. Save the secret again.</div> : null}

    <Form action="/settings/admin/bot-check" t={t} class="box">
      <div class="head">
        <h2>Which check</h2>
        <span class="badge">{PROVIDER_LABEL[r.policy.provider]}</span>
      </div>
      <div class="body fbody">
        <div class="field">
          <label for="provider">Bot check on the sign-up forms</label>
          <KSelect id="provider" name="provider" label="Bot check" block value={r.policy.provider} options={CAPTCHA_PROVIDERS.map((v) => ({ value: v, label: PROVIDER_LABEL[v] }))} />
          <div class="hint">
            A check that is chosen but not set up refuses every sign-up with a readable reason rather than letting a script through. Registration itself is on <a href="/settings/admin/registration">Registration</a>.
            {r.captcha.missing ? (
              <>
                {" "}
                <span class="badge red">Not set up: {r.captcha.missing}</span>
              </>
            ) : null}
          </div>
        </div>
        <div class="factions">
          <button class="btn primary">Save bot check</button>
        </div>
      </div>
    </Form>

    <Form action="/settings/admin/bot-check/turnstile" t={t} class="box">
      <div class="head">
        <h2>Cloudflare Turnstile</h2>
        {turnstile ? <span class="badge green">{turnstile.source === "settings" ? "set here" : "from the deployment"}</span> : <span class="badge">not set up</span>}
      </div>
      <div class="body fbody">
        <p class="muted m0">
          Cloudflare's bot check: the widget comes from <span class="mono">challenges.cloudflare.com</span>. Create a widget in the Cloudflare dashboard (Turnstile) and paste its site key and secret key here. Saved here, they win over <span class="mono">TURNSTILE_SITE_KEY</span> and the <span class="mono">TURNSTILE_SECRET</span> secret.
        </p>
        <div class="field">
          <label for="turnstile-site-key">Site key</label>
          <input id="turnstile-site-key" name="turnstile_site_key" maxlength={120} autocomplete="off" placeholder="0x4AAAAAAA…" value={saved.turnstileSiteKey ?? ""} />
        </div>
        <div class="field">
          <label for="turnstile-secret">Secret key</label>
          <input id="turnstile-secret" name="turnstile_secret" type="password" maxlength={200} autocomplete="off" placeholder={turnstile?.source === "settings" ? "saved; type a new one to replace it" : "the secret key"} />
          <div class="hint">Sealed with MASTER_KEY before it is stored, and never shown again. Leave it empty to keep the one that is saved. Save an empty site key to stop using the keys saved here and go back to the deployment's variables.</div>
        </div>
        <div class="factions">
          <button class="btn primary">Save Turnstile</button>
        </div>
      </div>
    </Form>

    <Form action="/settings/admin/bot-check/cap" t={t} class="box">
      <div class="head">
        <h2>cap.js server</h2>
        {cap ? <span class="badge green">{cap.source === "settings" ? "set here" : "from the deployment"}</span> : <span class="badge">not set up</span>}
      </div>
      <div class="body fbody">
        <p class="muted m0">
          <a href="https://capjs.js.org">cap.js</a> is a self-hosted proof-of-work CAPTCHA: no Google, nothing loaded from Cloudflare, and it runs on your own machine. Point it at your capd server, with a site key from its dashboard and that key's secret (not the capd <span class="mono">ADMIN_KEY</span>). Saved here, it applies without a deploy and wins over <span class="mono">CAP_ENDPOINT</span>, <span class="mono">CAP_SITE_KEY</span> and <span class="mono">CAP_SECRET</span>.
        </p>
        <div class="frow">
          <div class="field grow">
            <label for="cap-endpoint">Server</label>
            <input id="cap-endpoint" name="cap_endpoint" type="url" maxlength={300} placeholder="https://cap.example.com" value={saved.capEndpoint ?? ""} />
          </div>
          <div class="field">
            <label for="cap-site-key">Site key</label>
            <input id="cap-site-key" name="cap_site_key" maxlength={80} placeholder="the key, not the ADMIN_KEY" value={saved.capSiteKey ?? ""} />
          </div>
        </div>
        <div class="field">
          <label for="cap-secret">Secret</label>
          <input id="cap-secret" name="cap_secret" type="password" maxlength={200} autocomplete="off" placeholder={cap?.source === "settings" ? "saved; type a new one to replace it" : "the site key's secret"} />
          <div class="hint">Sealed with MASTER_KEY before it is stored, and never shown again. Leave it empty to keep the one that is saved. Save an empty server to stop using it.</div>
        </div>
        <div class="factions">
          <button class="btn primary">Save cap.js</button>
        </div>
      </div>
    </Form>

    <div class="box">
      <div class="body">
        {saved.updatedAt ? (
          <p class="m0 muted">
            Last keys saved by <b>{saved.updatedBy ?? "a site administrator"}</b> <Time at={saved.updatedAt} />.
          </p>
        ) : (
          <p class="m0 muted">No keys saved here yet: the deployment's variables, if any, are what apply.</p>
        )}
      </div>
    </div>
  </>
);

/**
 * Seal a secret for storage. A missing or unusable MASTER_KEY is this instance's setup, not the
 * administrator's mistake: it answers 503 with that, rather than a bare 500.
 */
const seal = (env: Env, scope: string, value: string): Promise<string> =>
  encryptSecret(env, scope, value).catch((e: Error) => {
    throw new HttpError(503, `The secret can't be stored: ${e.message || "encryption unavailable"}. Set MASTER_KEY on the deployment and try again.`);
  });

/** Routes for Settings → Site administration → Bot check. It shares the site-administration shell (account.tsx). */
export function registerBotCheckAdmin(web: WebApp, { requireSiteAdmin, page }: { requireSiteAdmin: (c: AppContext) => Account; page: AdminPage }): void {
  web.get("/settings/admin/bot-check", async (c) => {
    const me = requireSiteAdmin(c);
    const r = await registrationPolicy(c.env);
    const [saved, cap, turnstile] = await Promise.all([readCaptchaSettings(c.env), capConfiguration(c.env), turnstileConfiguration(c.env)]);
    return page(c, me, "bot-check", "Bot check", <BotCheckAdmin r={r} t={csrfToken(c)} saved={saved} cap={cap} turnstile={turnstile} />);
  });

  // The provider is a column of the registration policy: every other field is kept as it is.
  post(web, "/settings/admin/bot-check", async (c, f) => {
    const me = requireSiteAdmin(c);
    return act(
      c,
      "/settings/admin/bot-check",
      async () => {
        const current = await readRegistrationPolicy(c.env);
        const provider = CAPTCHA_PROVIDERS.find((p) => p === f.s("provider")) ?? current.provider;
        await saveRegistrationPolicy(c.env, c.get("dir"), { ...current, provider }, me);
      },
      "Bot check saved. It applies to the next form.",
    );
  });

  // Turnstile: stored here so it can be turned on without a deploy. The secret is sealed, never echoed.
  post(web, "/settings/admin/bot-check/turnstile", async (c, f) => {
    const me = requireSiteAdmin(c);
    return act(
      c,
      "/settings/admin/bot-check",
      async () => {
        const keyRaw = f.s("turnstile_site_key").trim();
        const secret = f.s("turnstile_secret").trim();
        const dir = c.get("dir");
        if (!keyRaw) {
          // An empty site key turns the saved pair off, falling back to the deployment's variables.
          await c.env.DB.prepare("UPDATE captcha_settings SET turnstile_site_key = NULL, turnstile_secret = NULL, updated_at = ?, updated_by = ? WHERE id = 1").bind(new Date().toISOString(), me.login).run();
          await dir.audit({ actorId: me.id, actorLogin: me.login, action: "captcha.settings.update", detail: { provider: "turnstile", removed: true } });
          flash(c, "notice", "The saved Turnstile keys are gone: the deployment's TURNSTILE_SITE_KEY and TURNSTILE_SECRET apply again.");
          return;
        }
        const siteKey = normalTurnstileSiteKey(keyRaw);
        if (!siteKey) throw new HttpError(422, "A Turnstile site key looks like 0x4AAAAAAA…: copy it from the widget in the Cloudflare dashboard.");
        // A site key with no secret (and none saved) would fall straight back to the deployment: refuse the half a pair.
        if (!secret && !(await readCaptchaSettings(c.env)).turnstileSealedSecret) throw new HttpError(422, "A Turnstile secret key is needed too: copy it from the widget in the Cloudflare dashboard.");
        const sealed = secret ? await seal(c.env, "captcha:turnstile", secret) : null;
        await c.env.DB.prepare(
          "INSERT INTO captcha_settings (id, turnstile_site_key, turnstile_secret, updated_at, updated_by) VALUES (1, ?, ?, ?, ?) " +
            "ON CONFLICT (id) DO UPDATE SET turnstile_site_key = excluded.turnstile_site_key, turnstile_secret = COALESCE(excluded.turnstile_secret, captcha_settings.turnstile_secret), updated_at = excluded.updated_at, updated_by = excluded.updated_by",
        )
          .bind(siteKey, sealed, new Date().toISOString(), me.login)
          .run();
        await dir.audit({ actorId: me.id, actorLogin: me.login, action: "captcha.settings.update", detail: { provider: "turnstile", siteKey, secret: secret ? "set" : "unchanged" } });
        flash(c, "notice", `Turnstile keys saved: ${siteKey}. They apply to the next form.`);
      },
    );
  });

  // cap.js: the same, for a server of your own.
  post(web, "/settings/admin/bot-check/cap", async (c, f) => {
    const me = requireSiteAdmin(c);
    return act(
      c,
      "/settings/admin/bot-check",
      async () => {
        const endpointRaw = f.s("cap_endpoint").trim();
        const keyRaw = f.s("cap_site_key").trim();
        const secret = f.s("cap_secret").trim();
        const dir = c.get("dir");
        if (!endpointRaw) {
          // An empty server turns the saved one off, falling back to the deployment's variables.
          await c.env.DB.prepare("UPDATE captcha_settings SET cap_endpoint = NULL, cap_site_key = NULL, cap_secret = NULL, updated_at = ?, updated_by = ? WHERE id = 1").bind(new Date().toISOString(), me.login).run();
          await dir.audit({ actorId: me.id, actorLogin: me.login, action: "captcha.settings.update", detail: { provider: "cap", removed: true } });
          flash(c, "notice", "The saved cap.js server is gone: the deployment's variables apply again.");
          return;
        }
        const endpoint = normalCapEndpoint(endpointRaw);
        if (!endpoint) throw new HttpError(422, "The cap.js server must be an https address without a query, like https://cap.example.com.");
        const siteKey = normalCapSiteKey(keyRaw);
        if (!siteKey) throw new HttpError(422, "The cap.js site key is a short token from the capd dashboard, like AbC123.");
        if (!secret && !(await readCaptchaSettings(c.env)).capSealedSecret) throw new HttpError(422, "The cap.js site key's secret is needed too: copy it from the capd dashboard.");
        const sealed = secret ? await seal(c.env, "captcha:cap", secret) : null;
        // A saved secret is kept when the form leaves it empty: only the upsert's SET may read the old row.
        await c.env.DB.prepare(
          "INSERT INTO captcha_settings (id, cap_endpoint, cap_site_key, cap_secret, updated_at, updated_by) VALUES (1, ?, ?, ?, ?, ?) " +
            "ON CONFLICT (id) DO UPDATE SET cap_endpoint = excluded.cap_endpoint, cap_site_key = excluded.cap_site_key, cap_secret = COALESCE(excluded.cap_secret, captcha_settings.cap_secret), updated_at = excluded.updated_at, updated_by = excluded.updated_by",
        )
          .bind(endpoint, siteKey, sealed, new Date().toISOString(), me.login)
          .run();
        await dir.audit({ actorId: me.id, actorLogin: me.login, action: "captcha.settings.update", detail: { provider: "cap", endpoint, siteKey, secret: secret ? "set" : "unchanged" } });
        flash(c, "notice", `cap.js saved: ${endpoint}. It applies to the next form.`);
      },
    );
  });
}
