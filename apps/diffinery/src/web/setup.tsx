/** @jsxImportSource hono/jsx */
/**
 * The first-run setup wizard.
 *
 * A fresh instance has no account, no email transport and no Cloudflare Access, so none of the
 * usual ways in work: an invite needs someone to send it, an administrator's sign-in link needs an
 * administrator, and a passkey needs an account to attach to. `/setup` breaks that circle: while the
 * instance has no user at all, it creates the first site administrator with a password
 * (src/auth/password.ts), signs it in, and stops existing.
 *
 * `app.ts` redirects every browser page here until an account exists, and this file refuses to run
 * once one does, so the page is reachable exactly once.
 */
import type { FC } from "hono/jsx";
import { setCookie } from "hono/cookie";
import { Auth, SESSION_COOKIE, SESSION_DAYS } from "../auth/sessions.js";
import { hashPassword, passwordProblem } from "../auth/password.js";
import { normalEmail } from "../auth/signup.js";
import { HttpError, isValidLogin } from "../lib/util.js";
import { csrfToken } from "./csrf.js";
import { Form, post, render, type WebApp } from "./ui.js";

const SETUP_NOTE = "This page appears once. After it, sign in at /login with the password you chose, or add a passkey from Settings → Security.";

const SetupCard: FC<{ children?: unknown; error?: string }> = ({ children, error }) => (
  <div class="authcard box">
    <div class="body">
      <h1>Set up Diffinery</h1>
      <p class="muted">This instance has no accounts yet. Create the first one: it is the site administrator.</p>
      {error ? (
        <div class="flash error" role="alert">
          {error}
        </div>
      ) : null}
      {children}
    </div>
  </div>
);

const Fields: FC<{ login?: string; email?: string; name?: string }> = ({ login, email, name }) => (
  <>
    <div class="field">
      <label for="login">Username</label>
      <input id="login" name="login" type="text" required autofocus autocomplete="username" maxlength={39} value={login ?? ""} placeholder="admin" />
    </div>
    <div class="field">
      <label for="email">Email address</label>
      <input id="email" name="email" type="email" required autocomplete="email" maxlength={254} value={email ?? ""} placeholder="you@example.com" />
      <div class="hint">Used to identify the account and to recover it later. No email is sent during setup.</div>
    </div>
    <div class="field">
      <label for="name">Display name (optional)</label>
      <input id="name" name="name" type="text" maxlength={100} value={name ?? ""} />
    </div>
    <div class="field">
      <label for="password">Password</label>
      <input id="password" name="password" type="password" required autocomplete="new-password" minlength={10} maxlength={200} />
      <div class="hint">At least 10 characters. Length matters more than punctuation.</div>
    </div>
    <div class="field">
      <label for="confirm">Password again</label>
      <input id="confirm" name="confirm" type="password" required autocomplete="new-password" minlength={10} maxlength={200} />
    </div>
  </>
);

/** The one page that runs before anything else, for a browser. */
export function registerSetup(web: WebApp): void {
  web.get("/setup", async (c) => {
    if (await c.get("dir").hasAnyUser()) return c.redirect("/login", 302);
    return render(
      c,
      { title: "Set up Diffinery" },
      <SetupCard>
        <p class="muted small">{SETUP_NOTE}</p>
        <Form action="/setup" t={csrfToken(c)}>
          <Fields />
          <button class="btn primary block">Create the administrator</button>
        </Form>
      </SetupCard>,
    );
  });

  post(web, "/setup", async (c, f) => {
    const dir = c.get("dir");
    const login = f.s("login").trim();
    const email = normalEmail(f.s("email"));
    const name = f.s("name").trim() || null;
    const password = f.s("password");
    const confirm = f.s("confirm");

    // Re-render with what they typed (never the password) and the reason.
    const again = async (error: string): Promise<Response> =>
      render(
        c,
        { title: "Set up Diffinery", status: 422 },
        <SetupCard error={error}>
          <Form action="/setup" t={csrfToken(c)}>
            <Fields login={login} email={f.s("email").trim()} name={name ?? ""} />
            <button class="btn primary block">Create the administrator</button>
          </Form>
        </SetupCard>,
      );

    if (await dir.hasAnyUser()) return c.redirect("/login", 302);
    if (!isValidLogin(login)) return again("Use a username of letters, digits, - and _ that starts with a letter or digit, up to 39 characters.");
    if (!email) return again("That email address does not look right.");
    if (password !== confirm) return again("The two passwords do not match.");
    const problem = passwordProblem(password);
    if (problem) return again(problem);

    let account;
    try {
      account = await dir.createFirstAdmin({ login, email, name, passwordHash: await hashPassword(password) });
    } catch (e) {
      // A second browser finished setup first: the unique index on login and the hasAnyUser check
      // both race, and whoever loses is told to sign in instead.
      if (e instanceof HttpError && e.status === 409) return c.redirect("/login", 302);
      throw e;
    }

    const auth = new Auth(c.env);
    const token = await auth.createSession(account.id, "password", null, c.req.header("user-agent") ?? null);
    setCookie(c, SESSION_COOKIE, token, { path: "/", httpOnly: true, secure: true, sameSite: "Lax", maxAge: SESSION_DAYS * 86400 });
    return c.redirect("/", 303);
  });
}
