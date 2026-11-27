import { afterEach, describe, expect, it, vi } from "vitest";
import { app } from "../../src/app.js";
import { web } from "../../src/web/routes.js";
import type { Env } from "../../src/env.js";
import { deliver, mailTransport, RetryableMailError, type Outgoing } from "../../src/mail/send.js";
import { formatMessage, readSmtpSettings, sendSmtp, SmtpError, smtpConfig, smtpConfiguration, smtpLabel, type SmtpConfig } from "../../src/mail/smtp.js";
import { encryptSecret } from "../../src/lib/crypto.js";
import { Suppressions } from "../../src/mail/suppression.js";
import type { MailJob } from "../../src/mail/types.js";
import { setConnect } from "./stubs/cloudflare-sockets.js";
import { testD1 } from "./stubs/d1.js";

// index.ts mounts the web UI last; do the same here (it can't load Durable Objects under Node).
app.route("/", web);

const enc = new TextEncoder();
const PASSWORD = "hunter2-very-secret";
/** A MASTER_KEY that encryptSecret accepts: base64 of 32 bytes. */
const MASTER = btoa(String.fromCharCode(...new Uint8Array(32).fill(5)));
const b64 = (s: string) => Buffer.from(s, "utf8").toString("base64");

type Verb = "STARTTLS" | "AUTH" | "MAIL" | "RCPT" | "DATA" | "END";

/**
 * A fake SMTP server behind a fake socket: it answers each command as a submission server would,
 * or with the reply a test sets for that step ("CLOSE" hangs up instead), and records the commands
 * and the message. Replies go out as soon as a command is written, so nothing here waits on time.
 */
class FakeSmtp {
  commands: string[] = [];
  data = "";
  connects: Array<{ address: unknown; options: unknown }> = [];
  upgrades = 0;
  private out: (s: string) => void = () => {};
  private hangUp: () => void = () => {};
  private buf = "";
  private inData = false;
  private loginStep = 0;
  private tls = false;

  constructor(
    private s: {
      silent?: boolean;
      /** Extensions after TLS (default PIPELINING, AUTH PLAIN LOGIN, ENHANCEDSTATUSCODES) and before it (default STARTTLS). */
      ehlo?: string[];
      ehloPlain?: string[];
      reply?: Partial<Record<Verb, string>>;
    } = {},
  ) {}

  connect = (address: unknown, options?: { secureTransport?: string }): Socket => {
    this.connects.push({ address, options });
    this.tls = options?.secureTransport === "on";
    const socket = this.socket();
    if (!this.s.silent) this.send("220 smtp.example ESMTP");
    return socket;
  };

  private socket(): Socket {
    const dec = new TextDecoder();
    let ctrl!: ReadableStreamDefaultController<Uint8Array>;
    const readable = new ReadableStream<Uint8Array>({ start: (c) => void (ctrl = c) });
    this.out = (s) => ctrl.enqueue(enc.encode(s));
    this.hangUp = () => {
      try {
        ctrl.close();
      } catch {
        // already closed
      }
    };
    const writable = new WritableStream<Uint8Array>({ write: (chunk) => this.receive(dec.decode(chunk, { stream: true })) });
    const startTls = () => {
      this.upgrades++;
      this.tls = true;
      return this.socket();
    };
    return { readable, writable, opened: Promise.resolve({}), closed: Promise.resolve(), close: async () => this.hangUp(), startTls } as unknown as Socket;
  }

  private send(s: string): void {
    if (s === "CLOSE") this.hangUp();
    else this.out(`${s}\r\n`);
  }

  private receive(text: string): void {
    this.buf += text;
    for (let i = this.buf.indexOf("\r\n"); i >= 0; i = this.buf.indexOf("\r\n")) {
      const line = this.buf.slice(0, i);
      this.buf = this.buf.slice(i + 2);
      if (this.inData) {
        if (line === ".") {
          this.inData = false;
          this.send(this.s.reply?.END ?? "250 2.0.0 Ok: queued as ABC123");
        } else this.data += `${line.startsWith(".") ? line.slice(1) : line}\r\n`;
      } else this.command(line);
    }
  }

  private command(line: string): void {
    this.commands.push(line);
    const r = this.s.reply ?? {};
    if (this.loginStep === 1) {
      this.loginStep = 2;
      return this.send("334 UGFzc3dvcmQ6");
    }
    if (this.loginStep === 2) {
      this.loginStep = 0;
      return this.send(r.AUTH ?? "235 2.7.0 Authentication successful");
    }
    const verb = line.split(" ")[0]!.toUpperCase();
    if (verb === "EHLO") {
      const ext = this.tls ? (this.s.ehlo ?? ["PIPELINING", "AUTH PLAIN LOGIN", "ENHANCEDSTATUSCODES"]) : (this.s.ehloPlain ?? ["STARTTLS", "ENHANCEDSTATUSCODES"]);
      const lines = ["smtp.example Hello", ...ext];
      return this.send(lines.map((l, i) => `250${i === lines.length - 1 ? " " : "-"}${l}`).join("\r\n"));
    }
    if (verb === "STARTTLS") return this.send(r.STARTTLS ?? "220 2.0.0 Ready to start TLS");
    if (line === "AUTH LOGIN") {
      this.loginStep = 1;
      return this.send("334 VXNlcm5hbWU6");
    }
    if (verb === "AUTH") return this.send(r.AUTH ?? "235 2.7.0 Authentication successful");
    if (verb === "MAIL") return this.send(r.MAIL ?? "250 2.1.0 Ok");
    if (verb === "RCPT") return this.send(r.RCPT ?? "250 2.1.5 Ok");
    if (verb === "DATA") {
      const reply = r.DATA ?? "354 End data with <CR><LF>.<CR><LF>";
      this.inData = reply.startsWith("354");
      return this.send(reply);
    }
    if (verb === "QUIT") return this.send("221 2.0.0 Bye");
    this.send("500 5.5.2 Unknown command");
  }

  /** The decoded text/plain or text/html part of the message the server received. */
  part(type: "plain" | "html"): string {
    const m = new RegExp(`Content-Type: text/${type}; charset=utf-8\\r\\nContent-Transfer-Encoding: base64\\r\\n\\r\\n([\\s\\S]*?)\\r\\n--`).exec(this.data);
    return Buffer.from(m![1]!.replace(/\r\n/g, ""), "base64").toString("utf8");
  }
}

const msg = (over: Partial<Outgoing> = {}): Outgoing => ({
  from: { name: "Ann (Diffinery)", email: "notifications@diffinery.example" },
  to: { name: "Bob", email: "bob@example.com" },
  subject: "Your test email",
  html: "<p>Hello <b>Bob</b></p>",
  text: "Hello Bob\n.a line that starts with a dot",
  headers: { "X-Diffinery-Reason": "account", "List-Unsubscribe": "<https://diffinery.example/u/x>" },
  ...over,
});

const implicit: SmtpConfig = { host: "smtp.example", port: 465, tls: "implicit", user: "ann@diffinery.example", password: PASSWORD };
const starttls: SmtpConfig = { ...implicit, port: 587, tls: "starttls" };

function server(s: ConstructorParameters<typeof FakeSmtp>[0] = {}): FakeSmtp {
  const f = new FakeSmtp(s);
  setConnect(f.connect);
  return f;
}

afterEach(() => {
  setConnect(null);
  vi.restoreAllMocks();
});

describe("SMTP settings", () => {
  it("reads SMTP_URL and SMTP_PASSWORD", () => {
    expect(smtpConfig({})).toBeNull();
    expect(smtpConfig({ SMTP_URL: "smtps://ann%40diffinery.example@smtp.example", SMTP_PASSWORD: PASSWORD })).toEqual(implicit);
    expect(smtpConfig({ SMTP_URL: "smtp://ann%40diffinery.example@smtp.example", SMTP_PASSWORD: PASSWORD })).toEqual(starttls);
    expect(smtpConfig({ SMTP_URL: "smtps://relay.example:2465" })).toEqual({ host: "relay.example", port: 2465, tls: "implicit", user: null, password: null });
    expect(smtpConfig({ SMTP_URL: "smtp://[::1]:1587" })).toMatchObject({ host: "::1", port: 1587 });
  });

  const savedEnv = (vars: Partial<Env> = {}): Env => ({ DB: testD1(), PUBLIC_URL: "https://diffinery.example", MASTER_KEY: MASTER, ...vars }) as unknown as Env;

  it("a server and password saved in Settings beat SMTP_URL, and an empty one falls back to it", async () => {
    const env = savedEnv({ SMTP_URL: "smtps://env%40diffinery.example@smtp.example", SMTP_PASSWORD: "from-the-deployment" });
    expect(await readSmtpSettings(env)).toEqual({ url: null, sealedPassword: null, updatedAt: null, updatedBy: null });
    expect(await smtpConfiguration(env)).toEqual({ config: { ...implicit, user: "env@diffinery.example", password: "from-the-deployment" }, source: "environment" });
    const sealed = await encryptSecret(env, "smtp", PASSWORD);
    env.DB.prepare("UPDATE smtp_settings SET smtp_url = ?, smtp_password = ?, updated_by = ? WHERE id = 1").bind("smtps://ann%40diffinery.example@smtp.example", sealed, "root").run();
    expect(await readSmtpSettings(env)).toMatchObject({ url: "smtps://ann%40diffinery.example@smtp.example", sealedPassword: sealed, updatedBy: "root" });
    expect(await smtpConfiguration(env)).toEqual({ config: implicit, source: "settings" });
    // Saving an empty server puts the deployment's variables back in charge.
    env.DB.prepare("UPDATE smtp_settings SET smtp_url = NULL, smtp_password = NULL WHERE id = 1").run();
    expect(await smtpConfiguration(env)).toMatchObject({ source: "environment" });
  });

  it("says so when the saved password can't be opened, instead of sending without it", async () => {
    const env = savedEnv({ MASTER_KEY: undefined });
    env.DB.prepare("UPDATE smtp_settings SET smtp_url = ?, smtp_password = ? WHERE id = 1").bind("smtps://ann%40diffinery.example@smtp.example", "v2.dead.beef.cafe").run();
    expect(await smtpConfiguration(env)).toEqual({ error: expect.stringContaining("can't be opened with this MASTER_KEY") });
  });

  it("a missing table (a deploy that raced its migration) reads as nothing saved", async () => {
    const env = savedEnv({ SMTP_URL: "smtps://relay.example:2465" });
    (env.DB as unknown as { sqlite: { exec: (q: string) => unknown } }).sqlite.exec("DROP TABLE smtp_settings");
    expect(await readSmtpSettings(env)).toEqual({ url: null, sealedPassword: null, updatedAt: null, updatedBy: null });
    expect(await smtpConfiguration(env)).toMatchObject({ source: "environment", config: { host: "relay.example", port: 2465 } });
  });

  it("says what is wrong, and never takes a password from the URL", () => {
    expect(smtpConfig({ SMTP_URL: "smtps://ann:pw@smtp.example" })).toEqual({ error: "the password goes in the SMTP_PASSWORD secret, not in SMTP_URL" });
    expect(smtpConfig({ SMTP_URL: "https://smtp.example" })).toEqual({ error: "SMTP_URL must start with smtps:// or smtp://" });
    expect(smtpConfig({ SMTP_URL: "smtps://ann@smtp.example" })).toEqual({ error: "SMTP_URL names a user but the SMTP_PASSWORD secret is not set" });
    expect(smtpConfig({ SMTP_URL: "smtps://smtp.example", SMTP_PASSWORD: PASSWORD })).toEqual({ error: "SMTP_PASSWORD is set but SMTP_URL names no user" });
    expect(smtpConfig({ SMTP_URL: "smtps://smtp.example/x?y" })).toEqual({ error: "SMTP_URL takes no path or query" });
  });

  it("shows administrators the server but not the password", () => {
    expect(smtpLabel(implicit)).toBe("smtps://ann%40diffinery.example@smtp.example:465");
    expect(smtpLabel(starttls)).toBe("smtp://ann%40diffinery.example@smtp.example:587 (STARTTLS)");
  });

  it("prefers the EMAIL binding when both are there", async () => {
    const EMAIL = { send: async () => ({ messageId: "x" }) } as unknown as SendEmail;
    const DB = testD1();
    expect((await mailTransport({ DB, EMAIL, SMTP_URL: "smtps://smtp.example" }))?.kind).toBe("email-sending");
    expect((await mailTransport({ DB, SMTP_URL: "smtps://smtp.example" }))?.kind).toBe("smtp");
    expect(await mailTransport({ DB })).toBeNull();
  });
});

describe("the MIME message", () => {
  const date = new Date("2026-10-30T12:00:00Z");

  it("has the headers, and the text and HTML parts in base64, with CRLF line ends", () => {
    const m = formatMessage(msg({ replyTo: "kim@example.com" }), { messageId: "<id@diffinery.example>", date, boundary: "b" });
    expect(m.replace(/\r\n/g, "")).not.toMatch(/[\r\n]/);
    const [head] = m.split("\r\n\r\n");
    expect(head!.split("\r\n")).toEqual([
      'From: "Ann (Diffinery)" <notifications@diffinery.example>',
      'To: "Bob" <bob@example.com>',
      "Reply-To: kim@example.com",
      "Subject: Your test email",
      "Date: Fri, 30 Oct 2026 12:00:00 +0000",
      "Message-ID: <id@diffinery.example>",
      "MIME-Version: 1.0",
      "X-Diffinery-Reason: account",
      "List-Unsubscribe: <https://diffinery.example/u/x>",
      'Content-Type: multipart/alternative; boundary="b"',
    ]);
    expect(m).toContain(`Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n${b64(msg().text)}\r\n--b\r\n`);
    expect(m).toContain(`Content-Type: text/html; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n${b64(msg().html)}\r\n--b--\r\n`);
  });

  it("encodes non-ASCII names and subjects, and keeps out injected headers", () => {
    const m = formatMessage(
      msg({ subject: "Ünal commented on acme/website#12 — a long subject that needs more than one encoded word", to: { name: "Bob Ünal", email: "bob@example.com" }, headers: { "X-Evil\r\nBcc": "x", "X-Ok": "a\r\nBcc: eve@example.com", Subject: "twice" } }),
      { messageId: "<id@x>", date },
    );
    const head = m.split("\r\n\r\n")[0]!;
    const decode = (s: string) => s.replace(/\r\n /g, "").replace(/=\?UTF-8\?B\?([^?]*)\?=/g, (_, w: string) => Buffer.from(w, "base64").toString("utf8"));
    expect(decode(/^Subject: (.*(?:\r\n .*)*)/m.exec(head)![1]!)).toBe("Ünal commented on acme/website#12 — a long subject that needs more than one encoded word");
    expect(/^Subject: .*(?:\r\n .*)*/m.exec(head)![0].split("\r\n").every((l) => l.length <= 78)).toBe(true);
    expect(decode(/^To: (.*)/m.exec(head)![1]!)).toBe("Bob Ünal <bob@example.com>");
    expect(head).toContain("X-Ok: a Bcc: eve@example.com");
    expect(head).not.toMatch(/^Bcc/m);
    expect(head.match(/^Subject:/gm)).toHaveLength(1);
  });
});

describe("sending over SMTP", () => {
  it("sends over implicit TLS with AUTH PLAIN", async () => {
    const f = server();
    const r = await sendSmtp(implicit, msg(), { ehlo: "diffinery.example" });
    expect(f.connects).toEqual([{ address: { hostname: "smtp.example", port: 465 }, options: { secureTransport: "on", allowHalfOpen: false } }]);
    expect(f.commands).toEqual(["EHLO diffinery.example", `AUTH PLAIN ${b64(`\0ann@diffinery.example\0${PASSWORD}`)}`, "MAIL FROM:<notifications@diffinery.example>", "RCPT TO:<bob@example.com>", "DATA", "QUIT"]);
    expect(r.messageId).toMatch(/^<[0-9a-f-]{36}@diffinery\.example>$/);
    expect(f.data).toContain(`Message-ID: ${r.messageId}\r\n`);
    expect(f.part("plain")).toBe(msg().text);
    expect(f.part("html")).toBe(msg().html);
  });

  it("upgrades with STARTTLS before anything else, and falls back to AUTH LOGIN", async () => {
    const f = server({ ehlo: ["AUTH LOGIN"] });
    await sendSmtp(starttls, msg(), { ehlo: "diffinery.example" });
    expect(f.connects[0]).toEqual({ address: { hostname: "smtp.example", port: 587 }, options: { secureTransport: "starttls", allowHalfOpen: false } });
    expect(f.upgrades).toBe(1);
    expect(f.commands.slice(0, 6)).toEqual(["EHLO diffinery.example", "STARTTLS", "EHLO diffinery.example", "AUTH LOGIN", b64("ann@diffinery.example"), b64(PASSWORD)]);
  });

  it("won't send the password without TLS", async () => {
    const f = server({ ehloPlain: ["AUTH PLAIN LOGIN"] });
    const err = await sendSmtp(starttls, msg(), { ehlo: "diffinery.example" }).catch((e: SmtpError) => e);
    expect(err).toMatchObject({ code: "E_SMTP_REJECTED", message: "SMTP: the server doesn't offer STARTTLS, and Diffinery doesn't send without TLS" });
    expect(f.commands).toEqual(["EHLO diffinery.example"]);
  });

  it("ignores anything the server sent before TLS started", async () => {
    // A man in the middle appends a reply to the 220; read after the upgrade, it would answer the second EHLO.
    const f = server({ reply: { STARTTLS: "220 2.0.0 go ahead\r\n250 injected" } });
    await sendSmtp(starttls, msg(), { ehlo: "diffinery.example" });
    expect(f.commands.slice(2, 4)).toEqual(["EHLO diffinery.example", `AUTH PLAIN ${b64(`\0ann@diffinery.example\0${PASSWORD}`)}`]);
  });

  it("sends without AUTH when SMTP_URL names no user", async () => {
    const f = server();
    await sendSmtp({ ...implicit, user: null, password: null }, msg(), { ehlo: "diffinery.example" });
    expect(f.commands[1]).toBe("MAIL FROM:<notifications@diffinery.example>");
  });

  it.each([
    ["RCPT", "550 5.1.1 <bob@example.com>: Recipient address rejected: User unknown", "E_SMTP_RECIPIENT_REJECTED"],
    ["RCPT", "550 Mailbox not found", "E_SMTP_RECIPIENT_REJECTED"],
    ["RCPT", "550 5.7.1 Relaying denied", "E_SMTP_REJECTED"],
    ["RCPT", "552 5.2.2 Mailbox full", "E_SMTP_REJECTED"],
    ["RCPT", "451 4.3.0 Try again later", "E_SMTP_TRANSIENT"],
    ["MAIL", "550 5.1.8 Sender address rejected", "E_SMTP_REJECTED"],
    ["MAIL", "421 4.7.0 Too many connections", "E_SMTP_TRANSIENT"],
    ["END", "554 5.6.0 Message rejected", "E_SMTP_REJECTED"],
    ["DATA", "CLOSE", "E_SMTP_TRANSIENT"],
  ] as const)("maps %s %s to %s", async (verb, reply, code) => {
    server({ reply: { [verb]: reply } });
    const err = await sendSmtp(implicit, msg(), { ehlo: "diffinery.example" }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(SmtpError);
    expect((err as SmtpError).code).toBe(code);
  });

  it("never puts the password in an error", async () => {
    server({ reply: { AUTH: "535 5.7.8 Authentication credentials invalid" } });
    const err = (await sendSmtp(implicit, msg(), { ehlo: "diffinery.example" }).catch((e: unknown) => e)) as SmtpError;
    expect(err).toMatchObject({ code: "E_SMTP_REJECTED", message: "SMTP AUTH: 535 5.7.8 Authentication credentials invalid" });
    const login = server({ ehlo: ["AUTH LOGIN"], reply: { AUTH: "535 5.7.8 nope" } });
    const err2 = (await sendSmtp(implicit, msg(), { ehlo: "diffinery.example" }).catch((e: unknown) => e)) as SmtpError;
    expect(login.commands).toContain(b64(PASSWORD));
    for (const e of [err, err2]) for (const secret of [PASSWORD, b64(PASSWORD), b64(`\0ann@diffinery.example\0${PASSWORD}`)]) expect(`${e.message} ${e.stack}`).not.toContain(secret);
  });

  it("gives up on a server that doesn't answer", async () => {
    server({ silent: true });
    const err = await sendSmtp(implicit, msg(), { ehlo: "diffinery.example", timeoutMs: 5 }).catch((e: unknown) => e);
    expect(err).toMatchObject({ code: "E_SMTP_TRANSIENT", message: "SMTP greeting: no answer from the server in 0.005 seconds" });
  });

  it("refuses an address that would break the command", async () => {
    const f = server();
    const err = await sendSmtp(implicit, msg({ to: "bob@example.com>\r\nRCPT TO:<eve@example.com" }), { ehlo: "diffinery.example" }).catch((e: unknown) => e);
    expect(err).toMatchObject({ code: "E_SMTP_REJECTED" });
    expect(f.connects).toEqual([]);
  });
});

describe("deliver() over SMTP", () => {
  const at = "2026-10-01T00:00:00.000Z";
  const job: MailJob = { kind: "test", data: { by: "ann" }, to: { accountId: "ann" }, reason: "account", at } as MailJob;

  function setup(vars: Partial<Env> = { SMTP_URL: "smtps://ann%40diffinery.example@smtp.example", SMTP_PASSWORD: PASSWORD }) {
    const DB = testD1();
    DB.sqlite.prepare("INSERT INTO accounts (id, login, kind, email, status, created_at) VALUES ('ann', 'ann', 'user', 'ann@example.com', 'active', ?)").run(at);
    const env = { DB, PUBLIC_URL: "https://diffinery.example", MASTER_KEY: "test-master-key", MAIL_FROM: "notifications@diffinery.example", ...vars } as unknown as Env;
    const log = () => DB.sqlite.prepare("SELECT to_addr, status, detail, message_id FROM email_log ORDER BY rowid").all() as Array<{ to_addr: string; status: string; detail: string | null; message_id: string | null }>;
    return { env, log };
  }

  it("sends through SMTP_URL when there is no EMAIL binding", async () => {
    const f = server();
    const { env, log } = setup();
    const r = await deliver(env, job);
    expect(r.status).toBe("sent");
    expect(f.commands).toContain("RCPT TO:<ann@example.com>");
    expect(log()).toEqual([{ to_addr: "ann@example.com", status: "sent", detail: null, message_id: r.messageId }]);
  });

  it("sends through the server saved in Settings, not SMTP_URL", async () => {
    const f = server();
    const { env, log } = setup({ MASTER_KEY: MASTER, SMTP_URL: undefined, SMTP_PASSWORD: undefined });
    const sealed = await encryptSecret(env, "smtp", PASSWORD);
    env.DB.prepare("UPDATE smtp_settings SET smtp_url = ?, smtp_password = ? WHERE id = 1").bind("smtps://ann%40diffinery.example@smtp.example", sealed).run();
    const r = await deliver(env, job);
    expect(r.status).toBe("sent");
    expect(f.commands).toContain("AUTH PLAIN " + b64(`\u0000ann@diffinery.example\u0000${PASSWORD}`));
    expect(log()[0]).toMatchObject({ status: "sent", to_addr: "ann@example.com" });
  });

  it("suppresses an address the server says doesn't exist", async () => {
    server({ reply: { RCPT: "550 5.1.1 User unknown" } });
    const { env, log } = setup();
    expect(await deliver(env, job)).toEqual({ status: "failed", detail: "E_SMTP_RECIPIENT_REJECTED: SMTP RCPT TO: 550 5.1.1 User unknown" });
    expect(await new Suppressions(env.DB).get("ann@example.com")).toMatchObject({ reason: "hard-bounce", source: "send", detail: "The SMTP server refused it: E_SMTP_RECIPIENT_REJECTED: SMTP RCPT TO: 550 5.1.1 User unknown" });
    expect(log()[0]).toMatchObject({ status: "failed" });
  });

  it("retries a temporary failure, and suppresses nothing", async () => {
    server({ reply: { MAIL: "421 4.7.0 Try again later" } });
    const { env, log } = setup();
    await expect(deliver(env, job)).rejects.toBeInstanceOf(RetryableMailError);
    expect(await new Suppressions(env.DB).get("ann@example.com")).toBeNull();
    expect(log()).toEqual([]);
  });

  it("fails a wrong password without suppressing the recipient or logging the password", async () => {
    server({ reply: { AUTH: "535 5.7.8 Authentication credentials invalid" } });
    const errors = vi.spyOn(console, "error").mockImplementation(() => {});
    const { env, log } = setup();
    expect((await deliver(env, job)).status).toBe("failed");
    expect(await new Suppressions(env.DB).get("ann@example.com")).toBeNull();
    const logged = JSON.stringify([errors.mock.calls, log()]);
    expect(logged).toContain("535 5.7.8");
    for (const secret of [PASSWORD, b64(PASSWORD), b64(`\0ann@diffinery.example\0${PASSWORD}`)]) expect(logged).not.toContain(secret);
  });

  it("fails without connecting when SMTP_URL can't be used", async () => {
    const f = server();
    vi.spyOn(console, "error").mockImplementation(() => {});
    const { env } = setup({ SMTP_URL: "smtps://ann:pw@smtp.example" });
    expect(await deliver(env, job)).toEqual({ status: "failed", detail: "E_SMTP_CONFIG: the password goes in the SMTP_PASSWORD secret, not in SMTP_URL" });
    expect(f.connects).toEqual([]);
  });

  it("skips when neither EMAIL nor SMTP_URL is set", async () => {
    const { env, log } = setup({});
    expect(await deliver(env, job)).toEqual({ status: "skipped", detail: "no EMAIL binding or SMTP server" });
    expect(log()[0]).toMatchObject({ status: "skipped", detail: "email sending is not configured (no EMAIL binding or SMTP server)" });
  });
});

describe("SMTP on Settings → Site administration → Email", () => {
  const at = "2026-10-01T00:00:00.000Z";
  const LOCAL = "http://localhost:8787";
  const ctx = { waitUntil() {}, passThroughOnException() {}, props: {} } as unknown as ExecutionContext;

  function setup() {
    const DB = testD1();
    DB.sqlite.prepare("INSERT INTO accounts (id, login, kind, email, status, site_admin, created_at) VALUES ('u-root', 'root', 'user', 'root@example.com', 'active', 1, ?)").run(at);
    const env = { DB, PUBLIC_URL: LOCAL, DEV_AUTH: "root@example.com", MASTER_KEY: MASTER } as unknown as Env;
    const token = "csrf-token-for-the-smtp-form-1";
    const form = (fields: Record<string, string>) => {
      const body = new URLSearchParams({ ...fields, _csrf: token }).toString();
      return app.fetch(new Request(`${LOCAL}/settings/admin/email/smtp`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", "content-length": String(body.length), accept: "text/html", cookie: `dfy_csrf=${token}` }, body }), env, ctx);
    };
    const get = () => app.fetch(new Request(`${LOCAL}/settings/admin/email`, { headers: { accept: "text/html" } }), env, ctx);
    return { env, DB, form, get };
  }

  it("saves a server and seals the password: it wins over SMTP_URL, and an empty password keeps it", async () => {
    const s = setup();
    expect((await s.form({ smtp_url: "smtps://ann%40diffinery.example@smtp.example", smtp_password: PASSWORD })).status).toBe(303);
    const saved = await readSmtpSettings(s.env);
    expect(saved.url).toBe("smtps://ann%40diffinery.example@smtp.example");
    expect(saved.sealedPassword).toMatch(/^v2\./);
    expect(saved.sealedPassword).not.toContain(PASSWORD);
    expect(saved.updatedBy).toBe("root");
    expect(await smtpConfiguration(s.env)).toEqual({ config: implicit, source: "settings" });
    // Saving again without a password keeps the one that is saved.
    expect((await s.form({ smtp_url: "smtps://ann%40diffinery.example@smtp.example", smtp_password: "" })).status).toBe(303);
    expect(await readSmtpSettings(s.env)).toMatchObject({ sealedPassword: saved.sealedPassword });
    expect(await smtpConfiguration(s.env)).toEqual({ config: implicit, source: "settings" });
    // The page says where the server comes from.
    const html = await (await s.get()).text();
    expect(html).toContain('name="smtp_url"');
    expect(html).toContain("set here");
  });

  it("refuses a password in the URL, and saves nothing", async () => {
    const s = setup();
    expect((await s.form({ smtp_url: "smtps://ann:pw@smtp.example", smtp_password: "" })).status).toBe(303);
    expect(await readSmtpSettings(s.env)).toMatchObject({ url: null });
    expect(await smtpConfiguration(s.env)).toBeNull();
  });

  it("a relay that takes no user drops the saved password, so the pair stays usable", async () => {
    const s = setup();
    await s.form({ smtp_url: "smtps://ann%40diffinery.example@smtp.example", smtp_password: PASSWORD });
    expect(await readSmtpSettings(s.env)).toMatchObject({ sealedPassword: expect.any(String) });
    expect((await s.form({ smtp_url: "smtps://relay.example:2465", smtp_password: "" })).status).toBe(303);
    expect(await readSmtpSettings(s.env)).toMatchObject({ url: "smtps://relay.example:2465", sealedPassword: null });
    expect(await smtpConfiguration(s.env)).toEqual({ config: { host: "relay.example", port: 2465, tls: "implicit", user: null, password: null }, source: "settings" });
  });

  it("without MASTER_KEY the form says the password can't be stored and saves nothing", async () => {
    const DB = testD1();
    DB.sqlite.prepare("INSERT INTO accounts (id, login, kind, email, status, site_admin, created_at) VALUES ('u-root', 'root', 'user', 'root@example.com', 'active', 1, ?)").run(at);
    const env = { DB, PUBLIC_URL: LOCAL, DEV_AUTH: "root@example.com" } as unknown as Env;
    const token = "csrf-token-for-the-smtp-form-2";
    const body = new URLSearchParams({ smtp_url: "smtps://ann%40diffinery.example@smtp.example", smtp_password: PASSWORD, _csrf: token }).toString();
    const r = await app.fetch(new Request(`${LOCAL}/settings/admin/email/smtp`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", "content-length": String(body.length), accept: "text/html", cookie: `dfy_csrf=${token}` }, body }), env, ctx);
    // The setup's fault, not a bare 500 (act() rethrows 5xx, so the page is an error page).
    expect(r.status).toBe(503);
    expect(await readSmtpSettings(env)).toMatchObject({ url: null, sealedPassword: null });
  });

  it("an empty server falls back to SMTP_URL, and the audit log records both changes", async () => {
    const s = setup();
    await s.form({ smtp_url: "smtps://ann%40diffinery.example@smtp.example", smtp_password: PASSWORD });
    await s.form({ smtp_url: "", smtp_password: "" });
    expect(await readSmtpSettings(s.env)).toMatchObject({ url: null, sealedPassword: null });
    expect(s.DB.sqlite.prepare("SELECT action FROM audit_log ORDER BY rowid").all()).toEqual([{ action: "email.smtp.update" }, { action: "email.smtp.update" }]);
    // Never the password, and never a URL that carries one.
    const details = s.DB.sqlite.prepare("SELECT detail FROM audit_log ORDER BY rowid").all() as Array<{ detail: string }>;
    for (const d of details) expect(d.detail).not.toContain("hunter2");
  });
});
