// Corbel's door. Every request under /corbel/ (pages, the test portfolio,
// everything) needs a Corbel session. A session comes only from a single-use
// pass that CARL issues after Face ID, to a person the owner has given Corbel.
// Only hashes of passes and sessions are stored, in CARL's D1 database.
//
//   /corbel/_auth?t=PASS&r=/corbel/x   CARL sends the person here with a pass
//   /corbel/_signout                     ends this Corbel session
//   anything else under /corbel/         needs a live session, else -> CARL
//
// Settings: DB (D1, CARL's records), CARL_URL (CARL's sign-in site).

const COOKIE = "corbel_session";
const SESSION_DAYS = 30;
const RENEW_AFTER_MS = 6 * 3600e3;

const sqlTime = (ms) => new Date(ms).toISOString().replace("T", " ").slice(0, 19);
const nowSql = () => sqlTime(Date.now());
const b64url = (b) => btoa(String.fromCharCode(...b)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
// Same encoding as CARL's _lib/auth.js sha256 (base64url), so hashes match.
async function sha256(text) {
  return b64url(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text))));
}
function readCookie(request, name) {
  for (const part of (request.headers.get("Cookie") || "").split(";")) {
    const [k, ...v] = part.trim().split("=");
    if (k === name) return v.join("=");
  }
  return null;
}
const cookie = (token, maxAge) =>
  `${COOKIE}=${token}; Path=/corbel; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
const safeReturn = (r) =>
  r && /^\/corbel\/[A-Za-z0-9._\-\/]*$/.test(r) && !r.includes("//") && !r.includes("..") ? r : "/corbel/";
const toCarl = (env, path) =>
  Response.redirect(`${(env.CARL_URL || "https://carl.carlcompliance.com").replace(/\/$/, "")}/auth/corbel?r=${encodeURIComponent(safeReturn(path))}`, 302);
const noStore = (resp, extra = {}) => {
  const out = new Response(resp.body, resp);
  out.headers.set("Cache-Control", "private, no-store");
  for (const [k, v] of Object.entries(extra)) out.headers.append(k, v);
  return out;
};

export async function corbelGate(request, env, serve) {
  const url = new URL(request.url);
  if (!url.pathname.startsWith("/corbel/") && url.pathname !== "/corbel") return serve();

  // CARL's pass -> a Corbel session.
  if (url.pathname === "/corbel/_auth") {
    const t = url.searchParams.get("t") || "";
    const r = safeReturn(url.searchParams.get("r"));
    if (!/^[A-Za-z0-9_-]{20,100}$/.test(t)) return toCarl(env, r);
    const hash = await sha256(t);
    // Spend the pass first, so a second use of the same pass finds nothing.
    const spent = await env.DB.prepare(
      "UPDATE corbel_passes SET used_at = ? WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?",
    ).bind(nowSql(), hash, nowSql()).run();
    if (!spent.meta || spent.meta.changes !== 1) return toCarl(env, r);
    const pass = await env.DB.prepare(
      `SELECT p.inspector_id, p.owner, i.corbel_access, i.disabled_at, o.disabled_at AS org_disabled
         FROM corbel_passes p JOIN inspectors i ON i.id = p.inspector_id
         LEFT JOIN organisations o ON o.id = i.org_id WHERE p.token_hash = ?`,
    ).bind(hash).first();
    if (!pass || pass.disabled_at || pass.org_disabled || !(pass.owner || pass.corbel_access === 1)) {
      return new Response("No access to Corbel.", { status: 403, headers: { "Cache-Control": "no-store" } });
    }
    const token = b64url(crypto.getRandomValues(new Uint8Array(32)));
    await env.DB.prepare(
      "INSERT INTO corbel_sessions (token_hash, inspector_id, owner, expires_at, last_seen_at) VALUES (?,?,?,?,?)",
    ).bind(await sha256(token), pass.inspector_id, pass.owner ? 1 : 0, sqlTime(Date.now() + SESSION_DAYS * 864e5), nowSql()).run();
    return new Response(null, {
      status: 302,
      headers: { Location: r, "Set-Cookie": cookie(token, SESSION_DAYS * 86400), "Cache-Control": "no-store" },
    });
  }

  const token = readCookie(request, COOKIE);
  const hash = token ? await sha256(token) : null;

  if (url.pathname === "/corbel/_signout") {
    if (hash) await env.DB.prepare("UPDATE corbel_sessions SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL")
      .bind(nowSql(), hash).run();
    return new Response("Signed out of Corbel.", {
      status: 200, headers: { "Set-Cookie": cookie("", 0), "Cache-Control": "no-store", "Content-Type": "text/plain; charset=utf-8" },
    });
  }

  if (!hash) return toCarl(env, url.pathname);
  // Checked on every request: the session, the person, their organisation,
  // and that they still have Corbel. Taking any of these away takes effect now.
  const s = await env.DB.prepare(
    `SELECT s.expires_at, s.last_seen_at, s.revoked_at, s.owner, i.corbel_access, i.disabled_at, o.disabled_at AS org_disabled
       FROM corbel_sessions s JOIN inspectors i ON i.id = s.inspector_id
       LEFT JOIN organisations o ON o.id = i.org_id WHERE s.token_hash = ?`,
  ).bind(hash).first();
  if (!s || s.revoked_at || s.expires_at < nowSql() || s.disabled_at || s.org_disabled || !(s.owner || s.corbel_access === 1)) {
    return noStore(toCarl(env, url.pathname), { "Set-Cookie": cookie("", 0) });
  }
  const last = s.last_seen_at ? Date.parse(s.last_seen_at.replace(" ", "T") + "Z") : 0;
  if (Date.now() - last > RENEW_AFTER_MS) {
    await env.DB.prepare("UPDATE corbel_sessions SET last_seen_at = ?, expires_at = ? WHERE token_hash = ?")
      .bind(nowSql(), sqlTime(Date.now() + SESSION_DAYS * 864e5), hash).run();
  }
  return noStore(await serve());
}
