SECURITY FINDINGS: hardikr2026-ux

FINDING 1: Forgeable session token (authentication bypass)

Severity: Critical
File / lines: src/web.js ~31-33 (makeSessionToken), ~35-42 (getUserFromRequest)
Route / feature: Every authenticated route (/dashboard, /api/*, /admin, /profile)

Evidence:
  function makeSessionToken(username) {
    return Buffer.from(`${username}:ospc-demo-session`).toString("base64url");
  }
  ...
  const username = Buffer.from(token, "base64url").toString().split(":")[0];
  return users.find(user => user.username === username) || null;

The sid cookie is only base64url("<username>:ospc-demo-session"). Base64 is encoding, not encryption, and there is no secret, signature, randomness, or expiry. The server trusts the username inside the cookie.
Local demo: set sid to the base64url of "sam:ospc-demo-session" in browser dev tools, then open /dashboard. The app greets you as Sam without a password.

Impact: Anyone who knows or guesses a username (see Finding 5) can impersonate that user with no password, which defeats authentication entirely.

Mitigation: Use long random session IDs stored server-side, or tokens signed with a secret key (HMAC/JWT), with expiry and server-side invalidation on logout.



FINDING 2: Mass assignment leading to privilege escalation

Severity: Critical
File / lines: src/server.js ~62 (Object.assign(user, changes)); role check at ~69
Route / feature: POST /api/profile, then GET /admin

Evidence:
  Object.assign(user, changes);
  ...
  if (user.role !== "admin") return send(res, 403, ...);

The profile page only advertises displayName, but the handler copies every field from the JSON body onto the user record. /admin makes its access decision from user.role, a field the user can edit.
Local demo: while signed in as a demo user, POST {"role":"admin"} to /api/profile, then open /admin. The access-denied page is replaced by the admin page with the training flag.

Impact: Any signed-in user can become admin. They can also overwrite other fields such as id, username, email, or password.

Mitigation: Allowlist editable fields (only displayName) and ignore all others. Roles should only change through a separate, authorized admin process.


FINDING 3: Broken object-level authorization (IDOR) on notes

Severity: High
File / lines: src/server.js ~41-48
Route / feature: GET /api/notes/:id

Evidence:
  const id = Number(url.pathname.split("/").pop());
  const note = notes.find(item => item.id === id);
  if (!note) return json(res, 404, { error: "note not found" });
  return json(res, 200, { id: note.id, title: note.title, body: note.body });

The route checks that a user is signed in (authentication) but never that the note belongs to them (authorization). The dashboard does filter by owner (notes.filter(note => note.owner === user.id)), but the API does not apply the same check.
Local demo: sign in as alex and open /api/notes/202, which is Sam's note.

Impact: Any signed-in user can read any other user's private notes. Note IDs are small sequential numbers, so they are easy to enumerate.

Mitigation: Compare note.owner with the session user's id on every request and return 403/404 on mismatch.



FINDING 4: Cross-site scripting (reflected and stored)

Severity: Medium
File / lines: src/server.js ~74-77 (/search), ~38 (/dashboard)
Route / feature: GET /search?q=..., /dashboard

Evidence:
  <input name="q" value="${query}">
  <h2>Results for: ${query}</h2>
  <li>${user.displayName} — ${user.email}</li>
  <h1>Hello, ${user.displayName}</h1>

User-controlled values are inserted into HTML with no output encoding. The q parameter gives reflected XSS. displayName can be changed through /api/profile (Finding 2's endpoint), so a malicious name is saved and shown to every viewer, which is stored XSS.
Local demo (harmless): search for <b>test</b>. If it renders as bold text instead of showing the tags, input is being interpreted as HTML.

Impact: Attacker-controlled script can run in a victim's browser under the app's origin. Because the session cookie has no HttpOnly flag (Finding 5), script can read it, and combined with Finding 1 this leads to account takeover.

Mitigation: HTML-escape all untrusted values in the right context (including attribute values), add a Content-Security-Policy, and set HttpOnly on the cookie.



FINDING 5: Weak credential handling and information exposure

Severity: Medium (Low if considered in isolation, since the app is local-only)
File / lines: src/data.js ~5-6; src/server.js ~28 (login check), ~30 (cookie), ~73-77 (/search)
Route / feature: POST /login, GET /search

Evidence:
  - Passwords are stored and compared in plaintext: password: "maple123" and item.password === body.get("password").
  - The cookie is set as sid=...; Path=/; SameSite=Lax, with no HttpOnly or Secure.
  - /search has no getUserFromRequest check, yet lists every user's display name and email.
  - /login has no rate limiting or lockout.

Impact: A data leak would expose every password directly. The unauthenticated directory lets anyone collect valid usernames and emails, which supports Finding 1. Missing cookie flags make XSS cookie theft possible. Unlimited login attempts allow brute force.

Mitigation: Hash passwords (bcrypt/argon2), set HttpOnly and Secure (and keep SameSite), require authentication for the directory, and add rate limiting or lockout on login.