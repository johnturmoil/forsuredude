import { neon } from "@neondatabase/serverless";

const SESSION_COOKIE = "basic_incremental_session";
const SESSION_DAYS = 30;
const MAX_SAVE_SIZE = 100 * 1024;

let schemaPromise = null;

const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...headers
    }
  });

const error = (message, status = 400) =>
  json({ error: message }, status);

function getSql(env) {
  if (!env.DATABASE_URL) {
    throw new Error("DATABASE_URL is not configured");
  }

  return neon(env.DATABASE_URL);
}

async function ensureSchema(sql) {
  if (!schemaPromise) {
    schemaPromise = (async () => {
      await sql`
        CREATE TABLE IF NOT EXISTS players (
          username TEXT PRIMARY KEY,
          salt TEXT NOT NULL,
          password_hash TEXT NOT NULL,
          data JSONB NOT NULL,
          created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
          updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
      `;

      await sql`
        CREATE TABLE IF NOT EXISTS sessions (
          token_hash TEXT PRIMARY KEY,
          username TEXT NOT NULL REFERENCES players(username) ON DELETE CASCADE,
          expires_at TIMESTAMPTZ NOT NULL,
          created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
      `;

      await sql`
        CREATE INDEX IF NOT EXISTS sessions_expires_idx
        ON sessions(expires_at)
      `;
    })().catch((err) => {
      schemaPromise = null;
      throw err;
    });
  }

  return schemaPromise;
}

function bytesToHex(bytes) {
  return [...new Uint8Array(bytes)]
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("");
}

function randomHex(bytes = 32) {
  const buffer = new Uint8Array(bytes);
  crypto.getRandomValues(buffer);
  return bytesToHex(buffer);
}

async function sha256(value) {
  const bytes = new TextEncoder().encode(value);
  return bytesToHex(await crypto.subtle.digest("SHA-256", bytes));
}

async function hashPassword(password, salt) {
  const passwordBytes = new TextEncoder().encode(password);
  const saltBytes = new TextEncoder().encode(salt);

  const key = await crypto.subtle.importKey(
    "raw",
    passwordBytes,
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const result = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt: saltBytes,
      iterations: 150000
    },
    key,
    256
  );

  return bytesToHex(result);
}

function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") {
    return false;
  }

  if (a.length !== b.length) {
    return false;
  }

  let result = 0;

  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }

  return result === 0;
}

function cookie(name, value, maxAge) {
  return [
    `${name}=${value}`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    `Max-Age=${maxAge}`
  ].join("; ");
}

function clearCookie(name) {
  return [
    `${name}=`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    "Max-Age=0"
  ].join("; ");
}

function getSessionToken(request) {
  const header = request.headers.get("Cookie");

  if (!header) {
    return null;
  }

  const cookies = header.split(";");

  for (const item of cookies) {
    const index = item.indexOf("=");

    if (index === -1) {
      continue;
    }

    const name = item.slice(0, index).trim();
    const value = item.slice(index + 1).trim();

    if (name === SESSION_COOKIE) {
      return value;
    }
  }

  return null;
}

async function createSession(sql, username) {
  const token = randomHex(32);
  const tokenHash = await sha256(token);

  await sql`
    DELETE FROM sessions
    WHERE expires_at < now()
  `;

  await sql`
    INSERT INTO sessions (
      token_hash,
      username,
      expires_at
    )
    VALUES (
      ${tokenHash},
      ${username},
      now() + INTERVAL '30 days'
    )
  `;

  return token;
}

async function getUser(sql, request) {
  const token = getSessionToken(request);

  if (!token) {
    return null;
  }

  const tokenHash = await sha256(token);

  const result = await sql`
    SELECT
      p.username,
      p.data
    FROM sessions s
    INNER JOIN players p
      ON p.username = s.username
    WHERE s.token_hash = ${tokenHash}
      AND s.expires_at > now()
    LIMIT 1
  `;

  return result[0] || null;
}

async function readJson(request) {
  const length = request.headers.get("Content-Length");

  if (length && Number(length) > MAX_SAVE_SIZE) {
    throw new Error("Request too large");
  }

  const text = await request.text();

  if (text.length > MAX_SAVE_SIZE) {
    throw new Error("Request too large");
  }

  try {
    return JSON.parse(text);
  } catch {
    throw new Error("Invalid JSON");
  }
}

function validateUsername(username) {
  return (
    typeof username === "string" &&
    /^[a-z0-9_]{3,20}$/.test(username)
  );
}

function validatePassword(password) {
  return (
    typeof password === "string" &&
    password.length >= 6 &&
    password.length <= 200
  );
}

async function register(request, env) {
  const body = await readJson(request);

  const username = String(body.username || "")
    .trim()
    .toLowerCase();

  const password = body.password;

  if (!validateUsername(username)) {
    return error(
      "Username must be 3 to 20 letters, numbers or underscores."
    );
  }

  if (!validatePassword(password)) {
    return error(
      "Password must be between 6 and 200 characters."
    );
  }

  const sql = getSql(env);

  await ensureSchema(sql);

  const salt = randomHex(16);
  const passwordHash = await hashPassword(password, salt);

  const freshSave = {
    v: 3,
    n: 0,
    p: 0,
    i: 0,
    c: 0,
    a: 0,
    x: 0,
    sn: {},
    l: {},
    tr: {},
    t: Date.now()
  };

  const result = await sql`
    INSERT INTO players (
      username,
      salt,
      password_hash,
      data
    )
    VALUES (
      ${username},
      ${salt},
      ${passwordHash},
      ${JSON.stringify(freshSave)}::jsonb
    )
    ON CONFLICT (username)
    DO NOTHING
    RETURNING username
  `;

  if (!result.length) {
    return error("That username is already taken.", 409);
  }

  const session = await createSession(sql, username);

  return json(
    {
      ok: true,
      username,
      data: freshSave
    },
    201,
    {
      "Set-Cookie": cookie(
        SESSION_COOKIE,
        session,
        SESSION_DAYS * 24 * 60 * 60
      )
    }
  );
}

async function login(request, env) {
  const body = await readJson(request);

  const username = String(body.username || "")
    .trim()
    .toLowerCase();

  const password = body.password;

  if (!validateUsername(username) || !validatePassword(password)) {
    return error("Wrong username or password.", 401);
  }

  const sql = getSql(env);

  await ensureSchema(sql);

  const result = await sql`
    SELECT
      username,
      salt,
      password_hash,
      data
    FROM players
    WHERE username = ${username}
    LIMIT 1
  `;

  const player = result[0];

  if (!player) {
    return error("Wrong username or password.", 401);
  }

  const passwordHash = await hashPassword(
    password,
    player.salt
  );

  if (!safeEqual(passwordHash, player.password_hash)) {
    return error("Wrong username or password.", 401);
  }

  const session = await createSession(sql, username);

  return json(
    {
      ok: true,
      username: player.username,
      data: player.data
    },
    200,
    {
      "Set-Cookie": cookie(
        SESSION_COOKIE,
        session,
        SESSION_DAYS * 24 * 60 * 60
      )
    }
  );
}

async function me(request, env) {
  const sql = getSql(env);

  await ensureSchema(sql);

  const user = await getUser(sql, request);

  if (!user) {
    return json({
      loggedIn: false
    });
  }

  return json({
    loggedIn: true,
    username: user.username,
    data: user.data
  });
}

async function save(request, env) {
  const sql = getSql(env);

  await ensureSchema(sql);

  const user = await getUser(sql, request);

  if (!user) {
    return error("Not logged in.", 401);
  }

  const body = await readJson(request);

  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return error("Invalid save data.");
  }

  body.v = 3;
  body.t = Date.now();

  await sql`
    UPDATE players
    SET
      data = ${JSON.stringify(body)}::jsonb,
      updated_at = now()
    WHERE username = ${user.username}
  `;

  return json({
    ok: true,
    savedAt: Date.now()
  });
}

async function logout(request, env) {
  const sql = getSql(env);

  await ensureSchema(sql);

  const token = getSessionToken(request);

  if (token) {
    const tokenHash = await sha256(token);

    await sql`
      DELETE FROM sessions
      WHERE token_hash = ${tokenHash}
    `;
  }

  return json(
    {
      ok: true
    },
    200,
    {
      "Set-Cookie": clearCookie(SESSION_COOKIE)
    }
  );
}

async function handleApi(request, env) {
  const url = new URL(request.url);

  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": url.origin,
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
        "Access-Control-Allow-Credentials": "true"
      }
    });
  }

  if (url.pathname === "/api/register") {
    if (request.method !== "POST") {
      return error("Method not allowed.", 405);
    }

    return register(request, env);
  }

  if (url.pathname === "/api/login") {
    if (request.method !== "POST") {
      return error("Method not allowed.", 405);
    }

    return login(request, env);
  }

  if (url.pathname === "/api/me") {
    if (request.method !== "GET") {
      return error("Method not allowed.", 405);
    }

    return me(request, env);
  }

  if (url.pathname === "/api/save") {
    if (request.method !== "POST") {
      return error("Method not allowed.", 405);
    }

    return save(request, env);
  }

  if (url.pathname === "/api/logout") {
    if (request.method !== "POST") {
      return error("Method not allowed.", 405);
    }

    return logout(request, env);
  }

  if (url.pathname === "/api/health") {
    return json({
      ok: true,
      service: "moonscripts-games-api"
    });
  }

  return error("API endpoint not found.", 404);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    try {
      if (url.pathname.startsWith("/api/")) {
        return await handleApi(request, env);
      }

      return env.ASSETS.fetch(request);
    } catch (err) {
      console.error(err);

      if (url.pathname.startsWith("/api/")) {
        return error(
          err?.message || "Internal server error.",
          500
        );
      }

      return new Response("Internal server error.", {
        status: 500
      });
    }
  }
};
