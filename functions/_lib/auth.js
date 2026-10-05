import { getDB } from "./db.js";

const SESSION_MAX_AGE = 60 * 60 * 24 * 30;

function bytesToHex(bytes) {
    return [...new Uint8Array(bytes)]
        .map(byte => byte.toString(16).padStart(2, "0"))
        .join("");
}

function hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);

    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }

    return bytes;
}

function equalHex(a, b) {
    if (typeof a !== "string" || typeof b !== "string") {
        return false;
    }

    if (a.length !== b.length) {
        return false;
    }

    const aa = hexToBytes(a);
    const bb = hexToBytes(b);

    let difference = 0;

    for (let i = 0; i < aa.length; i++) {
        difference |= aa[i] ^ bb[i];
    }

    return difference === 0;
}

export function randomHex(length) {
    const bytes = new Uint8Array(length);
    crypto.getRandomValues(bytes);
    return bytesToHex(bytes);
}

export async function hashPassword(password, salt) {
    const encoder = new TextEncoder();

    const key = await crypto.subtle.importKey(
        "raw",
        encoder.encode(password),
        "PBKDF2",
        false,
        ["deriveBits"]
    );

    const bits = await crypto.subtle.deriveBits(
        {
            name: "PBKDF2",
            hash: "SHA-256",
            salt: encoder.encode(salt),
            iterations: 100000
        },
        key,
        256
    );

    return bytesToHex(bits);
}

export async function createSession(env, username) {
    const sql = getDB(env);

    const token = randomHex(32);

    await sql`
        INSERT INTO sessions (
            token,
            username,
            expires_at
        )
        VALUES (
            ${token},
            ${username},
            NOW() + INTERVAL '30 days'
        )
    `;

    return token;
}

export function getSessionToken(request) {
    const cookie = request.headers.get("Cookie") || "";

    const cookies = cookie.split(";");

    for (const item of cookies) {
        const value = item.trim();

        if (value.startsWith("session=")) {
            return value.slice("session=".length);
        }
    }

    return null;
}

export function sessionCookie(token) {
    return [
        `session=${token}`,
        "Path=/",
        "HttpOnly",
        "Secure",
        "SameSite=Lax",
        `Max-Age=${SESSION_MAX_AGE}`
    ].join("; ");
}

export function clearSessionCookie() {
    return [
        "session=",
        "Path=/",
        "HttpOnly",
        "Secure",
        "SameSite=Lax",
        "Max-Age=0"
    ].join("; ");
}

export async function getPlayer(request, env) {
    const token = getSessionToken(request);

    if (!token) {
        return null;
    }

    const sql = getDB(env);

    const result = await sql`
        SELECT
            p.username,
            p.data
        FROM sessions s
        INNER JOIN players p
            ON p.username = s.username
        WHERE s.token = ${token}
        AND s.expires_at > NOW()
        LIMIT 1
    `;

    return result[0] || null;
}

export async function verifyPassword(password, salt, expectedHash) {
    const actualHash = await hashPassword(password, salt);
    return equalHex(actualHash, expectedHash);
}
