import { getDB } from "../_lib/db.js";
import { getBody, json } from "../_lib/response.js";
import {
    randomHex,
    hashPassword,
    createSession,
    sessionCookie
} from "../_lib/auth.js";

export async function onRequestPost(context) {
    try {
        const data = await getBody(context.request);

        if (!data) {
            return json({
                error: "Invalid request"
            }, 400);
        }

        const username = String(data.username || "")
            .trim()
            .toLowerCase();

        const password = String(data.password || "");

        if (!/^[a-z0-9_]{3,20}$/.test(username)) {
            return json({
                error: "Username must be 3-20 characters and only contain letters, numbers or _"
            }, 400);
        }

        if (password.length < 6) {
            return json({
                error: "Password must be at least 6 characters"
            }, 400);
        }

        if (password.length > 128) {
            return json({
                error: "Password is too long"
            }, 400);
        }

        const sql = getDB(context.env);

        const existing = await sql`
            SELECT username
            FROM players
            WHERE username = ${username}
            LIMIT 1
        `;

        if (existing.length) {
            return json({
                error: "That username is already taken"
            }, 409);
        }

        const salt = randomHex(16);
        const hash = await hashPassword(password, salt);

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
                hash,
                data
            )
            VALUES (
                ${username},
                ${salt},
                ${hash},
                ${JSON.stringify(freshSave)}::jsonb
            )
            RETURNING username, data
        `;

        const player = result[0];

        const token = await createSession(
            context.env,
            player.username
        );

        return json(
            {
                success: true,
                user: {
                    username: player.username,
                    data: player.data
                }
            },
            201,
            {
                "Set-Cookie": sessionCookie(token)
            }
        );
    } catch (error) {
        console.error("REGISTER ERROR:", error);

        return json({
            error: "Server error"
        }, 500);
    }
}
