import { getDB } from "../_lib/db.js";
import { json } from "../_lib/response.js";
import {
    getSessionToken,
    clearSessionCookie
} from "../_lib/auth.js";

export async function onRequestPost(context) {
    try {
        const token = getSessionToken(context.request);

        if (token) {
            const sql = getDB(context.env);

            await sql`
                DELETE FROM sessions
                WHERE token = ${token}
            `;
        }

        return json(
            {
                success: true
            },
            200,
            {
                "Set-Cookie": clearSessionCookie()
            }
        );
    } catch (error) {
        console.error("LOGOUT ERROR:", error);

        return json({
            error: "Server error"
        }, 500);
    }
}
