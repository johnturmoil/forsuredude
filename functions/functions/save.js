import { getDB } from "../_lib/db.js";
import { getBody, json } from "../_lib/response.js";
import { getPlayer } from "../_lib/auth.js";

export async function onRequestPost(context) {
    try {
        const player = await getPlayer(
            context.request,
            context.env
        );

        if (!player) {
            return json({
                error: "Not logged in"
            }, 401);
        }

        const body = await getBody(context.request);

        if (!body || typeof body.data !== "object" || body.data === null) {
            return json({
                error: "Invalid save data"
            }, 400);
        }

        const sql = getDB(context.env);

        await sql`
            UPDATE players
            SET
                data = ${JSON.stringify(body.data)}::jsonb,
                updated_at = NOW()
            WHERE username = ${player.username}
        `;

        return json({
            success: true
        });
    } catch (error) {
        console.error("SAVE ERROR:", error);

        return json({
            error: "Server error"
        }, 500);
    }
}
