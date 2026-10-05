import { json } from "../_lib/response.js";
import { getPlayer } from "../_lib/auth.js";

export async function onRequestGet(context) {
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

        return json({
            success: true,
            data: player.data
        });
    } catch (error) {
        console.error("LOAD ERROR:", error);

        return json({
            error: "Server error"
        }, 500);
    }
}
