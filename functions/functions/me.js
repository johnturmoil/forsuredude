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
                loggedIn: false
            });
        }

        return json({
            loggedIn: true,
            user: {
                username: player.username,
                data: player.data
            }
        });
    } catch (error) {
        console.error("ME ERROR:", error);

        return json({
            error: "Server error"
        }, 500);
    }
}
