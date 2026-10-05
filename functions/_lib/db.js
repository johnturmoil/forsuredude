import { neon } from "@neondatabase/serverless";

export function getDB(env) {
    if (!env.DATABASE_URL) {
        throw new Error("DATABASE_URL is not configured");
    }

    return neon(env.DATABASE_URL);
}
