export function json(data, status = 200, extraHeaders = {}) {
    return new Response(JSON.stringify(data), {
        status,
        headers: {
            "Content-Type": "application/json",
            ...extraHeaders
        }
    });
}

export async function getBody(request) {
    try {
        return await request.json();
    } catch {
        return null;
    }
}
