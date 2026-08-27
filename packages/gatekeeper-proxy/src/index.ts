export * from "./proxy.js";

export default {
  async fetch(request: Request, env: Cloudflare.Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === "/health") return new Response("ok");
    return new Response("Gatekeeper Proxy worker is running.", { headers: { "content-type": "text/plain" } });
  },
};
