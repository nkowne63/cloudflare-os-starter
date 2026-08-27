import { describe, expect, it, vi } from "vitest";
import {
  MAX_BODY_BYTES,
  ProxySessionImpl,
  parseProxyServices,
  resolveProxyResource,
} from "../src/proxy.js";

const serviceJson = JSON.stringify({
  esm: { upstream: "https://esm.sh", via: "public", writeMethods: "deny" },
  grafana: { upstream: "https://grafana.example.com/api", via: "public", writeMethods: "allow" },
});

function queue() {
  return {
    observations: [] as unknown[],
    actions: [] as unknown[],
    async authorizeObservation(value: unknown) { this.observations.push(value); },
    async submitAction(action: number, description: unknown) {
      this.actions.push({ action, description });
    },
  };
}

describe("proxy service configuration and resources", () => {
  it("accepts an authHeader Wrangler variable name", () => {
    const services = parseProxyServices(JSON.stringify({
      api: { upstream: "https://api.example.com", via: "public", writeMethods: "allow", authHeader: "API_TOKEN" },
    }));
    expect(services.get("api")?.authHeader).toBe("API_TOKEN");
  });

  it("accepts exact proxy service resources and rejects path or host substitutions", () => {
    const services = parseProxyServices(serviceJson);
    expect(resolveProxyResource("proxy://esm", services).service).toBe("esm");
    expect(() => resolveProxyResource("proxy://esm/extra", services)).toThrow();
    expect(() => resolveProxyResource("proxy://unknown", services)).toThrow();
    expect(() => resolveProxyResource("proxy://*", services)).toThrow();
    expect(() => resolveProxyResource("proxy:///", services)).toThrow();
    expect(() => parseProxyServices('{"esm":{},"esm":{"upstream":"https://x"}}'))
      .toThrow(/duplicate/i);
  });

  it("rejects traversal, absolute, protocol-relative, and backslash request paths", async () => {
    const q = queue();
    const session = new ProxySessionImpl(q, { service: "esm", config: parseProxyServices(serviceJson).get("esm")! }, {
      fetch: vi.fn(),
    });
    for (const path of ["/../secret", "/%2e%2e/secret", "/./secret", "/a//b", "/a\\b", "/a%5Cb", "https://evil/", "//evil/"]) {
      await expect(session.request({ path, method: "GET" })).rejects.toThrow();
    }
  });
});

describe("proxy request policy and transport", () => {
  it("uses the authHeader secret for Authorization and ignores caller credentials", async () => {
    const fetch = vi.fn(async (_url: string, init: RequestInit) => {
      const headers = new Headers(init.headers);
      expect(headers.get("authorization")).toBe("Bearer upstream-secret");
      expect(headers.get("cookie")).toBeNull();
      expect(headers.get("host")).toBeNull();
      return new Response("ok");
    });
    const services = parseProxyServices(JSON.stringify({ api: {
      upstream: "https://api.example.com", via: "public", writeMethods: "allow", authHeader: "API_TOKEN",
    } }));
    const session = new ProxySessionImpl(queue(), { service: "api", config: services.get("api")! }, {
      fetch, env: { API_TOKEN: "Bearer upstream-secret" },
    });
    await session.request({ path: "/data", method: "GET", headers: {
      Authorization: "Bearer caller-secret", Cookie: "caller=secret", Host: "evil.example",
    } });
  });

  it("rejects an authHeader service when its Wrangler secret is unavailable", async () => {
    const services = parseProxyServices(JSON.stringify({ api: {
      upstream: "https://api.example.com", via: "public", writeMethods: "allow", authHeader: "API_TOKEN",
    } }));
    const session = new ProxySessionImpl(queue(), { service: "api", config: services.get("api")! }, { fetch: vi.fn() });
    await expect(session.request({ path: "/data", method: "GET" })).rejects.toThrow(/authHeader/i);
  });

  it("passes public GET with filtered headers and manual redirects", async () => {
    const q = queue();
    const fetch = vi.fn(async (_url: string, init: RequestInit) => {
      expect(init.redirect).toBe("manual");
      expect(new Headers(init.headers).get("accept")).toBe("application/json");
      expect(new Headers(init.headers).get("authorization")).toBeNull();
      return new Response("source", {
        status: 302,
        headers: { Location: "https://redirect.example/path", "Set-Cookie": "secret=1", "Content-Type": "text/plain" },
      });
    });
    const session = new ProxySessionImpl(q, { service: "esm", config: parseProxyServices(serviceJson).get("esm")! }, { fetch });
    await expect(session.request({
      path: "/lodash-es@4.17.21?bundle",
      method: "GET",
      headers: { Accept: "application/json", Authorization: "Bearer secret", Cookie: "secret=1" },
    })).resolves.toMatchObject({ status: 302, body: "source", headers: { location: "https://redirect.example/path" } });
    expect(q.observations).toHaveLength(1);
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it("authorizes only the first observation in a session", async () => {
    const q = queue();
    const fetch = vi.fn(async () => new Response("ok"));
    const session = new ProxySessionImpl(q, { service: "esm", config: parseProxyServices(serviceJson).get("esm")! }, { fetch });
    await session.request({ path: "/one", method: "GET" });
    await session.request({ path: "/two", method: "HEAD" });
    expect(q.observations).toHaveLength(1);
  });

  it("keeps public writes deny-by-default and never prompts for allow", async () => {
    const denied = new ProxySessionImpl(queue(), { service: "esm", config: parseProxyServices(serviceJson).get("esm")! }, { fetch: vi.fn() });
    await expect(denied.request({ path: "/write", method: "POST", body: "x" })).rejects.toThrow(/denied/i);
    const allowedQueue = queue();
    const fetch = vi.fn(async () => new Response("written", { status: 200 }));
    const allowed = new ProxySessionImpl(allowedQueue, { service: "grafana", config: parseProxyServices(serviceJson).get("grafana")! }, { fetch });
    await expect(allowed.request({ path: "/dashboards", method: "POST", body: "{}" })).resolves.toMatchObject({ status: 200 });
    expect(allowedQueue.actions).toHaveLength(0);
  });

  it("submits approve writes without applying them", async () => {
    const q = queue();
    const fetch = vi.fn(async () => new Response("must-not-run"));
    const services = parseProxyServices(JSON.stringify({ api: { upstream: "https://api.example", via: "public", writeMethods: "approve" } }));
    const session = new ProxySessionImpl(q, { service: "api", config: services.get("api")! }, { fetch, actionId: () => 7 });
    await expect(session.request({ path: "/write", method: "PUT", body: "{}" })).resolves.toMatchObject({ status: 202 });
    expect(q.actions).toHaveLength(1);
    expect(fetch).not.toHaveBeenCalled();
  });

  it("supports tunnel and VPC transfers without leaking credentials", async () => {
    const tunnelQueue = queue();
    const tunnelFetch = vi.fn(async (_url: string, init: RequestInit) => {
      const headers = new Headers(init.headers);
      expect(headers.get("CF-Access-Client-Id")).toBe("id");
      expect(headers.get("CF-Access-Client-Secret")).toBe("secret");
      return new Response("tunnel");
    });
    const tunnelServices = parseProxyServices(JSON.stringify({ private: {
      upstream: "https://private.example/base", via: "tunnel", writeMethods: "allow",
      auth: { clientIdVar: "TUNNEL_ID", clientSecretVar: "TUNNEL_SECRET" },
    } }));
    const tunnel = new ProxySessionImpl(tunnelQueue, { service: "private", config: tunnelServices.get("private")! }, {
      fetch: tunnelFetch, env: { TUNNEL_ID: "id", TUNNEL_SECRET: "secret" },
    });
    await tunnel.request({ path: "/x", method: "GET" });

    const bindingFetch = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) =>
      new Response(init?.body instanceof Uint8Array ? new TextDecoder().decode(init.body) : "vpc"));
    const vpcServices = parseProxyServices(JSON.stringify({ internal: {
      upstream: "https://ignored.example", via: "vpc", writeMethods: "allow", binding: "SERVICE_INTERNAL",
    } }));
    const vpc = new ProxySessionImpl(queue(), { service: "internal", config: vpcServices.get("internal")! }, {
      fetch,
      env: { SERVICE_INTERNAL: { fetch: bindingFetch } },
    });
    await expect(vpc.request({ path: "/x", method: "POST", body: { base64: "eA==" } })).resolves.toMatchObject({ body: "x" });
    expect(bindingFetch).toHaveBeenCalled();
  });

  it("enforces the 8 MiB body and response boundary and preserves base64 bodies", async () => {
    const q = queue();
    const fetch = vi.fn(async (_url: string, init: RequestInit) => {
      expect(new Uint8Array(await new Response(init.body).arrayBuffer())).toHaveLength(MAX_BODY_BYTES);
      return new Response(new Uint8Array([0, 255, 1]), { headers: { "content-type": "application/octet-stream" } });
    });
    const session = new ProxySessionImpl(q, { service: "grafana", config: parseProxyServices(serviceJson).get("grafana")! }, { fetch });
    await expect(session.request({ path: "/upload", method: "POST", body: { base64: btoa("x".repeat(MAX_BODY_BYTES)) } })).resolves.toMatchObject({ body: { base64: "AP8B" } });
    await expect(session.request({ path: "/upload", method: "POST", body: "x".repeat(MAX_BODY_BYTES + 1) })).rejects.toThrow(/8 MiB/i);
    const oversizedResponse = new ProxySessionImpl(q, { service: "grafana", config: parseProxyServices(serviceJson).get("grafana")! }, {
      fetch: vi.fn(async () => new Response("x", { headers: { "content-length": String(MAX_BODY_BYTES + 1) } })),
    });
    await expect(oversizedResponse.request({ path: "/download", method: "GET" })).rejects.toThrow(/8 MiB/i);
  });
});
