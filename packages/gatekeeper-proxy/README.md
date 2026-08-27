# Gatekeeper Proxy

This package exposes explicitly configured HTTP services as `proxy://<service>` Gatekeeper
resources. It is auto-provisioned, so no credential connection flow is needed; the service list is
the capability boundary.

## Configuration

`deployment.jsonc` supplies the non-secret `gatekeeperProxy.services` map. The deploy script writes
it to the Worker's `PROXY_SERVICES` variable. Each entry has an absolute `http`/`https` `upstream`,
`via` (`public`, `tunnel`, or `vpc`), and `writeMethods` (`deny`, `approve`, or `allow`). A missing
write policy is treated as `deny` by the Worker. Upstream paths are fixed by configuration.

Public services are GET/HEAD-only unless `writeMethods: "allow"` is explicitly selected. `allow`
executes writes without an approval prompt, so use it only for an upstream where that authority is
intended. `approve` records a bounded request and applies it only after the Workshop calls
`applyAction`; `deny` returns an explicit error.

Tunnel services send Cloudflare Access client headers using `CF_ACCESS_CLIENT_ID` and
`CF_ACCESS_CLIENT_SECRET` Wrangler secrets by default. Override those names with `auth` variable
names. VPC services use the configured `binding`, or `SERVICE_<SERVICE>` when omitted. No tunnel
secret or forbidden header is returned to the caller.

All paths, headers, bodies, and responses are bounded and validated. The Worker rejects traversal,
host substitution, WebSocket/SSE streaming, forbidden credential headers, and payloads over 8 MiB.
Redirects use `redirect: "manual"` and expose a filtered `location` header unchanged.

## Local development

The package satisfies the upstream local runner's Gatekeeper discovery contract (a `gatekeeper-*`
directory containing `wrangler.jsonc`). In this starter checkout the pinned runner itself lives in
the core submodule and scans only core-owned packages; the core submodule is intentionally left
unchanged. Run the package's local contract tests directly:

```sh
pnpm install
pnpm --dir packages/gatekeeper-proxy test:run
```

For tunnel credentials, put only local values in the gitignored root `.dev.vars`; never commit
secret literals. Production secrets are installed with Wrangler, for example:

```sh
pnpm exec wrangler secret put CF_ACCESS_CLIENT_ID --name <proxy-worker-name>
pnpm exec wrangler secret put CF_ACCESS_CLIENT_SECRET --name <proxy-worker-name>
```

The proxy Worker is private behind the router in the generated deployment configs: `workers_dev`
and Preview URLs are disabled, and the router binding has no RPC entrypoint.
