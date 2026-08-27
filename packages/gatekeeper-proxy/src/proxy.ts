import { DurableObject, RpcStub, RpcTarget, WorkerEntrypoint } from "cloudflare:workers";
import { skipRpcValidation, validateRpc } from "capnweb-validate";
import type {
  AccountDescription,
  ActionDescription,
  ApprovalQueue,
  Gatekeeper,
  GatekeeperConnectCallback,
  GatekeeperConnectOptions,
  GatekeeperUser as GatekeeperUserContract,
  GatekeeperUserVerifier,
  ResourceConfiguratorFrame,
  ResourceConfiguratorIframe,
  ResourceDescription,
  SupportedResource,
  VendorDescription,
} from "@gadgets/workshop-shared/gatekeeper";
import TYPES_CODE from "./types-code.js";
import type { ProxyBody, ProxyRequest, ProxyResponse, ProxySession } from "./types.js";

export const MAX_BODY_BYTES = 8 * 1024 * 1024;

const REQUEST_HEADERS = new Set([
  "accept", "accept-encoding", "cache-control", "content-type", "if-match",
  "if-modified-since", "if-none-match", "range", "user-agent",
]);
const RESPONSE_HEADERS = new Set([
  "cache-control", "content-encoding", "content-language", "content-length", "content-range",
  "content-type", "etag", "last-modified", "location", "retry-after", "vary", "www-authenticate",
]);
const SECRET_HEADERS = new Set(["authorization", "cookie", "host", "set-cookie"]);
const SERVICE_NAME = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const ENV_NAME = /^[A-Z][A-Z0-9_]{0,127}$/;
const METHOD = /^[A-Z][A-Z0-9!#$%&'*+.^_`|~-]*$/;

export type ProxyServiceConfig = {
  upstream: string;
  via: "public" | "tunnel" | "vpc";
  writeMethods: "deny" | "approve" | "allow";
  binding?: string;
  authHeader?: string;
  auth?: { clientIdVar?: string; clientSecretVar?: string };
};

export type ProxyServices = Map<string, ProxyServiceConfig>;

/** Safe built-in configuration used by local Wrangler development. Deployments may replace it. */
export const DEFAULT_PROXY_SERVICES: ProxyServices = new Map([
  ["esm", { upstream: "https://esm.sh", via: "public", writeMethods: "deny" }],
]);

function skipWhitespace(source: string, offset: number): number {
  while (/\s/.test(source[offset] ?? "")) offset++;
  return offset;
}

function scanString(source: string, offset: number): number {
  if (source[offset] !== '"') throw new Error("Expected JSON string.");
  offset++;
  while (offset < source.length) {
    if (source[offset] === "\\") offset += 2;
    else if (source[offset++] === '"') return offset;
  }
  throw new Error("Unterminated JSON string.");
}

function skipJsonValue(source: string, offset: number): number {
  offset = skipWhitespace(source, offset);
  if (source[offset] === '"') return scanString(source, offset);
  if (source[offset] === "{" || source[offset] === "[") {
    const stack = [source[offset] === "{" ? "}" : "]"];
    offset++;
    while (stack.length && offset < source.length) {
      if (source[offset] === '"') {
        offset = scanString(source, offset);
        continue;
      }
      if (source[offset] === "{" || source[offset] === "[") {
        stack.push(source[offset] === "{" ? "}" : "]");
      } else if (source[offset] === stack.at(-1)) {
        stack.pop();
      }
      offset++;
    }
    if (stack.length) throw new Error("Malformed JSON value.");
    return offset;
  }
  while (offset < source.length && !",}".includes(source[offset])) offset++;
  return offset;
}

function topLevelKeys(source: string): string[] {
  const keys: string[] = [];
  let offset = skipWhitespace(source, 0);
  if (source[offset++] !== "{") throw new Error("PROXY_SERVICES must be a JSON object.");
  while (true) {
    offset = skipWhitespace(source, offset);
    if (source[offset] === "}") return keys;
    const end = scanString(source, offset);
    keys.push(JSON.parse(source.slice(offset, end)) as string);
    offset = skipWhitespace(source, end);
    if (source[offset++] !== ":") throw new Error("Malformed service definition.");
    offset = skipJsonValue(source, offset);
    offset = skipWhitespace(source, offset);
    if (source[offset] === ",") offset++;
    else if (source[offset] === "}") return keys;
    else throw new Error("Malformed PROXY_SERVICES JSON.");
  }
}

function parseUpstream(value: unknown): string {
  if (typeof value !== "string" || !value) throw new Error("upstream must be an absolute HTTP(S) URL.");
  let parsed: URL;
  try { parsed = new URL(value); } catch { throw new Error("upstream must be an absolute HTTP(S) URL."); }
  if (!["http:", "https:"].includes(parsed.protocol) || !parsed.hostname ||
      parsed.username || parsed.password || parsed.search || parsed.hash) {
    throw new Error("upstream must be an absolute HTTP(S) URL without credentials, query, or fragment.");
  }
  return parsed.toString().replace(/\/$/, "");
}

function parseService(name: string, value: unknown): ProxyServiceConfig {
  if (!SERVICE_NAME.test(name) || name === "*" || !value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`Malformed proxy service: ${name || "(empty)"}`);
  }
  const record = value as Record<string, unknown>;
  const allowed = new Set(["upstream", "via", "writeMethods", "binding", "authHeader", "auth"]);
  if (Object.keys(record).some(key => !allowed.has(key))) throw new Error(`Unknown proxy service field: ${name}`);
  if (record.via !== "public" && record.via !== "tunnel" && record.via !== "vpc") {
    throw new Error(`Invalid via for proxy service: ${name}`);
  }
  const writeMethods = record.writeMethods ?? "deny";
  if (writeMethods !== "deny" && writeMethods !== "approve" && writeMethods !== "allow") {
    throw new Error(`Invalid writeMethods for proxy service: ${name}`);
  }
  if (record.binding !== undefined && (typeof record.binding !== "string" || !ENV_NAME.test(record.binding))) {
    throw new Error(`Invalid binding for proxy service: ${name}`);
  }
  if (record.via !== "vpc" && record.binding !== undefined) throw new Error(`binding is only valid for vpc service: ${name}`);
  if (record.authHeader !== undefined && (typeof record.authHeader !== "string" || !ENV_NAME.test(record.authHeader))) throw new Error(`Invalid authHeader variable for proxy service: ${name}`);
  let auth: ProxyServiceConfig["auth"];
  if (record.auth !== undefined) {
    if (record.via !== "tunnel" || !record.auth || typeof record.auth !== "object" || Array.isArray(record.auth)) {
      throw new Error(`Invalid auth for proxy service: ${name}`);
    }
    const authRecord = record.auth as Record<string, unknown>;
    if (Object.keys(authRecord).some(key => key !== "clientIdVar" && key !== "clientSecretVar") ||
        ["clientIdVar", "clientSecretVar"].some(key => authRecord[key] !== undefined &&
          (typeof authRecord[key] !== "string" || !ENV_NAME.test(authRecord[key] as string)))) {
      throw new Error(`Invalid auth variables for proxy service: ${name}`);
    }
    auth = {
      clientIdVar: authRecord.clientIdVar as string | undefined,
      clientSecretVar: authRecord.clientSecretVar as string | undefined,
    };
  }
  return {
    upstream: parseUpstream(record.upstream),
    via: record.via,
    writeMethods,
    ...(record.binding ? { binding: record.binding as string } : {}),
    ...(record.authHeader ? { authHeader: record.authHeader as string } : {}),
    ...(auth ? { auth } : {}),
  };
}

/** Parse and strictly validate the JSON configuration supplied in PROXY_SERVICES. */
export function parseProxyServices(raw: string | unknown): ProxyServices {
  if (typeof raw !== "string") throw new Error("PROXY_SERVICES must be a JSON object string.");
  let parsed: unknown;
  try { parsed = JSON.parse(raw); } catch { throw new Error("PROXY_SERVICES is malformed JSON."); }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("PROXY_SERVICES must be a JSON object.");
  const keys = topLevelKeys(raw);
  if (new Set(keys).size !== keys.length) throw new Error("Duplicate proxy service name.");
  const result: ProxyServices = new Map();
  for (const name of keys) result.set(name, parseService(name, (parsed as Record<string, unknown>)[name]));
  if (!result.size) throw new Error("PROXY_SERVICES must define at least one service.");
  return result;
}

/** Resolve only an exact proxy://service resource URL. */
export function resolveProxyResource(resourceUrl: string, services: ProxyServices): { service: string; config: ProxyServiceConfig } {
  if (typeof resourceUrl !== "string" || !resourceUrl.startsWith("proxy://")) throw new Error("Resource must be proxy://<service>.");
  const service = resourceUrl.slice("proxy://".length);
  if (!SERVICE_NAME.test(service) || service === "*" || resourceUrl !== `proxy://${service}`) {
    throw new Error("Proxy resource URL must contain exactly one configured service name.");
  }
  const config = services.get(service);
  if (!config) throw new Error(`Unknown proxy service: ${service}`);
  return { service, config };
}

function decodeBody(body: ProxyBody | undefined): Uint8Array {
  if (body === undefined) return new Uint8Array();
  if (typeof body === "string") {
    const bytes = new TextEncoder().encode(body);
    if (bytes.byteLength > MAX_BODY_BYTES) throw new Error("Request body exceeds 8 MiB.");
    return bytes;
  }
  if (!body || typeof body !== "object" || typeof body.base64 !== "string") throw new Error("Body must be a string or {base64}.");
  let binary: string;
  try { binary = atob(body.base64); } catch { throw new Error("Body base64 is malformed."); }
  const bytes = Uint8Array.from(binary, char => char.charCodeAt(0));
  if (bytes.byteLength > MAX_BODY_BYTES) throw new Error("Request body exceeds 8 MiB.");
  return bytes;
}

function filterHeaders(input: HeadersInit | undefined, allowed: Set<string>): Record<string, string> {
  const result: Record<string, string> = {};
  if (!input) return result;
  const headers = new Headers(input);
  for (const [rawName, value] of headers) {
    const name = rawName.toLowerCase();
    if (!SECRET_HEADERS.has(name) && allowed.has(name)) result[name] = value;
  }
  return result;
}

function checkedPath(path: string): string {
  if (typeof path !== "string" || !path.startsWith("/") || path.startsWith("//") || path.includes("\\") || /^[a-z][a-z\d+.-]*:/i.test(path)) {
    throw new Error("Request path must be an absolute service-relative path.");
  }
  let parsed: URL;
  try { parsed = new URL(path, "https://proxy.invalid"); } catch { throw new Error("Malformed request path."); }
  if (parsed.hash) throw new Error("Request path must not contain a fragment.");
  let pathname: string;
  try { pathname = decodeURIComponent(parsed.pathname); } catch { throw new Error("Request path has malformed escaping."); }
  if (!pathname.startsWith("/") || pathname !== "/" && pathname.includes("//") || pathname.includes("\\") ||
      pathname.split("/").some(segment => segment === "." || segment === "..") ||
      pathname.includes("?") || pathname.includes("#")) {
    throw new Error("Request path contains unsafe traversal or empty segments.");
  }
  return pathname + parsed.search;
}

function joinUpstream(upstream: string, path: string): string {
  const base = new URL(upstream);
  const basePath = base.pathname.replace(/\/+$/, "");
  const parsedPath = new URL(path, "https://proxy.invalid");
  return `${base.origin}${basePath}${parsedPath.pathname}${parsedPath.search}`;
}

function encodeBody(bytes: Uint8Array, contentType: string | null): ProxyBody {
  if (!bytes.byteLength) return "";
  try {
    const text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(bytes);
    if (!contentType || /(?:text\/|json|javascript|xml|svg|form-urlencoded)/i.test(contentType)) return text;
  } catch { /* binary response */ }
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return { base64: btoa(binary) };
}

type QueueLike = Pick<ApprovalQueue, "authorizeObservation" | "submitAction"> & Partial<{ [Symbol.dispose](): void }>;
type ProxyEnv = Cloudflare.Env & Record<string, unknown>;
type ProxyTransport = {
  fetch: typeof fetch;
  env?: Record<string, unknown>;
  actionId?: () => number;
  stageAction?: (id: number, request: ProxyRequest) => void;
  discardAction?: (id: number) => void;
};
type BoundRequest = { service: string; config: ProxyServiceConfig; request: ProxyRequest };

function methodOf(method: string): string {
  if (typeof method !== "string") throw new Error("HTTP method is required.");
  const normalized = method.toUpperCase();
  if (!METHOD.test(normalized)) throw new Error("Invalid HTTP method.");
  return normalized;
}

/** RPC session implementation; exported to keep policy and transport tests independent of workerd. */
@validateRpc()
export class ProxySessionImpl extends RpcTarget implements ProxySession {
  #queue: QueueLike;
  #bound: Omit<BoundRequest, "request">;
  #transport: ProxyTransport;
  #observed = false;

  constructor(queue: QueueLike, bound: Omit<BoundRequest, "request">, transport: ProxyTransport) {
    super(); this.#queue = queue; this.#bound = bound; this.#transport = transport;
  }

  async request(request: ProxyRequest): Promise<ProxyResponse> {
    const normalized: ProxyRequest = { ...request, path: checkedPath(request.path), method: methodOf(request.method) };
    decodeBody(normalized.body);
    const isRead = normalized.method === "GET" || normalized.method === "HEAD";
    if (isRead) {
      if (!this.#observed) {
        await this.#queue.authorizeObservation({
          title: `Read proxy service ${this.#bound.service}`,
          description: `Read ${normalized.method} ${normalized.path} from the configured proxy service.`,
        });
        this.#observed = true;
      }
    } else if (this.#bound.config.writeMethods === "deny") {
      throw new Error(`Write method ${normalized.method} is denied for proxy service ${this.#bound.service}.`);
    } else if (this.#bound.config.writeMethods === "approve") {
      const actionId = this.#transport.actionId?.() ?? Date.now();
      this.#transport.stageAction?.(actionId, normalized);
      const description: ActionDescription = {
        title: `Proxy ${normalized.method} ${normalized.path}`,
        description: `Send ${normalized.method} request to the configured ${this.#bound.service} proxy service.`,
        implementsRevert: false,
      };
      try {
        await this.#queue.submitAction(actionId, description);
      } catch (error) {
        this.#transport.discardAction?.(actionId);
        throw error;
      }
      return { status: 202, headers: {}, body: "", queuedActionId: actionId };
    }
    return this.#execute(normalized);
  }

  async #execute(request: ProxyRequest): Promise<ProxyResponse> {
    return executeProxyRequest(this.#bound, request, this.#transport);
  }

  [Symbol.dispose](): void { this.#queue[Symbol.dispose]?.(); }
}

async function executeProxyRequest(
  bound: Omit<BoundRequest, "request">,
  request: ProxyRequest,
  transport: ProxyTransport,
): Promise<ProxyResponse> {
    const bytes = decodeBody(request.body);
    const inputHeaders = filterHeaders(request.headers, REQUEST_HEADERS);
    if (Object.keys(request.headers ?? {}).some(name => name.toLowerCase() === "upgrade")) throw new Error("WebSocket upgrades are not supported.");
    if (bound.config.via === "tunnel") {
      const env = transport.env ?? {};
      const idName = bound.config.auth?.clientIdVar ?? "CF_ACCESS_CLIENT_ID";
      const secretName = bound.config.auth?.clientSecretVar ?? "CF_ACCESS_CLIENT_SECRET";
      const clientId = env[idName];
      const clientSecret = env[secretName];
      if (typeof clientId !== "string" || typeof clientSecret !== "string" || !clientId || !clientSecret) throw new Error("Tunnel Access credentials are not configured.");
      inputHeaders["cf-access-client-id"] = clientId;
      inputHeaders["cf-access-client-secret"] = clientSecret;
    }
    if (bound.config.authHeader) {
      const value = (transport.env ?? {})[bound.config.authHeader];
      if (typeof value !== "string" || !value) throw new Error("authHeader secret is not configured.");
      inputHeaders.authorization = value;
    }
    let fetcher = transport.fetch;
    if (bound.config.via === "vpc") {
      const bindingName = bound.config.binding ?? `SERVICE_${bound.service.toUpperCase().replaceAll("-", "_")}`;
      const binding = (transport.env ?? {})[bindingName] as { fetch?: typeof fetch } | undefined;
      if (!binding || typeof binding.fetch !== "function") throw new Error(`Configured VPC binding is unavailable: ${bindingName}`);
      fetcher = binding.fetch.bind(binding);
    }
    const response = await fetcher(joinUpstream(bound.config.upstream, request.path), {
      method: request.method,
      headers: inputHeaders,
      ...(bytes.byteLength && request.method !== "GET" && request.method !== "HEAD" ? { body: bytes } : {}),
      redirect: "manual",
    });
    const contentLength = Number(response.headers.get("content-length"));
    if (Number.isFinite(contentLength) && contentLength > MAX_BODY_BYTES) throw new Error("Response body exceeds 8 MiB.");
    const contentType = response.headers.get("content-type");
    if (contentType?.toLowerCase().includes("text/event-stream")) throw new Error("Streaming responses are not supported.");
    const responseBytes = response.body ? new Uint8Array(await response.arrayBuffer()) : new Uint8Array();
    if (responseBytes.byteLength > MAX_BODY_BYTES) throw new Error("Response body exceeds 8 MiB.");
    return { status: response.status, headers: filterHeaders(response.headers, RESPONSE_HEADERS), body: encodeBody(responseBytes, contentType) };
}

type ProxyGatekeeperProps = { service: string };
type StoredAction = { request: ProxyRequest; state: "pending" | "approved" | "rejected" };

@validateRpc()
export class ProxyGatekeeper extends DurableObject<ProxyEnv, ProxyGatekeeperProps> implements Gatekeeper<ProxySession> {
  #services(): ProxyServices { return parseProxyServices(this.env.PROXY_SERVICES); }
  #config(): { service: string; config: ProxyServiceConfig } {
    const service = this.ctx.props.service;
    const config = this.#services().get(service);
    if (!config) throw new Error(`Unknown proxy service: ${service}`);
    return { service, config };
  }
  #key(id: number): string { return `action:${id}`; }
  #newActionId(): number {
    const id = (this.ctx.storage.kv.get<number>("action-counter") ?? 0) + 1;
    this.ctx.storage.kv.put("action-counter", id);
    return id;
  }
  async describe(): Promise<ResourceDescription> {
    const { service } = this.#config();
    return { url: `proxy://${service}`, title: `${service} proxy`, snippet: "Configured HTTP capability.", suggestedBindingName: `PROXY_${service.toUpperCase().replaceAll("-", "_")}`, tsType: "ProxySession" };
  }
  async getTypeScriptTypes(): Promise<string> { return TYPES_CODE; }
  async getAutoApprovableActions(): Promise<[]> { return []; }
  async startSession(approvalQueue: RpcStub<ApprovalQueue>): Promise<ProxySession> {
    const bound = this.#config();
    return new ProxySessionImpl(approvalQueue.dup(), bound, {
      fetch,
      env: this.env,
      actionId: () => this.#newActionId(),
      stageAction: (id, request) => this.ctx.storage.kv.put<StoredAction>(this.#key(id), { request, state: "pending" }),
      discardAction: (id) => this.ctx.storage.kv.delete(this.#key(id)),
    });
  }
  async addObserver(_id: string, _user: Fetcher<GatekeeperUserVerifier>): Promise<void> {}
  async removeObserver(_id: string): Promise<void> {}
  async applyAction(action: number): Promise<void> {
    const record = this.ctx.storage.kv.get<StoredAction>(this.#key(action));
    if (!record || record.state !== "pending") throw new Error(`Unknown or already handled proxy action: ${action}`);
    const bound = this.#config();
    await executeProxyRequest(bound, record.request, { fetch, env: this.env });
    record.state = "approved";
    this.ctx.storage.kv.put(this.#key(action), record);
  }
  async rejectAction(action: number): Promise<void> { this.ctx.storage.kv.delete(this.#key(action)); }
  async revertAction(_action: number): Promise<void> { throw new Error("Proxy actions cannot be reverted automatically."); }
}

@validateRpc()
export class ProxyVerifier extends WorkerEntrypoint<ProxyEnv> implements GatekeeperUserVerifier {
  verify(): void {}
}

@validateRpc()
export class GatekeeperUser extends WorkerEntrypoint<ProxyEnv> implements GatekeeperUserContract {
  async describe(): Promise<AccountDescription> { return { displayName: "Gatekeeper Proxy", avatar: { url: "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cpath d='M3 5h18v14H3z' fill='none' stroke='%23000'/%3E%3C/svg%3E" } }; }
  async getSupportedResources(): Promise<SupportedResource[]> {
    return [...this.#services().keys()].map(service => ({ urlPattern: `proxy://${service}`, title: `${service} proxy`, description: `HTTP access to the configured ${service} service.` }));
  }
  #services(): ProxyServices { return parseProxyServices(this.env.PROXY_SERVICES); }
  async getGatekeeperClassFor(url: string): Promise<{ class: DurableObjectClass<Gatekeeper<ProxySession>>; resource: SupportedResource }> {
    const services = this.#services();
    const resolved = resolveProxyResource(url, services);
    return { class: this.ctx.exports.ProxyGatekeeper({ props: { service: resolved.service } }), resource: { urlPattern: `proxy://${resolved.service}`, title: `${resolved.service} proxy`, description: `HTTP access to the configured ${resolved.service} service.` } };
  }
  async startResourceConfigurator(resourceUrlPattern: string): Promise<ResourceConfiguratorFrame> {
    const service = resourceUrlPattern.slice("proxy://".length);
    resolveProxyResource(`proxy://${service}`, this.#services());
    return { iframeHtml: `<html><body><p>Resource URL is <code>proxy://${service}</code>.</p></body></html>`, ui: new ProxyConfigurator(service) as unknown as RpcStub<RpcTarget> };
  }
  async revoke(): Promise<void> {}
  async reconnect(): Promise<{ url: string }> { throw new Error("Gatekeeper Proxy has no credentials to reconnect."); }
  async getAuthenticatedEmail(): Promise<string | null> { return null; }
  async ensureResources(_resourceUrlPatterns: string[]): Promise<{ url?: string }> { return {}; }
  @skipRpcValidation()
  async getVerifier(): Promise<Fetcher<GatekeeperUserVerifier>> { return this.ctx.exports.ProxyVerifier({}); }
}

@validateRpc()
class ProxyConfigurator extends RpcTarget implements ResourceConfiguratorIframe {
  #service: string;
  constructor(service: string) { super(); this.#service = service; }
  async collectResourceUrl(): Promise<string> { return `proxy://${this.#service}`; }
  updateViewport(_iframeTop: number, _viewportHeight: number): void {}
  windowResized(): void {}
}

export const PROXY_VENDOR: VendorDescription = {
  displayName: "Gatekeeper Proxy",
  url: "https://github.com/cloudflare/cloudflare-os-starter",
  tagline: "Controlled HTTP access to configured services",
  description: "Proxy selected HTTP services through Cloudflare OS with explicit path, header, size, and write policies.",
  autoProvisionsAccount: true,
};

@validateRpc()
export class GatekeeperVendor extends WorkerEntrypoint<ProxyEnv> {
  async describe(): Promise<VendorDescription> { return PROXY_VENDOR; }
  @skipRpcValidation()
  async createAccount(): Promise<Fetcher<GatekeeperUserContract>> { return this.ctx.exports.GatekeeperUser({}); }
  connectAccount(_callback: Fetcher<GatekeeperConnectCallback>, _options?: GatekeeperConnectOptions): Promise<{ url: string }> {
    throw new Error("Gatekeeper Proxy is auto-provisioned and has no connect flow.");
  }
  async getSupportedResources(): Promise<SupportedResource[]> { return [...this.#services().keys()].map(service => ({ urlPattern: `proxy://${service}`, title: `${service} proxy`, description: `HTTP access to the configured ${service} service.` })); }
  async getTypeScriptTypes(): Promise<string> { return TYPES_CODE; }
  #services(): ProxyServices { return parseProxyServices(this.env.PROXY_SERVICES); }
}

/** Compatibility aliases for the standard Gatekeeper role names. */
export { GatekeeperUser as Account };
export type { ProxySession as Session };
