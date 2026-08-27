const TYPES_CODE = `/** Bytes sent to or returned from the configured upstream. */
export type ProxyBody = string | { base64: string };

/** A request to a configured proxy service. The path is always service-relative. */
export type ProxyRequest = {
  path: string;
  method: string;
  headers?: Record<string, string>;
  body?: ProxyBody;
};

/** A bounded upstream response. Sensitive transport headers are omitted. */
export type ProxyResponse = {
  status: number;
  headers: Record<string, string>;
  body: ProxyBody;
  queuedActionId?: number;
};

/** Capability for one configured service. */
export interface ProxySession {
  /** Send a request to this service. GET/HEAD are observations; writes follow its policy. */
  request(request: ProxyRequest): Promise<ProxyResponse>;
}
`;

export default TYPES_CODE;
