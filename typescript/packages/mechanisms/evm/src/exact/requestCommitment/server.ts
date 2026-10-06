import type { ResourceServerExtension } from "@x402/core/types";

import {
  EVM_REQUEST_COMMITMENT,
  HEX_32,
  buildHttpBinding,
  deriveRequestNonce,
  parseNonce,
  requestDigest,
  validateBoundHeaders,
  validateTargetUri,
  type HttpRequestDescription,
} from "./binding";

/** Static route declaration (what the operator writes in the route config). */
export interface RequestCommitmentDeclarationInput {
  /** When true, a payment without a valid commitment is rejected. */
  required?: boolean;
  /**
   * Header names that affect the purchased operation, content interpretation or
   * account selection. Lowercase, strictly ascending, never `payment-signature`.
   */
  headers?: string[];
}

/** Minimal view of the HTTP request the extension needs. */
interface AdapterLike {
  getHeader(name: string): string | undefined;
  getMethod(): string;
  getUrl(): string;
  getBody?(): unknown;
}

/** Server-side configuration. */
export interface RequestCommitmentServerConfig {
  /**
   * Public origin of the protected resource, e.g. `https://api.example.com`.
   * The target URI is rebuilt from this origin and the request's path and query,
   * never from the Host header.
   */
  publicOrigin: string;
  /**
   * Returns the request's content bytes after transfer decoding, and an empty
   * array when there is no body. A parsed body cannot be hashed faithfully, so
   * without this accessor only bodiless GET and HEAD requests are accepted.
   * May be async (Hono, Next, fetch). It is called more than once per request,
   * so it must return the same bytes each time without consuming the stream.
   */
  getRawBody?: (adapter: AdapterLike) => Uint8Array | Promise<Uint8Array>;
}

/** Abort reasons surfaced by `onBeforeVerify`. */
export const REQUEST_COMMITMENT_ERRORS = {
  missing: "request_commitment_missing",
  malformed: "request_commitment_malformed",
  unsupported: "request_commitment_unsupported_transfer_method",
  mismatch: "request_commitment_mismatch",
} as const;

const JSON_SCHEMA = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  type: "object",
  properties: {
    required: { type: "boolean" },
    profile: { const: "http:1" },
    bindingParams: {
      type: "object",
      properties: { headers: { type: "array", items: { type: "string" } } },
      required: ["headers"],
    },
    requestDigest: { type: "string", pattern: "^[0-9a-f]{64}$" },
    salt: { type: "string", pattern: "^[0-9a-f]{64}$" },
  },
  required: ["required", "profile", "bindingParams"],
};

/**
 * Builds the route declaration for `extensions["evm-request-commitment"]`.
 *
 * @param input - Whether the commitment is required and which headers it binds.
 * @returns The declaration.
 */
export function declareRequestCommitmentExtension(input: RequestCommitmentDeclarationInput = {}) {
  return {
    info: {
      required: input.required ?? false,
      profile: "http:1" as const,
      bindingParams: { headers: validateBoundHeaders(input.headers ?? []) },
    },
    schema: JSON_SCHEMA,
  };
}

type Declaration = ReturnType<typeof declareRequestCommitmentExtension>;

/**
 * Pulls the HTTP adapter out of either context shape core passes around
 * (`HTTPRequestContext` or `HTTPTransportContext`).
 *
 * @param transportContext - Core's transport context.
 * @returns The adapter, if the request is HTTP.
 */
function adapterOf(transportContext: unknown): AdapterLike | undefined {
  const ctx = transportContext as { adapter?: AdapterLike; request?: { adapter?: AdapterLike } };
  return ctx?.adapter ?? ctx?.request?.adapter;
}

/** Characters an authority (host, port, IP literal) may contain. No `/`, `?`, `#`, `@`. */
const AUTHORITY = /^[A-Za-z0-9.\-:[\]_~%!$&'()*+;=]+$/;

/**
 * Lowercases an authority and drops the default port of the scheme, so a Host
 * header and a runtime-normalized URL authority compare equal.
 *
 * @param authority - Host and optional port.
 * @param scheme - `http` or `https`.
 * @returns The comparable form.
 */
function comparableAuthority(authority: string, scheme: string): string {
  const lower = authority.toLowerCase();
  const defaultPort = scheme.toLowerCase() === "https" ? ":443" : ":80";
  return lower.endsWith(defaultPort) ? lower.slice(0, -defaultPort.length) : lower;
}

/**
 * Path and query of the request as received.
 *
 * Adapters build `getUrl()` from client-influenced parts: the scheme
 * (`X-Forwarded-Proto` behind a trusted proxy), the authority (`Host` or
 * `X-Forwarded-Host`) and the request target. A crafted value in any of them
 * could move the boundary between authority and target and let the client
 * choose the path that gets checked. So the scheme must be exactly `http` or
 * `https`, the authority headers may hold only authority characters, the URL's
 * authority must be one of those headers, and the target must be in origin form.
 *
 * @param adapter - HTTP adapter.
 * @returns The path-and-query string, starting with a single `/`.
 * @throws When any input to the URL is ambiguous.
 */
function requestTarget(adapter: AdapterLike): string {
  const hosts: string[] = [];
  const host = adapter.getHeader("host");
  if (host !== undefined) hosts.push(host.trim());
  const forwardedHost = adapter.getHeader("x-forwarded-host");
  if (forwardedHost !== undefined) hosts.push(...forwardedHost.split(",").map(h => h.trim()));
  for (const value of hosts) {
    if (!AUTHORITY.test(value)) throw new Error("Ambiguous Host or X-Forwarded-Host header");
  }
  const forwardedProto = adapter.getHeader("x-forwarded-proto");
  if (forwardedProto !== undefined) {
    for (const value of forwardedProto.split(",")) {
      if (!/^https?$/i.test(value.trim())) throw new Error("Ambiguous X-Forwarded-Proto header");
    }
  }

  const url = adapter.getUrl();
  if (url.includes("#")) throw new Error("Request URL must not carry a fragment");
  let target = url;
  const absolute = /^(https?):\/\/([^/?]*)/i.exec(url);
  if (absolute) {
    const [prefix, scheme, authority] = absolute;
    const expected = hosts.map(h => comparableAuthority(h, scheme));
    if (expected.length > 0 && !expected.includes(comparableAuthority(authority, scheme))) {
      throw new Error("Request URL authority does not match the Host header");
    }
    target = url.slice(prefix.length);
  } else if (/^[a-z][a-z0-9+.-]*:/i.test(url)) {
    throw new Error("Request URL has an unsupported scheme");
  }
  if (!target.startsWith("/") || target.startsWith("//")) {
    throw new Error("Request target must be in origin form");
  }
  return target;
}

/**
 * Whether a value is a promise or other thenable.
 *
 * @param value - Any value.
 * @returns True for thenables.
 */
function isThenable(value: unknown): value is PromiseLike<unknown> {
  return typeof (value as { then?: unknown } | null)?.then === "function";
}

/**
 * Whether the method and framing headers leave room for a body. Header absence
 * alone does not prove there is none (an HTTP/2 body needs neither
 * Content-Length nor Transfer-Encoding), hence the method restriction.
 *
 * @param adapter - HTTP adapter.
 * @returns True when the request may be bodiless by method and headers.
 */
function framingAllowsNoBody(adapter: AdapterLike): boolean {
  const method = adapter.getMethod();
  const length = adapter.getHeader("content-length");
  return (
    (method === "GET" || method === "HEAD") &&
    (length === undefined || length.trim() === "0") &&
    adapter.getHeader("transfer-encoding") === undefined
  );
}

/**
 * Whether a framework-parsed body is empty.
 *
 * @param parsed - Parsed body, already awaited.
 * @returns True when nothing was parsed.
 */
function parsedBodyEmpty(parsed: unknown): boolean {
  return (
    parsed === undefined ||
    parsed === null ||
    parsed === "" ||
    (typeof parsed === "object" && Object.keys(parsed as object).length === 0)
  );
}

/**
 * Content bytes used for the digest published in the 402. Advisory only: the
 * paid retry is checked with {@link bodyForVerification}. When the body is only
 * available asynchronously, a bodiless GET or HEAD is published with an empty
 * body and anything else is published without a digest.
 *
 * @param adapter - HTTP adapter.
 * @param config - Server configuration.
 * @returns The bytes, or undefined when they cannot be known synchronously.
 * @throws When the request may carry a body the server cannot read.
 */
function bodyForDeclaration(
  adapter: AdapterLike,
  config: RequestCommitmentServerConfig,
): Uint8Array | undefined {
  const source = config.getRawBody ? config.getRawBody(adapter) : adapter.getBody?.();
  if (isThenable(source)) {
    Promise.resolve(source).catch(() => undefined);
    return framingAllowsNoBody(adapter) ? new Uint8Array() : undefined;
  }
  if (config.getRawBody) {
    if (!(source instanceof Uint8Array)) {
      throw new Error("Raw body accessor must return the content bytes");
    }
    return source;
  }
  if (!framingAllowsNoBody(adapter) || !parsedBodyEmpty(source)) {
    throw new Error("Request may carry a body but no raw body accessor is configured");
  }
  return new Uint8Array();
}

/**
 * Content bytes of the paid request. Without a raw body accessor the server
 * cannot hash a body, so it accepts only requests it can show have none.
 *
 * @param adapter - HTTP adapter.
 * @param config - Server configuration.
 * @returns The bytes.
 * @throws When the request carries, or may carry, a body the server cannot read.
 */
async function bodyForVerification(
  adapter: AdapterLike,
  config: RequestCommitmentServerConfig,
): Promise<Uint8Array> {
  if (config.getRawBody) {
    const bytes = await config.getRawBody(adapter);
    if (!(bytes instanceof Uint8Array)) {
      throw new Error("Raw body accessor must return the content bytes");
    }
    return bytes;
  }
  const parsed = await adapter.getBody?.();
  if (!framingAllowsNoBody(adapter) || !parsedBodyEmpty(parsed)) {
    throw new Error("Request may carry a body but no raw body accessor is configured");
  }
  return new Uint8Array();
}

/**
 * Describes the current request from the server's side.
 *
 * @param adapter - HTTP adapter.
 * @param config - Server configuration.
 * @param headers - Bound header names.
 * @param body - Content bytes.
 * @returns The request description.
 */
function describeRequest(
  adapter: AdapterLike,
  config: RequestCommitmentServerConfig,
  headers: readonly string[],
  body: Uint8Array,
): HttpRequestDescription {
  const origin = config.publicOrigin.replace(/\/+$/, "");
  const url = validateTargetUri(origin + requestTarget(adapter));
  const values: Record<string, string | undefined> = {};
  for (const name of headers) values[name] = adapter.getHeader(name);
  return { method: adapter.getMethod(), url, body, headers: values };
}

/** Payload members each bindable transfer method may carry, and where its nonce is. */
const PAYLOAD_SHAPES = {
  eip3009: { members: ["authorization", "signature"], authorization: "authorization" },
  permit2: {
    members: ["permit2Authorization", "signature"],
    authorization: "permit2Authorization",
  },
} as const;

/**
 * The signed nonce of an `exact` EVM payload.
 *
 * The transfer method comes from the requirements (default `eip3009`), and the
 * payload must have exactly that method's shape. Facilitators pick what to
 * settle from the payload; a payload that also carried another method's fields
 * could get a different authorization settled than the one checked here.
 *
 * @param payload - The scheme payload.
 * @param requirements - The accepted requirements.
 * @param requirements.extra - Carries the asset transfer method.
 * @returns The nonce as hex, or a reason it cannot be bound.
 */
function signedNonce(
  payload: unknown,
  requirements: { extra?: Record<string, unknown> },
): { nonce: string } | { reason: keyof typeof REQUEST_COMMITMENT_ERRORS; detail: string } {
  const method = requirements.extra?.assetTransferMethod ?? "eip3009";
  if (method !== "eip3009" && method !== "permit2") {
    return {
      reason: "unsupported",
      detail: `transfer method ${String(method)} has no bindable nonce`,
    };
  }
  const shape = PAYLOAD_SHAPES[method];
  const record = (payload ?? {}) as Record<string, unknown>;
  const members = Object.keys(record).sort();
  if (members.length !== shape.members.length || members.some((m, i) => m !== shape.members[i])) {
    return { reason: "malformed", detail: `payload does not have the ${method} shape` };
  }
  const authorization = record[shape.authorization] as { nonce?: unknown } | null;
  const nonce = parseNonce(authorization?.nonce, method);
  return nonce === undefined
    ? { reason: "malformed", detail: "authorization nonce is not a 32-byte value" }
    : { nonce };
}

/**
 * Creates the resource-server side of `evm-request-commitment`.
 *
 * - `enrichDeclaration` publishes the request digest for the request that produced the 402.
 * - `onBeforeVerify` recomputes the digest from the paid retry, derives the
 *   nonce with the salt the client disclosed, and compares it with the nonce
 *   the client signed.
 *
 * A disclosed salt must always lead to the signed nonce. Absence of a salt is
 * rejected only when the route declares `required: true`.
 *
 * @param config - Server configuration.
 * @returns The extension.
 */
export function createRequestCommitmentServerExtension(
  config: RequestCommitmentServerConfig,
): ResourceServerExtension {
  validateTargetUri(config.publicOrigin.replace(/\/+$/, "") + "/");

  return {
    key: EVM_REQUEST_COMMITMENT,
    dynamicInfoFields: ["requestDigest"],

    enrichDeclaration(declaration, transportContext) {
      const decl = declaration as Declaration;
      const adapter = adapterOf(transportContext);
      if (!adapter) return declaration;
      const headers = decl.info.bindingParams.headers;
      const body = bodyForDeclaration(adapter, config);
      if (body === undefined) return declaration;
      const digest = requestDigest(
        buildHttpBinding(describeRequest(adapter, config, headers, body), headers),
      );
      return { ...decl, info: { ...decl.info, requestDigest: digest } };
    },

    hooks: {
      async onBeforeVerify(declaration, context) {
        const { network, scheme } = context.requirements;
        if (scheme !== undefined && scheme !== "exact") return;
        if (!network.startsWith("eip155:")) return;
        // Core logs and *ignores* an exception thrown by a beforeVerify hook
        // (x402#3689), which would let the payment through unchecked. Every
        // failure here is therefore turned into an explicit rejection.
        try {
          return await verifyCommitment(declaration as Declaration, context);
        } catch (error) {
          return {
            abort: true as const,
            reason: REQUEST_COMMITMENT_ERRORS.malformed,
            message: `request commitment could not be checked: ${(error as Error).message}`,
          };
        }
      },
    },
  };

  /**
   * The actual check, kept separate so any exception becomes a rejection.
   *
   * @param decl - The server's own route declaration.
   * @param context - Core's verify context.
   * @param context.paymentPayload - The payment payload.
   * @param context.paymentPayload.payload - The scheme payload carrying the authorization.
   * @param context.paymentPayload.extensions - Payload extensions carrying the salt.
   * @param context.requirements - The accepted requirements.
   * @param context.requirements.extra - Carries the asset transfer method.
   * @param context.transportContext - Core's transport context.
   * @returns An abort directive, or undefined when the commitment holds.
   */
  async function verifyCommitment(
    decl: Declaration,
    context: {
      paymentPayload: { payload: unknown; extensions?: unknown };
      requirements: { extra?: Record<string, unknown> };
      transportContext?: unknown;
    },
  ) {
    const required = decl.info.required === true;
    const abort = (reason: string, message: string) => ({
      abort: true as const,
      reason,
      message,
    });

    const echoed = (context.paymentPayload.extensions as Record<string, unknown> | undefined)?.[
      EVM_REQUEST_COMMITMENT
    ] as { info?: { salt?: unknown } } | undefined;
    const salt = echoed?.info?.salt;
    if (salt === undefined) {
      return required
        ? abort(REQUEST_COMMITMENT_ERRORS.missing, "route requires a request commitment")
        : undefined;
    }
    if (typeof salt !== "string" || !HEX_32.test(salt)) {
      return abort(REQUEST_COMMITMENT_ERRORS.malformed, "salt is not 32 bytes of lowercase hex");
    }

    const signed = signedNonce(context.paymentPayload.payload, context.requirements);
    if ("reason" in signed) return abort(REQUEST_COMMITMENT_ERRORS[signed.reason], signed.detail);

    const adapter = adapterOf(context.transportContext);
    if (!adapter) {
      return abort(
        REQUEST_COMMITMENT_ERRORS.mismatch,
        "no HTTP request to recompute the commitment from",
      );
    }
    const headers = decl.info.bindingParams.headers;
    // Recomputed from the request that will execute, with the server's own
    // configuration. Nothing here is taken from the client's echo but the salt.
    const body = await bodyForVerification(adapter, config);
    const digest = requestDigest(
      buildHttpBinding(describeRequest(adapter, config, headers, body), headers),
    );
    if (deriveRequestNonce(digest, salt) !== signed.nonce) {
      return abort(
        REQUEST_COMMITMENT_ERRORS.mismatch,
        "signed nonce does not commit to this request",
      );
    }
    return undefined;
  }
}
