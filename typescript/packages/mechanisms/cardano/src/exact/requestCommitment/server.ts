import type { ResourceServerExtension } from "@x402/core/types";

import { isCardanoNetwork } from "../../constants";
import {
  CARDANO_REQUEST_COMMITMENT,
  buildHttpBinding,
  buildRequestCommitment,
  validateBoundHeaders,
  validateTargetUri,
  type HttpRequestDescription,
} from "./binding";
import { readRequestCommitment } from "./transaction";

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
   */
  getRawBody?: (adapter: AdapterLike) => Uint8Array;
}

/** Abort reasons surfaced by `onBeforeVerify`. */
export const REQUEST_COMMITMENT_ERRORS = {
  missing: "request_commitment_missing",
  unsigned: "request_commitment_unsigned",
  malformed: "request_commitment_malformed",
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
    commitment: { type: "object" },
  },
  required: ["required", "profile", "bindingParams"],
};

/**
 * Builds the route declaration for `extensions["cardano-request-commitment"]`.
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

/**
 * Path and query of a request URL exactly as received, fragment excluded.
 *
 * @param url - Absolute URL or origin-form path from the adapter.
 * @returns The path-and-query string.
 */
function pathAndQuery(url: string): string {
  const absolute = /^[a-z][a-z0-9+.-]*:\/\/[^/?#]*/i.exec(url);
  const rest = absolute ? url.slice(absolute[0].length) : url;
  const withoutFragment = rest.split("#")[0];
  return withoutFragment.startsWith("/") ? withoutFragment : `/${withoutFragment}`;
}

/**
 * Without a raw body accessor the server cannot hash a body, so it accepts only
 * requests it can show have none. Header absence alone is not enough (an HTTP/2
 * body needs neither Content-Length nor Transfer-Encoding), hence the method
 * restriction and the parsed-body check.
 *
 * @param adapter - HTTP adapter.
 * @returns The empty content.
 * @throws When the request carries, or may carry, a body.
 */
function bodilessOrThrow(adapter: AdapterLike): Uint8Array {
  const method = adapter.getMethod();
  const length = adapter.getHeader("content-length");
  const parsed = adapter.getBody?.();
  const parsedEmpty =
    parsed === undefined ||
    parsed === null ||
    parsed === "" ||
    (typeof parsed === "object" && Object.keys(parsed as object).length === 0);
  if (
    (method !== "GET" && method !== "HEAD") ||
    (length !== undefined && length.trim() !== "0") ||
    adapter.getHeader("transfer-encoding") !== undefined ||
    !parsedEmpty
  ) {
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
 * @returns The request description.
 */
function describeRequest(
  adapter: AdapterLike,
  config: RequestCommitmentServerConfig,
  headers: readonly string[],
): HttpRequestDescription {
  const origin = config.publicOrigin.replace(/\/+$/, "");
  const url = validateTargetUri(origin + pathAndQuery(adapter.getUrl()));
  const body = config.getRawBody ? config.getRawBody(adapter) : bodilessOrThrow(adapter);
  if (!(body instanceof Uint8Array)) {
    throw new Error("Raw body accessor must return the content bytes");
  }
  const values: Record<string, string | undefined> = {};
  for (const name of headers) values[name] = adapter.getHeader(name);
  return { method: adapter.getMethod(), url, body, headers: values };
}

/**
 * Creates the resource-server side of `cardano-request-commitment`.
 *
 * - `enrichDeclaration` publishes the commitment for the request that produced the 402.
 * - `onBeforeVerify` recomputes it from the paid retry and compares it with the
 *   commitment the buyer signed into the transaction.
 *
 * A commitment that is present must always be valid. Absence is rejected only
 * when the route declares `required: true`.
 *
 * @param config - Server configuration.
 * @returns The extension.
 */
export function createRequestCommitmentServerExtension(
  config: RequestCommitmentServerConfig,
): ResourceServerExtension {
  validateTargetUri(config.publicOrigin.replace(/\/+$/, "") + "/");

  return {
    key: CARDANO_REQUEST_COMMITMENT,
    dynamicInfoFields: ["commitment"],

    enrichDeclaration(declaration, transportContext) {
      const decl = declaration as Declaration;
      const adapter = adapterOf(transportContext);
      if (!adapter) return declaration;
      const headers = decl.info.bindingParams.headers;
      const binding = buildHttpBinding(describeRequest(adapter, config, headers), headers);
      return { ...decl, info: { ...decl.info, commitment: buildRequestCommitment(binding) } };
    },

    hooks: {
      async onBeforeVerify(declaration, context) {
        if (!isCardanoNetwork(context.requirements.network)) return;
        // Core logs and *ignores* an exception thrown by a beforeVerify hook,
        // which would let the payment through unchecked. Every failure here is
        // therefore turned into an explicit rejection.
        try {
          return verifyCommitment(declaration as Declaration, context);
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
   * @param context.paymentPayload.payload - The scheme payload carrying the transaction.
   * @param context.transportContext - Core's transport context.
   * @returns An abort directive, or undefined when the commitment holds.
   */
  function verifyCommitment(
    decl: Declaration,
    context: { paymentPayload: { payload: unknown }; transportContext?: unknown },
  ) {
    const required = decl.info.required === true;
    const abort = (reason: string, message: string) => ({
      abort: true as const,
      reason,
      message,
    });

    const transaction = (context.paymentPayload.payload as { transaction?: unknown }).transaction;
    if (typeof transaction !== "string") {
      return abort(REQUEST_COMMITMENT_ERRORS.malformed, "payload carries no transaction");
    }
    const found = readRequestCommitment(transaction);
    if (found.status === "absent") {
      return required
        ? abort(REQUEST_COMMITMENT_ERRORS.missing, "route requires a request commitment")
        : undefined;
    }
    if (found.status === "unsigned") return abort(REQUEST_COMMITMENT_ERRORS.unsigned, found.detail);
    if (found.status === "malformed")
      return abort(REQUEST_COMMITMENT_ERRORS.malformed, found.detail);

    if (found.metadatum.profile !== decl.info.profile) {
      return abort(REQUEST_COMMITMENT_ERRORS.mismatch, "commitment uses a different profile");
    }
    const adapter = adapterOf(context.transportContext);
    if (!adapter) {
      return abort(
        REQUEST_COMMITMENT_ERRORS.mismatch,
        "no HTTP request to recompute the commitment from",
      );
    }
    const headers = decl.info.bindingParams.headers;
    // Recomputed from the request that will execute, with the server's own
    // configuration. Nothing here is taken from the client's echo.
    const expected = buildRequestCommitment(
      buildHttpBinding(describeRequest(adapter, config, headers), headers),
    );
    if (found.metadatum.hash !== expected.digest) {
      return abort(
        REQUEST_COMMITMENT_ERRORS.mismatch,
        "signed commitment does not match this request",
      );
    }
    return undefined;
  }
}
