import { sha256 } from "viem";

/** Extension key carried in `PaymentRequired.extensions` and `PaymentPayload.extensions`. */
export const EVM_REQUEST_COMMITMENT = "evm-request-commitment";

/** Request binding profiles. Only `http:1` is implemented. */
export const REQUEST_COMMITMENT_PROFILES = ["http:1"] as const;
export type RequestCommitmentProfile = (typeof REQUEST_COMMITMENT_PROFILES)[number];

/**
 * Domain member of the binding object. Same structure and rules as the `http:1`
 * binding of `scheme_exact_lnbtc.md`, with an EVM-specific domain so a binding
 * can never be replayed across rails.
 */
export const HTTP_BINDING_DOMAIN = "x402:exact:evm:request-commitment:http:1";

/** Tag prefixed to the nonce preimage. */
export const NONCE_DERIVATION_TAG = "x402:exact:evm:request-nonce:v1";

/** The `http:1` binding object: exactly these members. */
export interface HttpRequestBinding {
  domain: string;
  method: string;
  url: string;
  bodyHash: string;
  headers: Array<{ name: string; valueHash: string }>;
}

/** A request as seen by whichever side computes the binding. */
export interface HttpRequestDescription {
  /** HTTP method, case preserved. */
  method: string;
  /** Absolute http(s) target URI, query included, no fragment or user information. */
  url: string;
  /** Content bytes after transfer decoding. Absent or empty means no body. */
  body?: Uint8Array;
  /** Header values by lowercase name. Only bound headers are read. */
  headers: Record<string, string | undefined>;
}

const encoder = new TextEncoder();
const HEADER_NAME = /^[!#$%&'*+\-.^_`|~0-9a-z]+$/;
export const HEX_32 = /^[0-9a-f]{64}$/;

const sha256Hex = (bytes: Uint8Array): string => sha256(bytes, "hex").slice(2);

/**
 * Hex string (lowercase, no prefix) to bytes.
 *
 * @param hex - 64 lowercase hex characters.
 * @returns The 32 bytes.
 */
function hex32ToBytes(hex: string): Uint8Array {
  if (!HEX_32.test(hex)) throw new Error("Expected 32 bytes of lowercase hex");
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/**
 * JCS (RFC 8785) for the value shapes a binding object can hold: strings,
 * arrays and objects. Strings use ECMAScript JSON serialization, as JCS does;
 * members are sorted by UTF-16 code units.
 *
 * @param value - Binding value.
 * @returns The canonical serialization.
 */
export function jcs(value: unknown): string {
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(jcs).join(",")}]`;
  if (value !== null && typeof value === "object") {
    const keys = Object.keys(value).sort();
    return `{${keys
      .map(k => `${JSON.stringify(k)}:${jcs((value as Record<string, unknown>)[k])}`)
      .join(",")}}`;
  }
  throw new Error("Binding objects hold only strings, arrays and objects");
}

/**
 * Validates a configured bound-header list: lowercase field-name tokens, strictly
 * ascending ASCII order (which also excludes duplicates), never `payment-signature`.
 *
 * @param headers - Configured header names.
 * @returns The same list.
 * @throws When the list breaks any rule.
 */
export function validateBoundHeaders(headers: readonly string[]): string[] {
  if (!Array.isArray(headers)) throw new Error("Bound headers must be an array");
  for (let i = 0; i < headers.length; i++) {
    const name = headers[i];
    if (typeof name !== "string" || !HEADER_NAME.test(name)) {
      throw new Error(`Bound header ${JSON.stringify(name)} is not a lowercase field-name token`);
    }
    if (name === "payment-signature") {
      throw new Error("payment-signature must not be a bound header");
    }
    if (i > 0 && !(headers[i - 1] < name)) {
      throw new Error("Bound headers must be in strictly ascending ASCII order");
    }
  }
  return [...headers];
}

/**
 * Validates an `http:1` target URI: absolute http(s), ASCII only, no fragment,
 * no user information. The string is used exactly as given (no normalization).
 *
 * @param url - Candidate target URI.
 * @returns The same string.
 * @throws When the URI breaks any rule.
 */
export function validateTargetUri(url: string): string {
  if (typeof url !== "string" || !/^[\x21-\x7e]+$/.test(url)) {
    throw new Error("Target URI must be printable ASCII");
  }
  if (url.includes("#")) throw new Error("Target URI must not carry a fragment");
  const match = /^(https?):\/\/([^/?]*)/i.exec(url);
  if (!match) throw new Error("Target URI must be an absolute http or https URL");
  if (match[2].length === 0) throw new Error("Target URI must carry an authority");
  if (match[2].includes("@")) throw new Error("Target URI must not carry user information");
  return url;
}

/**
 * Header value per RFC 9421 §2.1 for a single-valued field: leading and trailing
 * whitespace removed, ASCII only.
 *
 * @param value - Raw header value.
 * @returns The component value.
 * @throws When the value contains non-ASCII or control characters.
 */
function headerComponentValue(value: string): string {
  const trimmed = value.replace(/^[ \t]+|[ \t]+$/g, "");
  if (!/^[\x20-\x7e\t]*$/.test(trimmed)) {
    throw new Error("Bound header values must be ASCII without control characters");
  }
  return trimmed;
}

/**
 * Builds the `http:1` binding object for a request.
 *
 * `bodyHash` is SHA-256 of the content bytes; `valueHash` is SHA-256 of
 * `0x01 || ASCII(value)` for a present header and of `0x00` for an absent one.
 *
 * @param request - The request.
 * @param boundHeaders - Header names to bind, from the server's configuration.
 * @returns The binding object.
 */
export function buildHttpBinding(
  request: HttpRequestDescription,
  boundHeaders: readonly string[],
): HttpRequestBinding {
  if (
    typeof request.method !== "string" ||
    !/^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/.test(request.method)
  ) {
    throw new Error("HTTP method must be a token");
  }
  const headers = validateBoundHeaders(boundHeaders).map(name => {
    const raw = request.headers[name];
    const valueHash =
      raw === undefined
        ? sha256Hex(Uint8Array.of(0x00))
        : sha256Hex(new Uint8Array([0x01, ...encoder.encode(headerComponentValue(raw))]));
    return { name, valueHash };
  });
  return {
    domain: HTTP_BINDING_DOMAIN,
    method: request.method,
    url: validateTargetUri(request.url),
    bodyHash: sha256Hex(request.body ?? new Uint8Array()),
    headers,
  };
}

/**
 * The request digest: SHA-256 of the UTF-8 JCS serialization of the binding,
 * the same construction `scheme_exact_lnbtc.md` uses for `description_hash`.
 *
 * @param binding - The binding object.
 * @returns Lowercase hex digest.
 */
export function requestDigest(binding: HttpRequestBinding): string {
  return sha256Hex(encoder.encode(jcs(binding)));
}

/**
 * Derives the authorization nonce that commits to a request:
 * `SHA-256(UTF8(tag) || requestDigest || salt)`.
 *
 * The salt keeps two purchases of the same request apart, and keeps the
 * request digest off chain: the nonce alone reveals nothing about the request.
 *
 * @param digest - Request digest (64 lowercase hex characters).
 * @param salt - 32-byte salt (64 lowercase hex characters).
 * @returns The nonce as 64 lowercase hex characters.
 */
export function deriveRequestNonce(digest: string, salt: string): string {
  const tag = encoder.encode(NONCE_DERIVATION_TAG);
  return sha256Hex(new Uint8Array([...tag, ...hex32ToBytes(digest), ...hex32ToBytes(salt)]));
}

/**
 * Formats a derived nonce for an asset transfer method.
 *
 * @param nonceHex - 64 lowercase hex characters.
 * @param method - `eip3009` (bytes32, 0x-prefixed) or `permit2` (uint256, decimal).
 * @returns The nonce as the payload carries it.
 */
export function formatNonce(nonceHex: string, method: "eip3009" | "permit2"): string {
  if (!HEX_32.test(nonceHex)) throw new Error("Expected 32 bytes of lowercase hex");
  return method === "eip3009" ? `0x${nonceHex}` : BigInt(`0x${nonceHex}`).toString();
}

/**
 * Reads a payload nonce back into 64 lowercase hex characters.
 *
 * @param nonce - The nonce as the payload carries it.
 * @param method - Asset transfer method.
 * @returns The nonce as hex, or undefined when it is not a well-formed 32-byte value.
 */
export function parseNonce(nonce: unknown, method: "eip3009" | "permit2"): string | undefined {
  if (typeof nonce !== "string") return undefined;
  if (method === "eip3009") {
    const m = /^0x([0-9a-fA-F]{64})$/.exec(nonce);
    return m ? m[1].toLowerCase() : undefined;
  }
  if (!/^(0|[1-9][0-9]{0,77})$/.test(nonce)) return undefined;
  const value = BigInt(nonce);
  if (value >= 1n << 256n) return undefined;
  return value.toString(16).padStart(64, "0");
}
