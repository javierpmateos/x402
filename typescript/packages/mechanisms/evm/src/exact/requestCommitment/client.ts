import { createNonce } from "../../utils";
import {
  EVM_REQUEST_COMMITMENT,
  HEX_32,
  buildHttpBinding,
  deriveRequestNonce,
  requestDigest,
  validateBoundHeaders,
  type HttpRequestDescription,
} from "./binding";

/** Supplies the request being paid for. */
export type RequestCommitmentRequestProvider = () =>
  | HttpRequestDescription
  | Promise<HttpRequestDescription>;

/** Client-side request commitment options. */
export interface RequestCommitmentClientOptions {
  /**
   * Supplies the request being paid for. Needed to honor a server's
   * `evm-request-commitment`: the client recomputes the digest from this request
   * and refuses to pay if it does not match the one the server declared.
   */
  request?: RequestCommitmentRequestProvider;
  /**
   * Returns the 32-byte salt (64 lowercase hex characters) for this purchase.
   * Defaults to fresh random bytes. Returning the same salt when retrying the
   * same purchase yields the same nonce, so the retry cannot settle twice.
   * A new purchase MUST use a new salt.
   */
  salt?: (digest: string) => string | Promise<string>;
}

/** What the client commits to: the nonce to sign and the salt to disclose. */
export interface ResolvedRequestCommitment {
  digest: string;
  salt: string;
  nonce: string;
}

/**
 * Fresh 32-byte salt.
 *
 * @returns 64 lowercase hex characters.
 */
function randomSalt(): string {
  return createNonce().slice(2).toLowerCase();
}

/**
 * Decides what commitment, if any, the client signs into the nonce.
 *
 * The client never commits to a digest it has not recomputed from its own request:
 * - no declaration: nothing, the nonce stays random;
 * - declaration but no digest, or no request provider: refuse if required, otherwise pay without;
 * - declared digest that differs from the client's request: refuse, always.
 *
 * @param extensions - `PaymentRequired.extensions` as passed to the scheme.
 * @param options - The client's request provider and salt source.
 * @returns The commitment to sign, or undefined.
 * @throws When the commitment is required but cannot be honored, or does not match.
 */
export async function resolveClientRequestCommitment(
  extensions: Record<string, unknown> | undefined,
  options: RequestCommitmentClientOptions | undefined,
): Promise<ResolvedRequestCommitment | undefined> {
  const declaration = extensions?.[EVM_REQUEST_COMMITMENT] as
    | { info?: Record<string, unknown> }
    | undefined;
  if (declaration === undefined) return undefined;

  const info = declaration.info ?? {};
  const required = info.required === true;
  if (info.profile !== "http:1") {
    throw new Error(`Unsupported request commitment profile ${JSON.stringify(info.profile)}`);
  }
  const headers = validateBoundHeaders(
    ((info.bindingParams as { headers?: unknown } | undefined)?.headers as string[]) ?? [],
  );
  const declared = info.requestDigest;
  if (typeof declared !== "string" || !HEX_32.test(declared)) {
    // The server could not compute a digest for this request.
    if (required) throw new Error("Route requires a request commitment but declared none");
    return undefined;
  }

  if (!options?.request) {
    if (required) {
      throw new Error("Route requires a request commitment but no request provider is configured");
    }
    return undefined;
  }

  const digest = requestDigest(buildHttpBinding(await options.request(), headers));
  if (digest !== declared) {
    throw new Error("Refusing to pay: declared request digest does not match this request");
  }
  const salt = options.salt ? await options.salt(digest) : randomSalt();
  if (typeof salt !== "string" || !HEX_32.test(salt)) {
    throw new Error("Request commitment salt must be 32 bytes of lowercase hex");
  }
  return { digest, salt, nonce: deriveRequestNonce(digest, salt) };
}

/**
 * The payload extension that discloses the salt to the resource server.
 *
 * @param commitment - The resolved commitment.
 * @returns The `extensions` entry to merge into the payment payload.
 */
export function requestCommitmentPayloadExtension(commitment: ResolvedRequestCommitment) {
  return { [EVM_REQUEST_COMMITMENT]: { info: { salt: commitment.salt } } };
}
