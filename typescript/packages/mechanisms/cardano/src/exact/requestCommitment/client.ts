import type { MasumiInputCommitment } from "../../types";
import {
  CARDANO_REQUEST_COMMITMENT,
  buildHttpBinding,
  commitmentMismatch,
  validateBoundHeaders,
  type HttpRequestDescription,
} from "./binding";
import { readRequestCommitment } from "./transaction";

/** Supplies the request being paid for. */
export type RequestCommitmentRequestProvider = () =>
  | HttpRequestDescription
  | Promise<HttpRequestDescription>;

/**
 * Decides what commitment, if any, the client embeds.
 *
 * The client never signs a digest it has not recomputed from its own request:
 * - no declaration → nothing;
 * - declaration but no request provider → refuse if required, otherwise pay without;
 * - declared commitment that differs from the client's request → refuse, always.
 *
 * @param extensions - `PaymentRequired.extensions` as passed to the scheme.
 * @param provider - The client's view of the request, if configured.
 * @returns The commitment to embed, or undefined.
 * @throws When the commitment is required but cannot be honored, or does not match.
 */
export async function resolveClientRequestCommitment(
  extensions: Record<string, unknown> | undefined,
  provider: RequestCommitmentRequestProvider | undefined,
): Promise<{ profile: string; hash: string } | undefined> {
  const declaration = extensions?.[CARDANO_REQUEST_COMMITMENT] as
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
  const commitment = info.commitment as MasumiInputCommitment | undefined;
  if (!commitment || typeof commitment !== "object") {
    // The server could not compute a commitment for this request.
    if (required) throw new Error("Route requires a request commitment but declared none");
    return undefined;
  }

  if (!provider) {
    if (required) {
      throw new Error("Route requires a request commitment but no request provider is configured");
    }
    return undefined;
  }

  const binding = buildHttpBinding(await provider(), headers);
  const mismatch = commitmentMismatch(commitment, binding);
  if (mismatch) throw new Error(`Refusing to pay: ${mismatch}`);
  return { profile: "http:1", hash: commitment.digest };
}

/**
 * Confirms a signer actually embedded the commitment it was asked to embed.
 * A signer that ignores the request would otherwise drop the binding silently.
 *
 * @param transactionBase64 - The signed transaction.
 * @param expected - The commitment the signer was asked to embed.
 * @param expected.profile - Request binding profile.
 * @param expected.hash - Lowercase hex digest.
 * @throws When the transaction does not carry exactly that commitment.
 */
export function assertCommitmentEmbedded(
  transactionBase64: string,
  expected: { profile: string; hash: string },
): void {
  const found = readRequestCommitment(transactionBase64);
  if (
    found.status !== "present" ||
    found.metadatum.profile !== expected.profile ||
    found.metadatum.hash !== expected.hash
  ) {
    throw new Error(
      `Cardano signer did not embed the request commitment (${
        found.status === "present" ? "different value" : found.status
      })`,
    );
  }
}
