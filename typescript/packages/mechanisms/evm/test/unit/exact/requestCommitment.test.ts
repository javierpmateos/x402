import { describe, it, expect, vi } from "vitest";
import { x402Client } from "@x402/core/client";
import { x402ResourceServer, type FacilitatorClient } from "@x402/core/server";
import type {
  PaymentPayload,
  PaymentRequirements,
  SettleResponse,
  SupportedResponse,
  VerifyResponse,
} from "@x402/core/types";
import { getAddress, verifyTypedData } from "viem";
import { privateKeyToAccount } from "viem/accounts";

import { ExactEvmScheme as ExactEvmClient } from "../../../src/exact/client/scheme";
import { ExactEvmScheme as ExactEvmServer } from "../../../src/exact/server/scheme";
import { authorizationTypes, x402ExactPermit2ProxyAddress } from "../../../src/constants";
import {
  EVM_REQUEST_COMMITMENT,
  HTTP_BINDING_DOMAIN,
  REQUEST_COMMITMENT_ERRORS,
  buildHttpBinding,
  createRequestCommitmentServerExtension,
  declareRequestCommitmentExtension,
  deriveRequestNonce,
  formatNonce,
  jcs,
  parseNonce,
  requestDigest,
  resolveClientRequestCommitment,
  type HttpRequestDescription,
} from "../../../src/exact/requestCommitment";

const ORIGIN = "https://api.example.com";
const NETWORK = "eip155:84532";
const SALT = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
// Hardhat/anvil account #0, a public test key.
const account = privateKeyToAccount(
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
);

const GET_A: HttpRequestDescription = { method: "GET", url: `${ORIGIN}/article/A`, headers: {} };
const POST_SEARCH: HttpRequestDescription = {
  method: "POST",
  url: `${ORIGIN}/search?lang=en`,
  body: new TextEncoder().encode('{"q":"cardano"}'),
  headers: { "content-type": "application/json" },
};

// Recomputed independently in Python (hashlib + json.dumps(sort_keys=True)).
const VECTORS = {
  get: {
    jcs: '{"bodyHash":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","domain":"x402:exact:evm:request-commitment:http:1","headers":[],"method":"GET","url":"https://api.example.com/article/A"}',
    digest: "0039e207d55562647f82dd6fe1f0bd8c051ede9adb54be27b4d46ae65131ec4a",
    nonce: "785442ce8e6f178ed3cdfd23402e5f55b1c596e0f1872fb7e30b2e3f5c8a73ab",
    permit2: "54426418067441298523243347723773644916737610689795358306867073891018866324395",
  },
  post: {
    digest: "322b19d020385d8319435f1cd599ed0463cddbccc198cc90ee32f038761e8548",
    nonce: "354b1d112966d55b0eabd216888339b6ccb530ed537d28fdcdb0a5211b3eca62",
  },
};

const requirements = (method: "eip3009" | "permit2" = "eip3009"): PaymentRequirements => ({
  scheme: "exact",
  network: NETWORK,
  amount: "10000",
  asset: "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
  payTo: "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
  maxTimeoutSeconds: 60,
  extra: {
    name: "USDC",
    version: "2",
    ...(method === "permit2" ? { assetTransferMethod: "permit2" } : {}),
  },
});

/**
 * Minimal HTTP adapter for a request.
 *
 * @param req - Request description.
 * @param path - Path and query as the adapter reports it.
 * @param extra - Overrides.
 * @returns An adapter.
 */
function adapterFor(
  req: HttpRequestDescription,
  path: string,
  extra: Partial<{ getBody: () => unknown; headers: Record<string, string> }> = {},
) {
  const headers: Record<string, string | undefined> = { ...req.headers, ...extra.headers };
  return {
    getHeader: (name: string) => headers[name.toLowerCase()],
    getMethod: () => req.method,
    getUrl: () => path,
    ...(extra.getBody ? { getBody: extra.getBody } : {}),
  };
}

/** Facilitator stand-in that accepts everything and records calls. */
class AcceptingFacilitator implements FacilitatorClient {
  verifyCalls = 0;
  async verify(): Promise<VerifyResponse> {
    this.verifyCalls++;
    return { isValid: true, payer: account.address };
  }
  async settle(): Promise<SettleResponse> {
    return { success: true, transaction: "0x", network: NETWORK };
  }
  async getSupported(): Promise<SupportedResponse> {
    return {
      kinds: [{ x402Version: 2, scheme: "exact", network: NETWORK }],
      extensions: [],
      signers: {},
    };
  }
}

/**
 * Full stack: server issues a 402 for `req`, client pays with `clientReq`.
 *
 * @param opts - Scenario.
 * @param opts.req - Request the server sees (both times unless `retryReq`).
 * @param opts.clientReq - Request the client believes it is paying for.
 * @param opts.retryReq - Request the server sees on the paid retry.
 * @param opts.required - Route `required` flag.
 * @param opts.headers - Bound headers.
 * @param opts.method - Asset transfer method.
 * @param opts.withProvider - Whether the client is configured to commit.
 * @param opts.getRawBody - Server raw-body accessor.
 * @returns The payload and the verify response.
 */
async function roundTrip(opts: {
  req: HttpRequestDescription;
  clientReq?: HttpRequestDescription;
  retryReq?: HttpRequestDescription;
  required?: boolean;
  headers?: string[];
  method?: "eip3009" | "permit2";
  withProvider?: boolean;
  getRawBody?: (adapter: unknown) => Uint8Array;
}) {
  const pathOf = (r: HttpRequestDescription) => r.url.slice(ORIGIN.length);
  const facilitator = new AcceptingFacilitator();
  const server = new x402ResourceServer(facilitator);
  server.register(NETWORK, new ExactEvmServer());
  server.registerExtension(
    createRequestCommitmentServerExtension({
      publicOrigin: ORIGIN,
      ...(opts.getRawBody ? { getRawBody: opts.getRawBody } : {}),
    }),
  );
  await server.initialize();

  const declared = {
    [EVM_REQUEST_COMMITMENT]: declareRequestCommitmentExtension({
      required: opts.required ?? true,
      headers: opts.headers ?? [],
    }),
  };
  const first = { request: { adapter: adapterFor(opts.req, pathOf(opts.req)) } };
  const accepts = [requirements(opts.method)];
  const paymentRequired = await server.createPaymentRequiredResponse(
    accepts,
    { url: opts.req.url, description: "test", mimeType: "application/json" },
    undefined,
    server.enrichExtensions(declared, first.request),
    first,
  );

  const client = x402Client.fromConfig({
    schemes: [
      {
        network: NETWORK,
        client: new ExactEvmClient(
          account,
          undefined,
          opts.withProvider === false ? undefined : { request: () => opts.clientReq ?? opts.req },
        ),
      },
    ],
    spendControls: false,
  });
  const paymentPayload = await client.createPaymentPayload(paymentRequired);

  const retry = opts.retryReq ?? opts.req;
  const second = { request: { adapter: adapterFor(retry, pathOf(retry)) } };
  const verify = await server.verifyPayment(
    paymentPayload,
    server.findMatchingRequirements(accepts, paymentPayload)!,
    server.enrichExtensions(declared, second.request),
    second,
  );
  return { paymentPayload, paymentRequired, verify, facilitator };
}

describe("evm-request-commitment: binding and derivation", () => {
  it("serializes the GET binding exactly as the lnbtc construction, with the EVM domain", () => {
    const binding = buildHttpBinding(GET_A, []);
    expect(binding.domain).toBe(HTTP_BINDING_DOMAIN);
    expect(jcs(binding)).toBe(VECTORS.get.jcs);
  });

  it("matches the fixed vectors", () => {
    const get = requestDigest(buildHttpBinding(GET_A, []));
    const post = requestDigest(buildHttpBinding(POST_SEARCH, ["content-type"]));
    expect(get).toBe(VECTORS.get.digest);
    expect(post).toBe(VECTORS.post.digest);
    expect(deriveRequestNonce(get, SALT)).toBe(VECTORS.get.nonce);
    expect(deriveRequestNonce(post, SALT)).toBe(VECTORS.post.nonce);
    expect(formatNonce(VECTORS.get.nonce, "eip3009")).toBe(`0x${VECTORS.get.nonce}`);
    expect(formatNonce(VECTORS.get.nonce, "permit2")).toBe(VECTORS.get.permit2);
  });

  it("round-trips nonces through both payload encodings", () => {
    expect(parseNonce(`0x${VECTORS.get.nonce.toUpperCase()}`, "eip3009")).toBe(VECTORS.get.nonce);
    expect(parseNonce(VECTORS.get.permit2, "permit2")).toBe(VECTORS.get.nonce);
    expect(parseNonce("1", "permit2")).toBe("0".repeat(63) + "1");
    expect(parseNonce((1n << 256n).toString(), "permit2")).toBeUndefined();
    expect(parseNonce("01", "permit2")).toBeUndefined();
    expect(parseNonce(`0x${"a".repeat(63)}`, "eip3009")).toBeUndefined();
    expect(parseNonce(123, "eip3009")).toBeUndefined();
  });

  it("separates salts, requests and bound header values", () => {
    const d = VECTORS.get.digest;
    expect(deriveRequestNonce(d, "ff" + SALT.slice(2))).not.toBe(VECTORS.get.nonce);
    const b = requestDigest(buildHttpBinding({ ...GET_A, url: `${ORIGIN}/article/B` }, []));
    expect(deriveRequestNonce(b, SALT)).not.toBe(VECTORS.get.nonce);
    const absent = requestDigest(
      buildHttpBinding({ ...POST_SEARCH, headers: {} }, ["content-type"]),
    );
    const empty = requestDigest(
      buildHttpBinding({ ...POST_SEARCH, headers: { "content-type": "" } }, ["content-type"]),
    );
    expect(absent).not.toBe(empty);
    expect(absent).not.toBe(VECTORS.post.digest);
  });

  it("rejects malformed inputs", () => {
    expect(() => deriveRequestNonce("xyz", SALT)).toThrow();
    expect(() => deriveRequestNonce(VECTORS.get.digest, SALT.toUpperCase())).toThrow();
    expect(() => buildHttpBinding({ ...GET_A, url: `${ORIGIN}/a#frag` }, [])).toThrow();
    expect(() => buildHttpBinding({ ...GET_A, url: "https://u@api.example.com/" }, [])).toThrow();
    expect(() => buildHttpBinding(GET_A, ["payment-signature"])).toThrow();
    expect(() => buildHttpBinding(GET_A, ["b", "a"])).toThrow();
    expect(() => buildHttpBinding({ ...GET_A, method: "GE T" }, [])).toThrow();
  });
});

describe("evm-request-commitment: client resolution", () => {
  const decl = (info: Record<string, unknown>) => ({
    [EVM_REQUEST_COMMITMENT]: {
      info: { required: true, profile: "http:1", bindingParams: { headers: [] }, ...info },
    },
  });

  it("does nothing without a declaration", async () => {
    expect(await resolveClientRequestCommitment({}, { request: () => GET_A })).toBeUndefined();
  });

  it("derives the nonce from its own request and the salt", async () => {
    const r = await resolveClientRequestCommitment(decl({ requestDigest: VECTORS.get.digest }), {
      request: () => GET_A,
      salt: () => SALT,
    });
    expect(r).toEqual({ digest: VECTORS.get.digest, salt: SALT, nonce: VECTORS.get.nonce });
  });

  it("uses a fresh random salt by default", async () => {
    const opts = { request: () => GET_A };
    const a = await resolveClientRequestCommitment(
      decl({ requestDigest: VECTORS.get.digest }),
      opts,
    );
    const b = await resolveClientRequestCommitment(
      decl({ requestDigest: VECTORS.get.digest }),
      opts,
    );
    expect(a!.salt).toMatch(/^[0-9a-f]{64}$/);
    expect(a!.salt).not.toBe(b!.salt);
    expect(a!.nonce).not.toBe(b!.nonce);
  });

  it("refuses a declared digest that differs from its request, even when optional", async () => {
    await expect(
      resolveClientRequestCommitment(
        decl({ required: false, requestDigest: VECTORS.post.digest }),
        { request: () => GET_A },
      ),
    ).rejects.toThrow(/does not match/);
  });

  it("refuses when required and it cannot commit; pays without when optional", async () => {
    await expect(
      resolveClientRequestCommitment(decl({ requestDigest: VECTORS.get.digest }), undefined),
    ).rejects.toThrow(/no request provider/);
    await expect(
      resolveClientRequestCommitment(decl({}), { request: () => GET_A }),
    ).rejects.toThrow(/declared none/);
    expect(
      await resolveClientRequestCommitment(
        decl({ required: false, requestDigest: VECTORS.get.digest }),
        undefined,
      ),
    ).toBeUndefined();
  });

  it("rejects a bad salt and an unknown profile", async () => {
    await expect(
      resolveClientRequestCommitment(decl({ requestDigest: VECTORS.get.digest }), {
        request: () => GET_A,
        salt: () => "00",
      }),
    ).rejects.toThrow(/salt/);
    await expect(
      resolveClientRequestCommitment(decl({ profile: "mcp:1" }), { request: () => GET_A }),
    ).rejects.toThrow(/profile/);
  });
});

describe("evm-request-commitment: client signs the derived nonce", () => {
  it("EIP-3009: the signature covers the derived nonce and the salt is disclosed", async () => {
    const scheme = new ExactEvmClient(account, undefined, {
      request: () => GET_A,
      salt: () => SALT,
    });
    const extensions = {
      [EVM_REQUEST_COMMITMENT]: {
        info: {
          required: true,
          profile: "http:1",
          bindingParams: { headers: [] },
          requestDigest: VECTORS.get.digest,
        },
      },
    };
    const req = requirements();
    const result = await scheme.createPaymentPayload(2, req, { extensions });
    const payload = result.payload as {
      authorization: Record<string, string>;
      signature: `0x${string}`;
    };
    expect(payload.authorization.nonce).toBe(`0x${VECTORS.get.nonce}`);
    expect(result.extensions).toEqual({ [EVM_REQUEST_COMMITMENT]: { info: { salt: SALT } } });

    const a = payload.authorization;
    const valid = await verifyTypedData({
      address: account.address,
      domain: {
        name: "USDC",
        version: "2",
        chainId: 84532,
        verifyingContract: getAddress(req.asset),
      },
      types: authorizationTypes,
      primaryType: "TransferWithAuthorization",
      message: {
        from: getAddress(a.from),
        to: getAddress(a.to),
        value: BigInt(a.value),
        validAfter: BigInt(a.validAfter),
        validBefore: BigInt(a.validBefore),
        nonce: `0x${VECTORS.get.nonce}`,
      },
      signature: payload.signature,
    });
    expect(valid).toBe(true);
  });

  it("Permit2: the signed uint256 nonce is the derived one", async () => {
    const scheme = new ExactEvmClient(account, undefined, {
      request: () => GET_A,
      salt: () => SALT,
    });
    const result = await scheme.createPaymentPayload(2, requirements("permit2"), {
      extensions: {
        [EVM_REQUEST_COMMITMENT]: {
          info: {
            required: true,
            profile: "http:1",
            bindingParams: { headers: [] },
            requestDigest: VECTORS.get.digest,
          },
        },
      },
    });
    const p = result.payload as { permit2Authorization: { nonce: string; spender: string } };
    expect(p.permit2Authorization.nonce).toBe(VECTORS.get.permit2);
    expect(p.permit2Authorization.spender).toBe(x402ExactPermit2ProxyAddress);
    expect(result.extensions).toEqual({ [EVM_REQUEST_COMMITMENT]: { info: { salt: SALT } } });
  });

  it("Permit2 with EIP-2612 gas sponsoring keeps both extensions", async () => {
    const signer = {
      address: account.address,
      signTypedData: account.signTypedData,
      readContract: vi.fn().mockResolvedValue(0n), // allowance 0, permit nonce 0
    };
    const scheme = new ExactEvmClient(signer, undefined, {
      request: () => GET_A,
      salt: () => SALT,
    });
    const result = await scheme.createPaymentPayload(2, requirements("permit2"), {
      extensions: {
        eip2612GasSponsoring: { info: {} },
        [EVM_REQUEST_COMMITMENT]: {
          info: {
            required: true,
            profile: "http:1",
            bindingParams: { headers: [] },
            requestDigest: VECTORS.get.digest,
          },
        },
      },
    });
    expect(result.extensions?.eip2612GasSponsoring).toBeDefined();
    expect(result.extensions?.[EVM_REQUEST_COMMITMENT]).toEqual({ info: { salt: SALT } });
  });

  it("without a declaration the nonce stays random and nothing is disclosed", async () => {
    const scheme = new ExactEvmClient(account, undefined, { request: () => GET_A });
    const result = await scheme.createPaymentPayload(2, requirements(), { extensions: {} });
    expect(result.extensions).toBeUndefined();
    expect((result.payload as { authorization: { nonce: string } }).authorization.nonce).toMatch(
      /^0x[0-9a-f]{64}$/,
    );
  });
});

describe("evm-request-commitment: full client/server flow", () => {
  it("accepts a payment committed to the request (EIP-3009 and Permit2)", async () => {
    for (const method of ["eip3009", "permit2"] as const) {
      const { verify, facilitator, paymentPayload } = await roundTrip({ req: GET_A, method });
      expect(verify.isValid, `${method}: ${verify.invalidReason}`).toBe(true);
      expect(facilitator.verifyCalls).toBe(1);
      // The salt survives core's extension merge next to the echoed declaration.
      const echoed = paymentPayload.extensions?.[EVM_REQUEST_COMMITMENT] as {
        info: Record<string, unknown>;
      };
      expect(echoed.info.salt).toMatch(/^[0-9a-f]{64}$/);
      expect(echoed.info.requestDigest).toBe(VECTORS.get.digest);
    }
  });

  it("binds the body and bound headers through a raw body accessor", async () => {
    const body = POST_SEARCH.body!;
    const ok = await roundTrip({
      req: POST_SEARCH,
      headers: ["content-type"],
      getRawBody: () => body,
    });
    expect(ok.verify.isValid, ok.verify.invalidReason).toBe(true);
    expect(
      (ok.paymentRequired.extensions?.[EVM_REQUEST_COMMITMENT] as { info: Record<string, unknown> })
        .info.requestDigest,
    ).toBe(VECTORS.post.digest);
  });

  it("rejects the payment on a different request at the same price", async () => {
    const { verify, facilitator } = await roundTrip({
      req: GET_A,
      retryReq: { ...GET_A, url: `${ORIGIN}/article/B` },
    });
    expect(verify.isValid).toBe(false);
    expect(verify.invalidReason).toBe(REQUEST_COMMITMENT_ERRORS.mismatch);
    expect(facilitator.verifyCalls).toBe(0);
  });

  it("rejects a changed bound header", async () => {
    const body = POST_SEARCH.body!;
    const { verify } = await roundTrip({
      req: POST_SEARCH,
      retryReq: { ...POST_SEARCH, headers: { "content-type": "text/plain" } },
      headers: ["content-type"],
      getRawBody: () => body,
    });
    expect(verify.invalidReason).toBe(REQUEST_COMMITMENT_ERRORS.mismatch);
  });

  it("client refuses to pay when the 402 was issued for another request", async () => {
    await expect(
      roundTrip({ req: GET_A, clientReq: { ...GET_A, url: `${ORIGIN}/article/B` } }),
    ).rejects.toThrow(/does not match/);
  });

  it("required route without a commitment is rejected; optional route lets it through", async () => {
    await expect(roundTrip({ req: GET_A, withProvider: false })).rejects.toThrow(
      /no request provider/,
    );
    const optional = await roundTrip({ req: GET_A, withProvider: false, required: false });
    expect(optional.verify.isValid).toBe(true);
  });

  it("without a raw body accessor a request with a body is rejected, not let through", async () => {
    const { verify } = await roundTrip({
      req: GET_A,
      retryReq: { ...GET_A, headers: { "content-length": "5" } },
    });
    expect(verify.isValid).toBe(false);
    expect(verify.invalidReason).toBe(REQUEST_COMMITMENT_ERRORS.malformed);
  });
});

describe("evm-request-commitment: server checks on tampered payloads", () => {
  const ext = createRequestCommitmentServerExtension({ publicOrigin: ORIGIN });
  const declaration = declareRequestCommitmentExtension({ required: true });
  const transport = { request: { adapter: adapterFor(GET_A, "/article/A") } };
  const hook = ext.hooks!.onBeforeVerify!;
  const run = (
    payload: unknown,
    extensions: unknown,
    network = NETWORK,
    ctx: unknown = transport,
    req: PaymentRequirements = requirements(),
  ) =>
    hook(declaration, {
      paymentPayload: { payload, extensions } as unknown as PaymentPayload,
      requirements: { ...req, network } as PaymentRequirements,
      declaredExtensions: {},
      transportContext: ctx,
    } as never);
  const saltExt = (salt: unknown) => ({ [EVM_REQUEST_COMMITMENT]: { info: { salt } } });
  const auth = (nonce: string) => ({ authorization: { nonce }, signature: "0x" });

  it("accepts the matching nonce", async () => {
    expect(await run(auth(`0x${VECTORS.get.nonce}`), saltExt(SALT))).toBeUndefined();
    expect(
      await run(
        { permit2Authorization: { nonce: VECTORS.get.permit2 }, signature: "0x" },
        saltExt(SALT),
        NETWORK,
        transport,
        requirements("permit2"),
      ),
    ).toBeUndefined();
  });

  it("reads the nonce of the requirements' transfer method, not of whatever the payload carries", async () => {
    // A Permit2 payload presented against eip3009 requirements, and the reverse.
    expect(
      await run(
        { permit2Authorization: { nonce: VECTORS.get.permit2 }, signature: "0x" },
        saltExt(SALT),
      ),
    ).toMatchObject({ reason: REQUEST_COMMITMENT_ERRORS.malformed });
    expect(
      await run(
        auth(`0x${VECTORS.get.nonce}`),
        saltExt(SALT),
        NETWORK,
        transport,
        requirements("permit2"),
      ),
    ).toMatchObject({ reason: REQUEST_COMMITMENT_ERRORS.malformed });
  });

  it("rejects a decoy authorization added to an erc7710 payload", async () => {
    const erc7710 = {
      ...requirements(),
      extra: { ...requirements().extra, assetTransferMethod: "erc7710" },
    } as PaymentRequirements;
    const decoy = {
      delegationManager: "0x",
      permissionContext: "0x",
      delegator: "0x",
      authorization: { nonce: `0x${VECTORS.get.nonce}` },
    };
    expect(await run(decoy, saltExt(SALT), NETWORK, transport, erc7710)).toMatchObject({
      reason: REQUEST_COMMITMENT_ERRORS.unsupported,
    });
    // Same decoy against eip3009 requirements: extra members are not allowed.
    expect(await run(decoy, saltExt(SALT))).toMatchObject({
      reason: REQUEST_COMMITMENT_ERRORS.malformed,
    });
  });

  it("does not let a Host header move the checked path (payment for A presented on B)", async () => {
    const injected = (host: string, target: string) => ({
      request: {
        adapter: {
          getHeader: (n: string) => (n === "host" ? host : undefined),
          getMethod: () => "GET",
          getUrl: () => `http://${host}${target}`,
        },
      },
    });
    for (const [host, target] of [
      ["x/article/A#", "/article/B"],
      ["x/article/A?", "/article/B"],
      ["api.example.com/article/A", "/article/B"],
      ["user@api.example.com", "/article/A"],
    ]) {
      const r = await run(
        auth(`0x${VECTORS.get.nonce}`),
        saltExt(SALT),
        NETWORK,
        injected(host, target),
      );
      expect(r, `${host} ${target}`).toMatchObject({ abort: true });
    }
    // A forwarded host is checked the same way.
    const forwarded = {
      request: {
        adapter: {
          getHeader: (n: string) => (n === "x-forwarded-host" ? "x/article/A#" : undefined),
          getMethod: () => "GET",
          getUrl: () => "http://x/article/A#/article/B",
        },
      },
    };
    expect(
      await run(auth(`0x${VECTORS.get.nonce}`), saltExt(SALT), NETWORK, forwarded),
    ).toMatchObject({
      abort: true,
    });
    // An honest absolute URL with a valid Host still verifies.
    expect(
      await run(
        auth(`0x${VECTORS.get.nonce}`),
        saltExt(SALT),
        NETWORK,
        injected("api.example.com:8080", "/article/A"),
      ),
    ).toBeUndefined();
  });

  it("does not let X-Forwarded-Proto, an absolute-form target or a foreign authority move the path", async () => {
    const nonce = `0x${VECTORS.get.nonce}`;
    const expressLike = (headers: Record<string, string>, url: string) => ({
      request: {
        adapter: {
          getHeader: (n: string) => headers[n],
          getMethod: () => "GET",
          getUrl: () => url,
        },
      },
    });
    // Victim paid for /fetch?u=https://api.example.com/article/A; attacker asks for /article/A.
    const victim = requestDigest(
      buildHttpBinding(
        { ...GET_A, url: `${ORIGIN}/fetch?u=https://api.example.com/article/A` },
        [],
      ),
    );
    const victimNonce = `0x${deriveRequestNonce(victim, SALT)}`;
    const cases: Array<[Record<string, string>, string, string]> = [
      [
        { host: "api.example.com", "x-forwarded-proto": "https://x/fetch?u=https" },
        "https://x/fetch?u=https://api.example.com/article/A",
        victimNonce,
      ],
      [
        { host: "api.example.com" },
        "https://x/fetch?u=https://api.example.com/article/A",
        victimNonce,
      ],
      [{ host: "host" }, "http://hosthttp://evil/article/A", nonce],
      [{}, "http://x//article/A", nonce],
      [{}, "ftp://api.example.com/article/A", nonce],
    ];
    // Without a Host header to compare against, the scheme check alone must hold.
    cases.push([
      { "x-forwarded-proto": "https://x/fetch?u=https" },
      "https://x/fetch?u=https://api.example.com/article/A",
      victimNonce,
    ]);
    // A target starting with `//` is not origin form, even when it would match a paid URL.
    const doubleSlash = requestDigest(
      buildHttpBinding({ ...GET_A, url: `${ORIGIN}//article/A` }, []),
    );
    cases.push([{}, "http://x//article/A", `0x${deriveRequestNonce(doubleSlash, SALT)}`]);
    for (const [headers, url, n] of cases) {
      const r = await run(auth(n), saltExt(SALT), NETWORK, expressLike(headers, url));
      expect(r, url).toMatchObject({ abort: true });
    }
    // Legitimate variants still verify: default port, case, list of forwarded protos.
    for (const [headers, url] of [
      [{ host: "API.example.com:443" }, "https://api.example.com/article/A"],
      [
        { host: "api.example.com", "x-forwarded-proto": "https, http" },
        "https://api.example.com/article/A",
      ],
      [{ host: "[::1]:3000" }, "http://[::1]:3000/article/A"],
      [
        { host: "internal:8080", "x-forwarded-host": "api.example.com" },
        "https://api.example.com/article/A",
      ],
    ] as Array<[Record<string, string>, string]>) {
      expect(
        await run(auth(nonce), saltExt(SALT), NETWORK, expressLike(headers, url)),
        url,
      ).toBeUndefined();
    }
  });

  it("awaits an async parsed body: empty is accepted, non-empty is rejected", async () => {
    const withBody = (body: unknown) => ({
      request: {
        adapter: { ...adapterFor(GET_A, "/article/A"), getBody: () => Promise.resolve(body) },
      },
    });
    expect(
      await run(auth(`0x${VECTORS.get.nonce}`), saltExt(SALT), NETWORK, withBody(undefined)),
    ).toBeUndefined();
    expect(
      await run(auth(`0x${VECTORS.get.nonce}`), saltExt(SALT), NETWORK, withBody("text")),
    ).toMatchObject({
      reason: REQUEST_COMMITMENT_ERRORS.malformed,
    });
  });

  it("accepts an async raw body accessor and publishes no digest it cannot compute", async () => {
    const body = POST_SEARCH.body!;
    const ext2 = createRequestCommitmentServerExtension({
      publicOrigin: ORIGIN,
      getRawBody: async () => body,
    });
    const post = { request: { adapter: adapterFor(POST_SEARCH, "/search?lang=en") } };
    const decl = declareRequestCommitmentExtension({ required: true, headers: ["content-type"] });
    // The 402 cannot carry a digest for a POST whose body is only available asynchronously.
    const enriched = ext2.enrichDeclaration!(decl, post.request) as {
      info: Record<string, unknown>;
    };
    expect(enriched.info.requestDigest).toBeUndefined();
    // A bodiless GET still gets one.
    const get = ext2.enrichDeclaration!(declareRequestCommitmentExtension({ required: true }), {
      adapter: adapterFor(GET_A, "/article/A"),
    }) as { info: Record<string, unknown> };
    expect(get.info.requestDigest).toBe(VECTORS.get.digest);
    // Verification awaits the accessor.
    const r = await ext2.hooks!.onBeforeVerify!(decl, {
      paymentPayload: {
        payload: auth(`0x${VECTORS.post.nonce}`),
        extensions: saltExt(SALT),
      } as unknown as PaymentPayload,
      requirements: requirements(),
      declaredExtensions: {},
      transportContext: post,
    } as never);
    expect(r).toBeUndefined();
  });

  it("does not treat an async parsed body as proof of no body", async () => {
    const asyncBody = {
      request: {
        adapter: { ...adapterFor(GET_A, "/article/A"), getBody: () => Promise.resolve({ q: "x" }) },
      },
    };
    expect(
      await run(auth(`0x${VECTORS.get.nonce}`), saltExt(SALT), NETWORK, asyncBody),
    ).toMatchObject({
      reason: REQUEST_COMMITMENT_ERRORS.malformed,
    });
  });

  it("ignores schemes other than exact", async () => {
    expect(
      await run({}, {}, NETWORK, transport, {
        ...requirements(),
        scheme: "upto",
      } as PaymentRequirements),
    ).toBeUndefined();
  });

  it("rejects a random nonce presented with a salt", async () => {
    const r = await run(auth(`0x${"ab".repeat(32)}`), saltExt(SALT));
    expect(r).toMatchObject({ abort: true, reason: REQUEST_COMMITMENT_ERRORS.mismatch });
  });

  it("rejects a payload carrying both authorizations", async () => {
    const r = await run(
      {
        authorization: { nonce: `0x${VECTORS.get.nonce}` },
        permit2Authorization: { nonce: "1" },
      },
      saltExt(SALT),
    );
    expect(r).toMatchObject({ abort: true, reason: REQUEST_COMMITMENT_ERRORS.malformed });
  });

  it("rejects a transfer method without a bindable nonce", async () => {
    const r = await run({ permissionContext: "0x" }, saltExt(SALT));
    expect(r).toMatchObject({ abort: true, reason: REQUEST_COMMITMENT_ERRORS.malformed });
  });

  it("rejects a missing or malformed salt", async () => {
    expect(await run(auth(`0x${VECTORS.get.nonce}`), {})).toMatchObject({
      reason: REQUEST_COMMITMENT_ERRORS.missing,
    });
    expect(await run(auth(`0x${VECTORS.get.nonce}`), saltExt(SALT.toUpperCase()))).toMatchObject({
      reason: REQUEST_COMMITMENT_ERRORS.malformed,
    });
    expect(await run(auth("0x1234"), saltExt(SALT))).toMatchObject({
      reason: REQUEST_COMMITMENT_ERRORS.malformed,
    });
  });

  it("rejects when there is no HTTP request to recompute from", async () => {
    expect(await run(auth(`0x${VECTORS.get.nonce}`), saltExt(SALT), NETWORK, {})).toMatchObject({
      reason: REQUEST_COMMITMENT_ERRORS.mismatch,
    });
  });

  it("turns an internal error into a rejection", async () => {
    const throwing = {
      request: {
        adapter: {
          ...adapterFor(GET_A, "/article/A"),
          getMethod: vi.fn(() => {
            throw new Error("boom");
          }),
        },
      },
    };
    expect(
      await run(auth(`0x${VECTORS.get.nonce}`), saltExt(SALT), NETWORK, throwing),
    ).toMatchObject({ abort: true, reason: REQUEST_COMMITMENT_ERRORS.malformed });
  });

  it("ignores payments on other networks", async () => {
    expect(await run({}, {}, "solana:devnet")).toBeUndefined();
  });

  it("the same salt reproduces the same nonce, so a retry cannot settle twice", () => {
    expect(deriveRequestNonce(VECTORS.get.digest, SALT)).toBe(
      deriveRequestNonce(VECTORS.get.digest, SALT),
    );
  });
});
