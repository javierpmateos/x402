# Extension: `evm-request-commitment`

**Status:** Draft

## Summary

`evm-request-commitment` binds an EVM `exact` payment to the HTTP request it pays for. The buyer derives the authorization nonce from a digest of the request and a random salt, signs the authorization as usual, and discloses the salt in the payment payload. The resource server recomputes the digest from the request it is about to serve and checks that it leads, with the salt, to the nonce the buyer signed.

It addresses the same gap as `cardano-request-commitment` (draft, [#3449](https://github.com/x402-foundation/x402/issues/3449)). The verification rules of `scheme_exact_evm.md` check signature, balance, amount, validity window, token and network, and none of them reference the request. An authorization signed for resource A therefore also verifies against resource B on the same server at the same price. The nonce stops the same authorization from settling twice; it does not tie the authorization to a request.

The extension needs no contract, facilitator or token change. EIP-3009 and Permit2 both let the signer choose any 32-byte nonce, and both include it in the signed message. EIP-3009 itself suggests dedicating part of the nonce to an application identifier.

The extension is opt-in per route. A route that does not declare it is unaffected. A route that declares it with `required: false` accepts payments without a commitment but rejects an invalid one; with `required: true` it also rejects payments without one.

Unlike Cardano metadata, the salt is not covered by the payer's signature. Anyone holding a payload can strip the salt, and on a `required: false` route the stripped payload is accepted unbound. `required: false` therefore only protects a client from paying for a 402 issued for another request. Protection against a payload being redeemed for another request requires `required: true`.

It reuses the `http:1` binding object of `scheme_exact_lnbtc.md` and its digest construction (SHA-256 of the JCS serialization), so Lightning, Cardano and EVM bind an HTTP request the same way. What differs is only the anchor: `description_hash` on Lightning, transaction metadata on Cardano, the authorization nonce on EVM.

---

## `PaymentRequired`

The server declares the extension and publishes the digest it computed for the request that produced the 402:

```json
{
  "extensions": {
    "evm-request-commitment": {
      "info": {
        "required": true,
        "profile": "http:1",
        "bindingParams": { "headers": [] },
        "requestDigest": "0039e207d55562647f82dd6fe1f0bd8c051ede9adb54be27b4d46ae65131ec4a"
      },
      "schema": { "...": "JSON Schema for info" }
    }
  }
}
```

| Field | Required | Description |
|---|---|---|
| `required` | Yes | When `true`, a payment without a commitment is rejected. |
| `profile` | Yes | Request binding profile. Only `"http:1"` is defined. |
| `bindingParams.headers` | Yes | Header names bound into the digest, lowercase, strictly ascending, never `payment-signature`. |
| `requestDigest` | No | Lowercase hex digest of the request that produced the 402. Absent when the server could not compute it. |

## `PaymentPayload`

The client echoes the declaration and adds the salt:

```json
{
  "extensions": {
    "evm-request-commitment": {
      "info": {
        "required": true,
        "profile": "http:1",
        "bindingParams": { "headers": [] },
        "requestDigest": "0039e207…ec4a",
        "salt": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
      }
    }
  },
  "payload": {
    "signature": "0x…",
    "authorization": {
      "from": "0x…",
      "to": "0x…",
      "value": "10000",
      "validAfter": "0",
      "validBefore": "1740672154",
      "nonce": "0x785442ce8e6f178ed3cdfd23402e5f55b1c596e0f1872fb7e30b2e3f5c8a73ab"
    }
  }
}
```

`salt` is 32 bytes as 64 lowercase hex characters. Only `salt` is read by the server; everything else in the echo is ignored.

---

## Commitment construction

### Request binding (`http:1`)

The binding object has exactly the members, value rules and normalization of the `http:1` profile in `scheme_exact_lnbtc.md`, including its rejection rules except the one on `resource.url` (below), with this domain:

```text
"domain": "x402:exact:evm:request-commitment:http:1"
```

A distinct domain means a binding made for another rail can never be presented as an EVM one, or the reverse. As in `cardano-request-commitment`, `PaymentRequired.resource.url` is not required to equal the bound `url`.

### Digest and nonce

```text
requestDigest = SHA-256( UTF8(JCS(binding)) )
nonce         = SHA-256( UTF8("x402:exact:evm:request-nonce:v1") || requestDigest || salt )
```

`requestDigest` and `salt` enter the nonce as 32 raw bytes each. The nonce is carried as:

| Transfer method | Field | Encoding |
|---|---|---|
| `eip3009` | `authorization.nonce` | `bytes32`, `0x`-prefixed hex |
| `permit2` | `permit2Authorization.nonce` | `uint256`, decimal string |

`erc7710` has no nonce the payer signs per payment, so this extension does not apply to it. A route that requires a commitment rejects it.

**Why a salt.** Without it, two purchases of the same request would derive the same nonce, and the second would be rejected by the token as a replay. The salt also keeps the request digest off-chain: the nonce alone reveals nothing about the request, while anyone holding the salt can verify the binding later.

**Retries.** A client that lost the response MAY retry the same purchase with the same salt. The retry then carries the same nonce and cannot settle a second time. A new purchase MUST use a new salt.

---

## Client rules

When a 402 declares `evm-request-commitment`, the client:

1. MUST recompute the binding from its own request, using the declared `bindingParams.headers`, and MUST recompute `requestDigest` from it.
2. MUST refuse to pay if the declared `requestDigest` does not match what it recomputed, whether or not `required` is set.
3. MUST NOT derive a nonce from a digest it has not recomputed itself.
4. Not being able to compute the digest is not the same as detecting a mismatch. If the client cannot compute it, it MUST refuse to pay when `required` is `true`, and MAY proceed with a random nonce and no salt when `required` is `false` or unset, provided no mismatch has been detected.
5. MUST draw the salt from a cryptographically secure random source for each new purchase.

## Server rules

On the paid retry, the server:

1. MUST recompute the binding from the request that will execute, using its own route configuration. It MUST NOT take the profile, the bound headers or the digest from the client's echo; the salt is the only value it takes from the payload extension.
2. MUST build the target URI from its configured public origin and the request's path and query, never from the `Host` header. Where the framework only exposes a URL assembled from client-influenced parts (scheme from `X-Forwarded-Proto`, authority from `Host` or `X-Forwarded-Host`, then the request target), a crafted value in any of them can move the boundary between authority and path and let the client choose the path that gets checked. The server MUST then reject the request unless: `X-Forwarded-Proto`, if present, holds only `http` or `https`; `Host` and `X-Forwarded-Host` hold only authority characters (no `/`, `?`, `#`, `@`); the URL's authority equals one of those headers (ignoring case and the scheme's default port); and the remaining target is in origin form (one leading `/`, no fragment). Taking the request target directly from the HTTP parser is preferable when the framework exposes it.
3. MUST hash the content bytes as received, and MUST reject any request it cannot show has no body when it cannot obtain those bytes (same rule as `cardano-request-commitment`).
4. MUST take the transfer method from the accepted requirements (`extra.assetTransferMethod`, default `eip3009`), require the payload to have exactly that method's members (`authorization` and `signature`, or `permit2Authorization` and `signature`), read the nonce from it, and evaluate:

| Payload | Outcome |
|---|---|
| No `salt`, route `required: true` | **reject** (`request_commitment_missing`) |
| No `salt`, route `required` false or unset | accept (no binding) |
| `salt` not 64 lowercase hex characters | **reject** (`request_commitment_malformed`) |
| Transfer method other than `eip3009` or `permit2`, with a `salt` | **reject** (`request_commitment_unsupported_transfer_method`) |
| Payload members differ from the method's (missing, extra, or another method's) | **reject** (`request_commitment_malformed`) |
| Nonce not a 32-byte value | **reject** (`request_commitment_malformed`) |
| Derived nonce differs from the signed nonce | **reject** (`request_commitment_mismatch`) |
| Derived nonce equals the signed nonce | accept |

Facilitators choose what to settle from the payload's shape. A payload carrying another method's fields as well could get an authorization settled other than the one checked here, so any extra member is rejected.

A present salt is always checked, regardless of `required`. Any failure to complete the check, expected or internal, MUST reject. In the TypeScript core an exception thrown by a `beforeVerify` hook is currently ignored ([#3689](https://github.com/x402-foundation/x402/issues/3689)), so an implementation MUST catch every internal error and return an explicit rejection.

These checks run in `beforeVerify`, before the facilitator is called and before the resource executes, in the authorization and upfront flows alike. They do not run if the extension is declared on a route but not registered with the resource server, or if an earlier `beforeVerify` hook short-circuits verification; a server that declares `required: true` MUST register the extension and MUST NOT let another hook skip it. The rules apply to `exact` payments on `eip155` networks only: on a route that also accepts other networks, `required` says nothing about those payments.

## Facilitator

No change. The nonce is an ordinary nonce to the facilitator and to the token.

---

## Changes to the reference EVM implementation

1. **Payload builders** (`exact/client/eip3009.ts`, `shared/permit2.ts`): accept an optional nonce; without one they keep generating a random nonce as today.
2. **Client scheme** (`exact/client/scheme.ts`): a new optional constructor argument supplies the client's view of the request (and optionally the salt). The scheme derives the nonce, checks the signed payload carries it, and returns the salt as a payload extension, merged with any gas sponsoring extension.
3. **New module** (`exact/requestCommitment/`): binding, digest, nonce derivation, client resolution, and the resource-server extension (`enrichDeclaration` publishes the digest; `onBeforeVerify` checks the nonce).

### Known limitations of the reference implementation

- The raw body accessor may be async, but the 402 is built synchronously, so for a request with a body the 402 carries no `requestDigest` when the body is only available asynchronously (Hono, Next, fetch). A client then cannot commit, and on a `required: true` route it refuses to pay. Bodiless GET and HEAD requests are unaffected.
- The client's request provider takes no arguments, so one scheme instance cannot tell concurrent purchases apart. A wrong request produces a digest mismatch and the client refuses to pay; it fails closed, but it is not usable for concurrent requests yet.

## Cost

None on-chain: the nonce exists already. Off-chain, one SHA-256 over the binding and one over 95 bytes on each side, and 32 bytes of salt in the payload.

---

## Security considerations

- **What it binds.** The nonce ties the authorization to the method, target URI, body and bound headers of one request. Finding a second request and salt that derive the same nonce requires a SHA-256 second preimage.
- **Header selection, public origin, bodies.** As in `cardano-request-commitment`. Bound headers must cover everything that changes the response; the origin comes from configuration; a body the server cannot read as bytes is a rejection, not an empty body.
- **Stripped salt.** See the summary: only `required: true` protects against a payload being redeemed for another request.
- **Privacy.** On-chain, the nonce is indistinguishable from a random one. The salt travels only in the payload, to the resource server and the facilitator.
- **What it does not provide.** Without the salt, a third party looking at the chain cannot verify the binding. A receipt that wants to prove it must carry the salt.

---

## Test vectors

Salt for both: `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`.

### 1. Bodiless GET

`GET https://api.example.com/article/A`, no bound headers.

```text
JCS(binding)  = {"bodyHash":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","domain":"x402:exact:evm:request-commitment:http:1","headers":[],"method":"GET","url":"https://api.example.com/article/A"}
requestDigest = 0039e207d55562647f82dd6fe1f0bd8c051ede9adb54be27b4d46ae65131ec4a
nonce         = 785442ce8e6f178ed3cdfd23402e5f55b1c596e0f1872fb7e30b2e3f5c8a73ab
eip3009       = 0x785442ce8e6f178ed3cdfd23402e5f55b1c596e0f1872fb7e30b2e3f5c8a73ab
permit2       = 54426418067441298523243347723773644916737610689795358306867073891018866324395
```

### 2. POST with query, body and a bound header

`POST https://api.example.com/search?lang=en`, body `{"q":"cardano"}`, `content-type: application/json`, bound headers `["content-type"]`.

```text
requestDigest = 322b19d020385d8319435f1cd599ed0463cddbccc198cc90ee32f038761e8548
nonce         = 354b1d112966d55b0eabd216888339b6ccb530ed537d28fdcdb0a5211b3eca62
```
