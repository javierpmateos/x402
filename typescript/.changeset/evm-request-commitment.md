---
"@x402/evm": minor
---

Add the `evm-request-commitment` extension: binds an `exact` payment to the HTTP request it pays for by deriving the EIP-3009 or Permit2 nonce from a request digest and a salt. The client scheme honors a declared commitment; payload builders accept an optional nonce.
