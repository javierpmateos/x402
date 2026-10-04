---
"@x402/cardano": minor
---

Add the `cardano-request-commitment` extension: binds a payment to the HTTP request it pays for by signing a request digest into the transaction as label 402 metadata. The client scheme honors a declared commitment, and the reference signer now keeps the auxiliary data it attaches.
