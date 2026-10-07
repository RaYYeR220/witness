# `witness/v1` envelope

Status: implemented. Reference implementation: `core/src/witness_core/` (Python). The
TypeScript port in `packages/verify/src/` gives the same results on the shared vectors
(section 9). The vectors pin the behaviour; should this text disagree with them, the
vectors are right and the text needs fixing.

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119 and RFC 8174.

## 1. Purpose

A `witness/v1` envelope is a signed JSON object carried as the `data` of an IOTA Stardust
tagged-data payload. It binds a message body (or its ciphertext) to the block's tag, to an
issuer DID and key, to a per-issuer sequence number and nonce, and optionally to the issuer's
previous block and a correlation id. The block's tag is unchanged, so consumers that filter
by tag keep working, and a consumer that ignores envelopes still finds the original body under
`body`.

## 2. Carriage

- The envelope MUST be the `data` of a tagged-data payload (Stardust payload type 5) as
  UTF-8 JSON text. The payload's `tag` is the UTF-8 tag, at most 64 bytes.
- Writers SHOULD write the RFC 8785 (JCS) serialisation of the envelope as the data; the
  witness-relay always does (`relay/src/witness_relay/attest.py`, `envelope_data`).
  Verifiers MUST accept any JSON text that parses to the same value.
- The whole block MUST fit the Stardust block size; the relay refuses messages that would
  exceed `RELAY_MAX_BLOCK_BYTES` (32768).

## 3. Detection and parsing

- Data that is not UTF-8 JSON, or whose JSON is not an object, is not an envelope.
- A JSON object is an envelope candidate when it has a member `w` that is an integer equal to
  `1` (not a boolean) and a member `sig` that is a string (`envelope.is_envelope`). Any other
  object is a legacy (unsigned) message.
- Parsers MUST refuse JSON text in which `[` or `{` outside strings nest more than 2500 deep,
  whether or not the text is otherwise valid JSON (`nesting.MAX_JSON_DEPTH`,
  `nesting.text_too_deep`). The verdict is `MALFORMED`. This cap makes the result independent
  of the platform's own parser limits.
- `NaN`, `Infinity` and `-Infinity` MUST be refused.
- Producers MUST NOT emit duplicate member names. Verifiers follow Python's `json.loads`
  (the last occurrence wins), which the TypeScript port reproduces.
- Integers and decimals are distinct: `7` is an integer, `7.0` is not
  (`packages/verify/src/json.ts` keeps the distinction that `JSON.parse` loses).

## 4. Members

The member set is closed: an envelope with any other top-level member is `MALFORMED`.

| Member | Required | Type and constraint |
|---|---|---|
| `w` | yes | integer `1` |
| `tag` | yes | string; MUST equal the block's tag, decoded as UTF-8 |
| `iss` | yes | string; the issuer DID (section 6) |
| `kid` | yes | string `<iss>#<fragment>`; the part before the first `#` MUST equal `iss` |
| `seq` | yes | integer in `[0, 2^53 − 1]`, not a boolean, written without fraction or exponent |
| `iat` | yes | integer in `[0, 2^53 − 1]`: issue time, milliseconds since the Unix epoch |
| `nonce` | yes | 16 random bytes, canonical unpadded base64url: exactly 22 characters of `[A-Za-z0-9_-]` that decode to 16 bytes and re-encode to the same string |
| `att` | yes | object; `mode` is `"producer"` or `"relay"`; with `"relay"`, `sub` MUST be a non-empty string; when present, `sub` MUST be a string. Other members of `att` are not interpreted but are covered by the signature |
| `body` | exactly one of `body`, `enc` | a JSON object (`null` passes the signature check but is `MALFORMED` in the explorer and refused by the relay) |
| `enc` | exactly one of `body`, `enc` | object: a sealed body (section 5) |
| `bix` | no | array of strings: blind index tokens (section 5.2) |
| `cmt` | no | object whose values are strings: commitments (section 5.3) |
| `prev` | no | `0x` + 64 lowercase hex: block id of the issuer's previous message |
| `corr` | no | string: correlation id of a flow |
| `sig` | yes | 64-byte Ed25519 signature, canonical unpadded base64url: exactly 86 characters |

A message that is not a JSON object is wrapped by the relay as `{"value": <message>}` before
it becomes a `body`.

### 4.1 Signature

- The signing input MUST be the RFC 8785 serialisation of the envelope with the `sig` member
  removed (`envelope._signing_input`). Every other member, including `att`, `enc`, `bix`,
  `cmt`, `prev` and `corr`, is signed.
- The signature MUST be Ed25519 (RFC 8032, PureEdDSA) over those bytes, with the private key
  of the verification method `kid`.
- If the envelope cannot be canonicalised it is `MALFORMED`. That covers integers outside
  `[−(2^53 − 1), 2^53 − 1]` anywhere in it, strings with unpaired surrogates, and values
  nested more than 500 levels below the envelope object (`nesting.MAX_JCS_DEPTH`).
- Verifiers MUST refuse public keys that are not a strict encoding of a curve point (y ≥ p,
  x = 0 with the sign bit set, not on the curve) and keys of small order (8·A is the
  identity), before verifying anything (`ed25519.is_weak_public_key`). Under such a key a
  crafted signature verifies for every message. Verification itself follows OpenSSL: the
  cofactorless equation, S < L, R compared by its encoding. The TypeScript port assembles the
  same check from `@noble/curves` point arithmetic, because that library's own `verify`
  (ZIP-215 or strict RFC 8032) differs from OpenSSL on crafted inputs.

## 5. Sealed bodies, blind indexes, commitments

### 5.1 `enc`

- `enc` MUST be a JWE in General JSON Serialization (RFC 7516) with exactly this suite:
  protected header `{"enc":"A256GCM"}` and nothing else; no shared `unprotected` header and no
  top-level `header`; one entry per recipient in `recipients`, each with a header holding only
  `alg` = `"ECDH-ES+A256KW"`, `kid` and `epk`. Decryptors MUST refuse any other algorithm or
  header member (`sealed._check_pinned`).
- Key agreement is X25519 with the recipient's `keyAgreement` key (the `#kex-1` method of its
  DID). The plaintext is the RFC 8785 serialisation of the body, and it MUST decrypt to a JSON
  object, parsed under the same 2500-level cap.
- The signature covers `enc` as it stands: anyone can check who sealed a message without
  being able to read it.
- The relay seals legacy messages on the tags listed in `RELAY_ENCRYPT_TAGS` for the domain's
  key. A producer that signs its own envelope decides itself whether to seal.

### 5.2 `bix`

- A token is `base64url_unpadded(HMAC-SHA256(K, kind + ":" + value))` with `kind` `ie` (an
  Infrastructure Element id) or `tag`, and `K` a non-empty secret search key held by the
  domain (`sealed.blind_token`; the compose setup draws 32 random bytes).
- The relay adds a `tag` token and, when the body names one in `id`, an `ie` token.
- Tokens are deterministic: equal values under one key give equal tokens. They let a key
  holder find messages (`POST /lookup/blind`) without the explorer holding the key; they do
  not hide that two messages share a value.
- The explorer indexes at most 64 distinct tokens per message, each at most 256 characters.

### 5.3 `cmt`

- A commitment is `base64url_unpadded(BLAKE2b-256(salt || JCS(value)))` with a salt of
  exactly 16 random bytes (`commit.commit`). The member name says what is committed; the
  patched Trust Manager uses `rel`, `sec` and `rep` for its sub-scores.
- Disclosing `(value, salt)` later lets anyone recompute and compare (constant-time in the
  reference, `commit.verify`); a salt of another length never verifies.

## 6. Issuers and keys

- `iss` SHOULD be a `did:iota` DID. It MUST then be canonical:
  `did:iota:[<network>:]0x<64 lowercase hex>`, the network segment being 1 to 8 characters of
  `[a-z0-9]` and absent on mainnet (`ids.is_canonical_did`). A non-canonical `did:iota` DID is
  never resolved and the message is `FORGED`.
- `did:key` with an Ed25519 key (multicodec `0xed01`, base58btc `z…`) MAY be used; it resolves
  without a registry (`indexer/src/witness_indexer/didkey.py`).
- A DID longer than 128 characters is never resolved; the message is `FORGED`.
- Keys come from a resolver the verifier trusts, never from the envelope or the proof bundle.
  The witness resolver (anchor service `GET /resolve/{did}`) answers
  `{doc, version, keys: [{kid, type, publicKeyHex, revokedAtMs}], historyComplete}`; a key
  replaced under the same `kid` appears once per key with its own `revokedAtMs`. A reply
  nested deeper than 64 levels is unusable (`nesting.MAX_DOC_DEPTH`).
- A resolver that cannot be reached is not a verdict: the explorer retries the milestone, the
  relay answers 503, the proof verifier leaves step ④ unchecked. Only a definitive "no such
  key" makes a message `FORGED`.

## 7. Verdicts

Each tagged-data message gets exactly one verdict.

| Verdict | Meaning |
|---|---|
| `PRODUCER_SIGNED` | valid envelope with `att.mode = "producer"`, by an allowed writer, not replayed, key in force |
| `RELAY_ATTESTED` | the same with `att.mode = "relay"`: the relay vouches that it received the message from `att.sub` |
| `UNSIGNED_LEGACY` | not an envelope |
| `FORGED` | envelope tag differs from the block tag; `kid` does not belong to `iss`; the key cannot be resolved; the key is weak; the signature does not verify |
| `UNAUTHORIZED_WRITER` | valid signature by an issuer the writer policy does not allow on this tag |
| `REPLAY` | the issuer already used this `seq` or this `nonce` in another block |
| `REVOKED_KEY` | the key was revoked before or within the second of the confirming milestone |
| `MALFORMED` | the member rules of section 4 are broken, the envelope cannot be canonicalised or is nested too deep, or a validly signed body breaks the schema of its tag; also a payload on a known aeriOS tag that is not a JSON object |

The explorer decides in this order and stops at the first that applies
(`indexer/src/witness_indexer/classify.py`, `judge`):

1. JSON text over the 2500-level cap: `MALFORMED`.
2. Not an envelope: `UNSIGNED_LEGACY`, or `MALFORMED` on a tag of the schema registry whose
   payload is not a JSON object.
3. Envelope nested more than 64 levels (the explorer's storage limit, stricter than the
   canonicalisation cap): `MALFORMED`.
4. Structure, tag binding, key resolution and signature (`envelope.verify`): `MALFORMED` or
   `FORGED`.
5. Key revoked by the confirming milestone's second: `REVOKED_KEY`.
6. Issuer not allowed by the writer policy for the tag: `UNAUTHORIZED_WRITER`.
7. `seq`, then `nonce`, already used by the issuer in another stored block with a signed
   verdict: `REPLAY`.
8. Body breaks its tag's schema: `MALFORMED` (a sealed body cannot be inspected and is not
   judged on its schema).
9. Otherwise `PRODUCER_SIGNED` or `RELAY_ATTESTED`.

### 7.1 Writer policy

`core/src/witness_core/policy.py`. A JSON document
`{"version", "tags": {<tag>: {"allowed": [<DID>…], "require_signature", "legacy_grace"}},
"default": {…}}`; an unlisted tag uses `default`, and `"*"` allows any issuer. Its hash,
`BLAKE2b-256(JCS(policy))`, is committed in every checkpoint. On a tag with
`require_signature` and `legacy_grace` false, an unsigned message raises `UNSIGNED` and the
relay refuses unsigned uploads from callers without a Keycloak identity.

### 7.2 Sequence numbers and nonces

- An issuer MUST use strictly increasing `seq` values. The relay claims each `(iss, seq)`
  atomically before sending and refuses one not greater than the issuer's last (`REPLAY`).
- An issuer MUST NOT reuse a `nonce`.
- The explorer does not require increasing order: white-flag order is not issue order. A
  message is `REPLAY` only if another block of the same issuer with a signed verdict already
  carries the same `seq` or the same `nonce`; blocks are judged in milestone and white-flag
  order, so the first keeps its verdict.
- The relay never accepts an envelope whose `iss` is the relay's own DID: only the relay signs
  as itself.

### 7.3 Revocation

Milestone timestamps have one-second precision, so the moment a block was confirmed is only
known to lie inside that second. A key revoked at `revokedAtMs` may sign a message confirmed
by a milestone with timestamp `T` (seconds) only if it was never revoked or
`revokedAtMs ≥ (T + 1) × 1000` (`bundle.valid_through_second`). A revocation anywhere inside
the second, or before it, revokes. When a key was replaced under the same `kid`, the key in
force at `(T + 1) × 1000` is the one checked. The relay refuses a key whose `revokedAtMs` is
not in the future at submission time.

### 7.4 Chains and flows

- `prev` links a message to the issuer's previous block, forming a per-issuer hash chain. The
  explorer raises `CHAIN_GAP` when `prev` is not the issuer's last seen block and
  `CHAIN_FORK` when two messages continue from the same `prev`. The relay chains the messages
  it attests itself.
- `corr` groups the messages of one flow across issuers (`GET /flows/corr/{corr}`).
- `iat` more than 300 s away from the confirming milestone's timestamp raises `CLOCK_SKEW`.

## 8. Example

A producer envelope as the patched Trust Manager writes it (JCS form; keys sorted, no
whitespace; shortened here):

```json
{"att":{"mode":"producer"},"body":{"id":"MyDomain:fa163ed55867","score":0.053424256924272794},"cmt":{"rel":"nlfKag3LPLbAkRwx-BSsSyngANCPDjquEMJupB5UWGI"},"iat":1791338253662,"iss":"did:iota:testnet:0x15eb8c4d90fa4fff1d49f3ae8b1676a61e09c883303acd383cbfaacb538db9ba","kid":"did:iota:testnet:0x15eb8c4d90fa4fff1d49f3ae8b1676a61e09c883303acd383cbfaacb538db9ba#sig-1","nonce":"u0SchKtiuomrxADPPYl8ng","prev":"0xf9674179f833a5d471bd24887cd9dbe641b1ed4f176ea0d035753597bb519427","seq":1791332997848,"sig":"FhrBkdbDscGNcMTq9RYGgijzxwZxa0HLg0-i28Fh…","tag":"trust.score","w":1}
```

## 9. Test vectors

All in `core/tests/vectors/`, run by both implementations:

| File | Covers |
|---|---|
| `envelopes.json` | 21 cases with the exact signing input: valid producer, relay and `prev`/`corr` envelopes; every signed member tampered; tag rebinding; `seq` as string and as `7.0`; `w: 2`; padded and non-canonical signatures; `body` with `enc`; the small-order identity key with `R = identity, S = 0` |
| `sealed.json` | JWE for several recipients, a non-recipient, blind tokens (including non-ASCII values), commitments with a fixed 16-byte salt |
| `bundles.json` | 43 proof-bundle cases, including revocation inside, at and after the milestone second, replaced keys, hostile nesting at and past each cap |
| `witness_anchor.json` | `witness.anchor` mirror envelopes (section 10) |

## 10. Related formats

- **`witness.checkpoint`** (`core/src/witness_core/checkpoint.py`): the closed object
  `{v: 1, kind: "witness.checkpoint", network, domain, from: {index, id}, to: {index, id},
  msRoot, msgCount, policyHash, prev}`; `msRoot` is the TIP-4 Merkle root over the milestone
  ids `from..to`, `prev` the hash of the previous checkpoint or `null`; its hash is
  `BLAKE2b-256(JCS(checkpoint))`. On IOTA Rebased one Audit Trail record holds the JCS text as
  its data and `{"kind": "witness.checkpoint", "seq", "checkpointHash"}` as its metadata.
- **`witness.anchor`** (`core/src/witness_core/schema.py`): the body of the anchor service's
  mirror on the Tangle, exactly `{seq, checkpoint, checkpointHash, rebased: {network, trail,
  record, tx}}`, `checkpointHash` equal to the checkpoint's hash; producer-signed by the
  anchor DID. The explorer ingests mirrors only from the pinned anchor DID and never treats
  them as the on-chain record.
- **`audit.report`**: exactly `{reportHash, generatedAt, range?: {msFrom?, msTo?}, ie?}`, the
  report itself staying off the Tangle.
- **`witness-proof/v1`** (`core/src/witness_core/bundle.py`): the proof bundle, described with
  its five checks in [architecture.md](architecture.md#the-proof-ladder).
