# Constructive findings — node security posture

These are constructive security findings about the aeriOS IOTA stack as it ships, surfaced by
the Witness node posture scanner (`GET /posture`, `POST /posture/scan`; spec §4.8). Each one
lists **what** we observe, the **evidence**, and a concrete **fix**. The scanner is passive by
default (only `GET`/`HEAD`/`OPTIONS` and a TCP connect); active probes run only against our own
loopback deployment.

All of these fire against our own local stack — that is the point: we run the vendor's
`iota-tangle` configuration unchanged, so the findings are reproducible rather than theoretical.

## F1 — Milestones signed with public sample coordinator keys (high)

**What.** The coordinator signs milestones with the well-known IOTA private-tangle sample key
pair, which is published in the open. Anyone can produce milestones that every node on the
network accepts as genuine, which defeats the ledger's integrity guarantee.

**Evidence.** `protocol.publicKeyRanges` in `iota-tangle/docker/config_private_tangle.json`
(mirrored in `iotaledger/hornet` `private_tangle/config_private_tangle.json`) pins
`ed3c3f1a319ff4e909cf2771d79fece0ac9bd9fd2ee49ea6c0885c9cb3b1248c` and
`f6752f5f46a53364e2ee9c4d662d762a81efd51010282a75cd6bd03f28ef349c`. The matching private keys
are in `private_tangle/private_tangle_keys.md` and in the `COO_PRV_KEYS` environment variable
of the `inx-coordinator` service. Our live milestones are signed with exactly these keys.

**Fix.** Generate a fresh coordinator key pair (`hornet tool ed25519-key`), set
`protocol.publicKeyRanges` to the new public keys and `COO_PRV_KEYS` to the new private keys,
and bootstrap a new private tangle. Never ship the sample keys outside throwaway test networks.

## F2 — Administrative REST routes answer without authentication (high)

**What.** The node exposes every REST route publicly, including destructive control endpoints.
`POST /api/core/v2/control/database/prune` can wipe ledger history and `GET /api/core/v2/peers`
discloses the peer topology — both without a token.

**Evidence.** `restAPI.publicRoutes` is `["/health", "/api/*"]` with an empty
`restAPI.protectedRoutes` (`config_private_tangle.json`). A probe gets a non-`401`/`403` answer:
`GET /api/core/v2/peers` returns `200`, and the prune route is reached (its handler answers
`405`/`400`, not `401`), i.e. no credentials are required. HORNET's auth middleware runs before
method dispatch, so a protected route would answer `401` even for a wrong method.

**Fix.** Keep only the routes clients need in `restAPI.publicRoutes` (health, info, blocks,
milestones, …) and move `/api/core/v2/control/*` and `/api/core/v2/peers` into
`restAPI.protectedRoutes`. Issue JWT tokens with `hornet tool jwt-api` for the few callers that
need the admin surface.

## F3 — INX gRPC port reachable without authentication (medium)

**What.** The INX port (`:9029`) speaks an unauthenticated gRPC protocol with full node access
(it is how coordinator, dashboard and PoI extensions drive the node). Anything that can reach
the port has node-level control.

**Evidence.** A TCP connect to the configured INX address succeeds (connect only; the scanner
sends no gRPC). HORNET is started with `--inx.bindAddress=0.0.0.0:9029`.

**Fix.** Bind `--inx.bindAddress` to `127.0.0.1` (or a private interface), keep the port off any
public network, and use network policy so only your own INX extensions can reach it.

## F4 — Debug REST API enabled (low)

**What.** The debug API (`/api/debug/v1/*`) is enabled and public. It exposes internal node
state useful for reconnaissance.

**Evidence.** The node is run with `--debug.enabled=true`, `/api/debug/v1/*` is in
`restAPI.publicRoutes`, and `GET /api/debug/v1/requests` returns `200`.

**Fix.** Run the node without `--debug.enabled`, set `restAPI.debugRequestLoggerEnabled` off,
and remove `/api/debug/v1/*` from `restAPI.publicRoutes` in production.

## F5 — Dashboard accepts default admin/admin credentials (high, active)

**What.** The inx-dashboard ships with the default `admin`/`admin` login, which grants full
dashboard control. This check runs only actively, and only against our own loopback dashboard.

**Evidence.** `--dashboard.auth.passwordHash`/`--dashboard.auth.passwordSalt` in
`iota-tangle/docker/main/hornet-main.yaml` are the published defaults (the compose file even
comments `##Default credentials are admin/admin`). A login with `admin`/`admin` at
`/dashboard/auth` is accepted (the issued session token is never recorded by the scanner).

**Fix.** Generate a new hash with `hornet tool pwd-hash` and set
`--dashboard.auth.passwordHash`, `--dashboard.auth.passwordSalt` and
`--dashboard.auth.username` to fresh values.

## F6 — Messages API builds its upstream URL from the client's `node` parameter (medium)

**What.** The aeriOS IOTA Messages API constructs the node URL it connects to directly from the
caller-supplied `node` query parameter — a server-side request forgery (SSRF): a caller chooses
which host the server talks to.

**Evidence.** `eclipse-aerios/iota-messages-api` `send_data.py`:
`node = "http://" + request.args.get("node") + ":14265/api/core/v2/blocks"`.

**Fix.** Validate `node` against an allow-list of known node names that map to fixed base URLs
and reject anything else with `400`. This is exactly what the Witness relay does
(`RELAY_ALLOWED_NODES`), so an attacker can never steer the server at an arbitrary host.

## F7 — Message payloads written to the Tangle in plaintext (info)

**What.** Tagged-data payloads are stored on the Tangle in plaintext and are world-readable
forever. The scanner reports the share of stored messages that are not encrypted.

**Evidence.** The explorer's `messages.encrypted` column: the ratio of plaintext to total
messages observed in the parallel database.

**Fix.** For tags that carry sensitive detail, enable the relay's envelope encryption
(`RELAY_ENCRYPT_TAGS` with recipient X25519 keys). The blind index still allows lookup by tag
and IE id without disclosing the content.
