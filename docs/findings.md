# Constructive findings in the aeriOS IOTA stack

Security and correctness findings about the aeriOS IOTA stack as it ships, each with where it
is, what it means and a concrete fix. F1 to F7 are also reported by the Witness node posture
scanner (`GET /posture`, `POST /posture/scan`, `api/src/witness_api/posture.py`); F8 to F12
come from reading the aeriOS sources while building the explorer.

Every finding cites file and line in the upstream repositories at the commits below. "Observed
live" means we saw it on our own local stack, which runs the organisers' configuration
unchanged except that our compose override publishes every port on loopback only. Nothing was
probed on anyone else's infrastructure; the scanner is passive by default and sends active
probes only to loopback or explicitly allowed hosts.

| Repository | Commit |
|---|---|
| `eclipse-aerios/iota-tangle` | `7803e5d` (2026-10-05) |
| `eclipse-aerios/iota-messages-api` | `1ed089a` (2026-10-05); image `eclipseaerios/iota-messages-api:1.0.2` |
| `eclipse-aerios/trust-manager` | `17d46f2` (2026-02-18) |
| `eclipse-aerios/self-orchestrator` | `c42da00` (2026-09-01) |
| `eclipse-aerios/llo-docker-operator` | `3a37dc0` (2026-09-02) |
| `eclipse-aerios/llo-k8s` | `5d4cce9` (2026-07-23) |
| `iotaledger/hornet` | `3ab9641` (branch `develop`) |

## F1 — Milestones are signed with IOTA's public sample coordinator keys (high)

**What.** The private Tangle's coordinator signs milestones with the sample key pair IOTA
publishes for private-tangle tutorials. Whoever has those keys (anyone) can produce milestones
that every node of this network accepts as genuine. The Tangle's integrity then rests on
nothing.

**Where.** `iota-tangle/docker/config_private_tangle.json:20-31` pins the public keys
`ed3c3f1a…b3b1248c` and `f6752f5f…28ef349c`; the private keys are in clear in
`docker/main/hornet-main.yaml:11` and `docker/main/startup.yaml:22` (`COO_PRV_KEYS`). The same
pair is published in `iotaledger/hornet` `private_tangle/private_tangle_keys.md:4-7`.

**Impact.** Observed live: our milestones are signed with exactly these keys. A milestone made
offline with them passes signature verification: the proof vector `valid_anchored` in
`core/tests/vectors/bundles.json` is one, and `witness verify` accepts its signatures (see
[JUDGES.md](../JUDGES.md#2-verify-a-bundle-yourself)). Witness's step ⑤, a checkpoint on IOTA
Rebased, is the check that still tells such a milestone apart.

**Fix.** Generate a coordinator key pair per deployment (`hornet tool ed25519-key`), put the
public keys in `protocol.publicKeyRanges` and the private keys in `COO_PRV_KEYS` from a secret
store, not the compose file, and bootstrap a new Tangle. Keep the sample keys for throwaway
networks only.

## F2 — Administrative REST routes answer without authentication (high)

**What.** The node's whole REST API is public, including the routes that change the node:
`POST /api/core/v2/control/database/prune` (delete ledger history), `POST
/api/core/v2/control/snapshots/create`, `POST /api/core/v2/peers` and `DELETE
/api/core/v2/peers/{peerId}` (change who the node talks to), and `GET /api/core/v2/peers`
(peer topology).

**Where.** `iota-tangle/docker/config_private_tangle.json:51-55`: `restAPI.publicRoutes` is
`["/health", "/api/*"]` and `restAPI.protectedRoutes` is empty. HORNET's own defaults
(`hornet/components/restapi/params.go:43-66`) list only read routes as public and protect
`/api/*`; the aeriOS config overrides that. The routes are registered in
`hornet/components/coreapi/component.go:442-493`.

**Impact.** Observed live: `GET /api/core/v2/peers` answers 200 without credentials. The write
routes were not called; their exposure follows from the configuration.

**Fix.** Drop the `publicRoutes` override and use HORNET's defaults, or list only the routes
clients need (health, info, blocks, milestones, …). Issue JWTs with `hornet tool jwt-api` to
the few callers that need the protected routes.

## F3 — INX is reachable without authentication (medium)

**What.** INX, the gRPC interface HORNET's extensions (coordinator, dashboard, inx-poi) use to
drive the node, has no authentication and listens on all interfaces. Any client that reaches
it can read the ledger, submit blocks and mount its own REST routes on the node.

**Where.** `iota-tangle/docker/main/hornet-main.yaml:40-41` (`--inx.enabled=true`,
`--inx.bindAddress=0.0.0.0:9029`) and `:30` (port 9029 published on every host interface).

**Impact.** Observed live, by design of our own explorer: Witness registers `/api/witness/v1`
on the node through INX `RegisterAPIRoute` with no credential, and the node then serves it
under its public `/api/*`. Any INX client can do the same. The scanner itself only checks that
a TCP connection succeeds and sends no gRPC.

**Fix.** Publish 9029 on loopback or a private interface only, keep it off shared networks,
and let only your own extensions reach it (network policy). Our
`deploy/compose/hornet-loopback.yml` does the first.

## F4 — Debug API enabled and public (low)

**What.** HORNET's debug API (`/api/debug/v1/*`) is enabled and public. It exposes internal
node state useful for reconnaissance.

**Where.** `iota-tangle/docker/main/hornet-main.yaml:42` (`--debug.enabled=true`); public
through `/api/*` in `config_private_tangle.json:51-54` (HORNET's defaults also list
`/api/debug/v1/*` as public, `params.go:54`).

**Impact.** Observed live: `GET /api/debug/v1/requests` answers 200 without credentials.

**Fix.** Drop `--debug.enabled` in production; if it is needed, move `/api/debug/v1/*` to
`restAPI.protectedRoutes`. (`restAPI.debugRequestLoggerEnabled` is already off,
`config_private_tangle.json:59`.)

## F5 — Dashboard ships with admin/admin (high)

**What.** inx-dashboard is configured with the default `admin`/`admin` login, which grants full
dashboard control, and is published on all interfaces.

**Where.** `iota-tangle/docker/main/hornet-main.yaml:44` (`##Default credentials are
admin/admin`), `:56-57` (the default `passwordHash` and `passwordSalt`), `:52` (port 31011 on
every host interface).

**Impact.** From the configuration. The scanner's active check (`check_dashboard` in
`api/src/witness_api/posture.py`) tries the login, only against a loopback or allow-listed
dashboard, and never records the session token. Not re-checked for this write-up.

**Fix.** `hornet tool pwd-hash`, then set `--dashboard.auth.username`,
`--dashboard.auth.passwordHash` and `--dashboard.auth.passwordSalt` to fresh values from a
secret store, and publish the port on loopback only.

## F6 — The Messages API sends requests wherever the caller's `node` points (medium)

**What.** The Messages API builds the URL it posts to from the caller's `node` query parameter
by string concatenation: a server-side request forgery. A value such as
`attacker.example:8080/any/path?` makes the server send
`POST http://attacker.example:8080/any/path?:14265/api/core/v2/blocks`, so the caller chooses
host, port and path, and gets the response body back in `return_payload`.

**Where.** `iota-messages-api/send_data.py:13`
(`node = "http://" + request.args.get("node") + ":14265/api/core/v2/blocks"`), `:39`
(`requests.request("POST", node, …)`), `:45-48` (the response text returned to the caller);
`:51` and `docker-compose.yaml:9-10` (listening and published on all interfaces).

**Impact.** Anyone who can reach the API can make it send HTTP POSTs, with the block JSON as
body, to any host the API can reach, internal services included, and read the replies. From
the source; not exercised.

**Fix.** Accept only configured node names, each mapped to a fixed base URL, and answer 400 to
anything else. The Witness relay does exactly that (`RELAY_ALLOWED_NODES`,
`relay/src/witness_relay/app.py`).

## F7 — Payloads are written to the Tangle in plaintext (info)

**What.** Tagged-data payloads are public and replicated to every peer, for good. Trust scores,
IE identifiers (`<Domain>:<MAC>`) and orchestration events are readable by anyone who can read
the Tangle.

**Where.** Every writer; the Messages API posts `json.dumps(message)` as is
(`send_data.py:16-19`). The scanner reports the share of stored messages that are not
encrypted (`messages.encrypted` in the explorer's database).

**Fix.** Seal sensitive tags. The Witness relay encrypts listed tags to the domain's X25519
key (`RELAY_ENCRYPT_TAGS`) and adds keyed blind index tokens so they can still be found by IE
and tag ([envelope-spec.md](envelope-spec.md#5-sealed-bodies-blind-indexes-commitments)).

## F8 — The Messages API runs with Flask's debugger on all interfaces (medium)

**What.** The Messages API sets `app.debug = True` and serves on `0.0.0.0` with Flask's
development server. Any unhandled exception returns the Werkzeug interactive debugger page:
full traceback, source lines and file paths, and a Python console locked by a PIN that the
server prints to its standard output. A request without `node` is enough to raise one
(`"http://" + None`).

**Where.** `iota-messages-api/send_data.py:8` (`app.debug = True`), `:51`
(`app.run(port=5555, host='0.0.0.0')`), `:13` (the exception).

**Impact.** Observed live on our local `eclipseaerios/iota-messages-api:1.0.2` container:
`POST /upload` without `node` answers 500 with the "Werkzeug Debugger" page, `EVALEX = true`,
the console asking for the PIN, and the traceback through `/app/send_data.py`. Source and
paths are disclosed to any caller; anyone who can also read the container's logs gets a
Python shell inside the container.

**Fix.** Remove `app.debug = True`, serve with a production WSGI server (gunicorn, for
example), and validate `node` (F6) so the request cannot fail this way.

## F9 — Rejected blocks are reported as success (medium)

**What.** The Messages API answers HTTP 200 whatever HORNET answered, with HORNET's status only
inside the JSON (`status_code`). Its callers check the HTTP status, so a block the node
refused is logged as written by every aeriOS writer.

**Where.** `iota-messages-api/send_data.py:45-48` (`jsonify(...)` without a status, so 200);
the callers: `trust-manager/src/trustmanager/main.py:421` (`raise_for_status()`),
`llo-docker-operator/internal/iota/iotaTangle.go:74` and `llo-k8s/pkg/iota/iotaTangle.go:74`
(`res.StatusCode >= 400`), `self-orchestrator/script.js:322` and `:356` (only failed requests
reach `.catch`).

**Impact.** A trust score or orchestration event that never reached the Tangle looks, to the
component that wrote it, exactly like one that did. From the source.

**Fix.** Return HORNET's status (or 502 when the node refused) as the HTTP status. The Witness
relay answers 502 with HORNET's body when the node rejects a block and keeps the legacy body
shape otherwise (`relay/tests/test_legacy_contract.py::test_hornet_error_is_502_with_body`).

## F10 — No aeriOS writer keeps the block id (medium)

**What.** HORNET returns the id of every block it accepts. The Messages API hands it back only
inside a string (`return_payload` is HORNET's response text), stores nothing, and every caller
drops the response. No aeriOS component can later name the block that holds a message it
wrote, so none of it can be looked up or checked against the Tangle; the brief's checks (c)
and (d) start from a block id.

**Where.** `iota-messages-api/send_data.py:39-48`;
`trust-manager/src/trustmanager/main.py:419-420` (prints the response, keeps nothing);
`llo-docker-operator/internal/iota/iotaTangle.go:67-77` and `llo-k8s/pkg/iota/iotaTangle.go:67-77`
(the body is never read); `self-orchestrator/script.js:316-325` and `:350-359` (the response
is unused).

**Fix.** Return `blockId` as a field of the Messages API's answer and store it with the event
that caused the write, for example as an attribute next to `trustScore` on the Orion entity.
The Witness relay returns it as `witness.blockId`, keeps a receipt per block
(`GET /receipts`), and forwards it to the explorer with the exact bytes sent.

## F11 — Trust Manager uses `trust_score` before assigning it (medium)

**What.** `update_trust_score` and `update_trust_scores` assign `trust_score` (and
`current_timestamp`) only when the IE has an entry in local storage, but use them
unconditionally afterwards.

**Where.** `trust-manager/src/trustmanager/main.py:271-279` (`update_trust_score`) and
`:294-304` (`update_trust_scores`). IEs come from Orion when they have an
`internalIpAddress` (`:337-345`); storage entries come from the reliability, security and
reputation passes, and `storage.py:76` returns `None` for an IE it does not hold.

**Impact.** For an IE that Orion lists but local storage does not hold yet (for example one
registered after the last reliability pass):

- in the scheduled `update_trust_scores`, when no IE before it in the loop had data,
  `UnboundLocalError` at `:300`. The job runs from `schedule.run_pending()` in a daemon thread
  (`src/start.py:9-12`, `:190-193`), and the `schedule` library does not catch job exceptions,
  so the thread ends and periodic scoring stops while the HTTP API keeps running;
- when an earlier IE had data, that IE's score and timestamp are written to Orion and to the
  Tangle under this IE's id (`:300`, `:304`).

From the source; not reproduced live.

**Fix.** `continue` when `data is None` (and return early in `update_trust_score`), or compute
and write inside the `if`.

## F12 — self-orchestrator reads `AEROS_*` while its deployment sets `AERIOS_*` (medium)

**What.** The code reads `AEROS_IOTA`, `AEROS_IOTA_URL`, `AEROS_IOTA_NODE` and `AEROS_EAT_URL`;
the compose file, the Helm chart and the README set and document `AERIOS_IOTA`,
`AERIOS_IOTA_URL`, `AERIOS_IOTA_NODE` and `AERIOS_EAT_URL`.

**Where.** `self-orchestrator/script.js:309`, `:315-316`, `:344`, `:349-350` (reads);
`docker-compose.yml:12-15`, `helm-chart/templates/orchestrator/daemonset.yaml:70-77` and
`README.md:23-32` (set and documented).

**Impact.** Deployed as documented, `process.env.AEROS_IOTA` is undefined: the
self-orchestrator writes nothing to IOTA, without any error, and its alerts to the EAT go to
`http://undefined/async-function/…`. From the source.

**Fix.** Read the documented `AERIOS_*` names (accepting both during a transition) and fail at
startup when IOTA is enabled but its URL or node is missing.
