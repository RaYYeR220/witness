"""`python -m witness_indexer`: run the indexer, and optionally submission ingest + validation.

    python -m witness_indexer --source inx --inx 127.0.0.1:9029 --rest http://127.0.0.1:14265 \\
        --db postgresql://postgres:…@127.0.0.1:5432/postgres --schema witness \\
        --policy policy.json [--mqtt mqtt://127.0.0.1:1883] [--validate]

With `--source inx` the node is read over INX; if INX does not answer at startup, the indexer
says so and polls the REST API instead (the choice is made once; a later INX outage is
retried on INX). `--mqtt` consumes the Messages API's submission records, `--validate`
checks every submitted block against the node (solid, confirmed, same bytes) and, every
`--reverify-every-s` seconds, compares every stored copy of a checked or indexed block with
the Tangle again (DB_TAMPER when the database was altered). A writer policy is required;
`--allow-any-writer` is the explicit opt-out for development.

Signing keys are resolved through the anchor service (`--resolver`, did:key needs nothing),
and the integrity rules run on every stored message, every `--periodic-s` seconds
(drift, stale, anchors, shadow writes) and every `--rescan-s` seconds against the Tangle
(rows missing from the database). An empty `--orion` turns the Orion rules off; an empty
`--resolver` disables DID resolution (did:iota signers are then FORGED).

The incident engine (Incident Explorer) runs after the rules on every message and pass,
grouping trust events into incidents; `--alerts-mqtt` (default: the `--mqtt` broker)
publishes each incident change to `witness/alerts/{severity}`. `--no-incidents` turns it off.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import signal
import sys
import time
from collections.abc import Awaitable, Callable, Coroutine
from typing import Any

from witness_core import policy
from witness_core.policy import WriterPolicy

from .anchors import default_anchor_did
from .incidents import (
    ENGINE_STATUS,
    MQTT_STATUS,
    CorrelatedRules,
    IncidentConfig,
    IncidentEngine,
    MqttAlertPublisher,
)
from .maintenance import Every, Rescanner
from .orion import OrionClient
from .pipeline import ALLOW_ALL, Indexer
from .resolver import DidResolver
from .rules import RulesConfig, RulesEngine
from .source import BlockSource, SourceUnavailable
from .source_inx import InxSource
from .source_rest import RestSource
from .store import Store

log = logging.getLogger("witness_indexer.main")

# (name, run, stop) of a long-running component
Service = tuple[str, Callable[[], Coroutine[Any, Any, None]], Callable[[], Awaitable[None]]]


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="witness-indexer", description=__doc__.split("\n")[0])
    p.add_argument("--source", choices=("inx", "rest"), default="inx",
                   help="how to read the node (default: inx, falling back to rest)")
    p.add_argument("--inx", default="127.0.0.1:9029", help="INX gRPC address")
    p.add_argument("--inx-timeout", type=float, default=5.0,
                   help="seconds to wait for INX before falling back to REST")
    p.add_argument("--rest", default="http://127.0.0.1:14265", help="HORNET REST API base URL")
    p.add_argument("--poll", type=float, default=1.0, help="REST polling interval in seconds")
    p.add_argument("--db", default=os.environ.get("WITNESS_DB"),
                   help="PostgreSQL DSN (default: $WITNESS_DB)")
    p.add_argument("--schema", default="witness", help="database schema")
    who = p.add_mutually_exclusive_group(required=True)
    who.add_argument("--policy", help="writer policy JSON (which DIDs may write which tags)")
    who.add_argument("--allow-any-writer", action="store_true",
                     help="development only: accept every signer for every tag")
    p.add_argument("--resolver", default="http://127.0.0.1:7300",
                   help="anchor service base URL for DID resolution (empty: did:key only)")
    p.add_argument("--anchor-did", default=os.environ.get("WITNESS_ANCHOR_DID"),
                   help="DID whose witness.anchor mirrors become anchors (default: "
                        "$WITNESS_ANCHOR_DID, else the `anchor` entry of "
                        "deploy/identity/<rebased network>.json; empty: off)")
    p.add_argument("--rebased-network",
                   default=os.environ.get("WITNESS_REBASED_NETWORK") or "testnet",
                   help="IOTA Rebased network of the identity file (default: testnet)")
    p.add_argument("--orion", default="http://127.0.0.1:1026",
                   help="Orion-LD base URL for the drift / unknown-IE rules (empty: off)")
    p.add_argument("--periodic-s", type=float, default=30.0,
                   help="seconds between periodic rule passes")
    p.add_argument("--rescan-s", type=float, default=300.0,
                   help="seconds between re-scans of indexed cones against the Tangle")
    p.add_argument("--rescan-batch", type=int, default=200,
                   help="milestones re-read from the node per re-scan")
    p.add_argument("--mqtt", default=os.environ.get("WITNESS_MQTT") or None,
                   help="consume submission records from this broker, e.g. "
                        "mqtt://user:password@127.0.0.1:1883 (default: $WITNESS_MQTT)")
    p.add_argument("--validate", action="store_true",
                   help="validate submitted blocks against the node's REST API")
    p.add_argument("--reverify-every-s", type=float, default=60.0,
                   help="with --validate: seconds between re-verification passes of the "
                        "stored copies against the Tangle (DB_TAMPER); 0 turns them off")
    p.add_argument("--incidents", action=argparse.BooleanOptionalAction, default=True,
                   help="correlate trust events into incidents (default: on)")
    p.add_argument("--alerts-mqtt", default=os.environ.get("WITNESS_ALERTS_MQTT"),
                   help="publish incident alerts to witness/alerts/{severity} on this broker "
                        "(default: $WITNESS_ALERTS_MQTT, else the --mqtt broker; empty: off)")
    p.add_argument("--incident-window-s", type=float, default=600.0,
                   help="events this close to an open incident's latest event join it")
    p.add_argument("--incident-quiet-s", type=float, default=1800.0,
                   help="an incident without events for this long closes (closed:quiet)")
    p.add_argument("--incident-drop", type=float, default=0.2,
                   help="trust score drop that opens an incident")
    p.add_argument("--stale-after-s", type=int, default=120,
                   help="R8 STALE: an IE with no trust score on the ledger for this long is "
                        "stale; at least twice the Trust Manager's scoreInterval (default: "
                        "120, for scoreInterval = 1 minute)")
    p.add_argument("--log-level", default="INFO")
    args = p.parse_args(argv)
    if args.stale_after_s <= 0:
        p.error("--stale-after-s must be positive")
    if not args.db:
        p.error("--db (or WITNESS_DB) is required")
    if args.anchor_did is None:
        args.anchor_did = default_anchor_did(args.rebased_network)
    return args


def writer_policy(args: argparse.Namespace) -> tuple[WriterPolicy, str]:
    """The writer policy and how it was chosen: "file" or "allow-any"."""
    if args.allow_any_writer:
        log.warning("--allow-any-writer: ANY signer may write ANY tag; UNAUTHORIZED_WRITER "
                    "will never be reported. Use a --policy file outside development.")
        return ALLOW_ALL, "allow-any"
    with open(args.policy, encoding="utf-8") as f:
        return policy.load(json.load(f)), "file"


async def open_source(args: argparse.Namespace) -> BlockSource:
    if args.source == "inx":
        inx = InxSource(args.inx, connect_timeout_s=args.inx_timeout)
        try:
            await inx.connect()
        except SourceUnavailable as e:
            await inx.close()
            log.warning("%s; falling back to REST polling of %s", e, args.rest)
        else:
            log.info("reading the node over INX at %s", args.inx)
            return inx
    log.info("reading the node over REST at %s (polling every %g s)", args.rest, args.poll)
    return RestSource(args.rest, poll_s=args.poll)


def build_rules(args: argparse.Namespace, store: Store, pol: WriterPolicy
                ) -> tuple[RulesEngine, DidResolver, OrionClient | None]:
    resolver = DidResolver(args.resolver or None)
    if not args.resolver:
        log.warning("no --resolver: DID resolution disabled; only did:key signers can be "
                    "verified, any other DID is reported FORGED (resolver: disabled)")
    orion = OrionClient(args.orion) if args.orion else None
    cfg = RulesConfig(stale_after_s=args.stale_after_s)
    return RulesEngine(store, orion, resolver, pol, cfg), resolver, orion


def build_incidents(args: argparse.Namespace, store: Store, orion: OrionClient | None,
                    pol: WriterPolicy) -> IncidentEngine | None:
    """The incident engine, or None with --no-incidents."""
    if not args.incidents:
        return None
    url = args.mqtt if args.alerts_mqtt is None else args.alerts_mqtt
    publisher = (MqttAlertPublisher(url, client_id=f"witness-indexer-alerts-{args.schema}")
                 if url else None)
    cfg = IncidentConfig(window_ms=int(args.incident_window_s * 1000),
                         quiet_close_ms=int(args.incident_quiet_s * 1000),
                         drop_threshold=args.incident_drop)
    return IncidentEngine(store, orion, cfg, publisher, policy=pol)


def _now_ms() -> int:
    return int(time.time() * 1000)


class _NoValidation:
    """Stands in for the validator when submissions are ingested without `--validate`."""

    def enqueue(self, block_id: bytes | None, sub_id: str) -> None:
        pass


async def amain(args: argparse.Namespace, *, stop: asyncio.Event | None = None) -> int:
    """Run until `stop` is set (or the process is interrupted); returns the exit code."""
    stop = stop or asyncio.Event()
    pol, policy_mode = writer_policy(args)
    store = await Store.open(args.db, schema=args.schema)
    services: list[Service] = []
    closers: list[Callable[[], Awaitable[None]]] = [store.close]
    try:
        await store.migrate()
        source = await open_source(args)
        closers.insert(0, source.close)
        rules, resolver, orion = build_rules(args, store, pol)
        closers.insert(0, resolver.aclose)
        if orion is not None:
            closers.insert(0, orion.aclose)
        if rules.anchor is not None:
            closers.insert(0, rules.anchor.aclose)
        incidents = build_incidents(args, store, orion, pol)
        if incidents is None:
            await store.set_service_status(ENGINE_STATUS, "disabled")
        else:
            # Same calls as the rules engine; the incident engine runs after the rules.
            rules = CorrelatedRules(rules, incidents)
            closers.insert(0, incidents.aclose)
            if incidents.publisher is None:
                await store.set_service_status(MQTT_STATUS, "disabled")
            else:
                services.append((MQTT_STATUS, incidents.run_publisher,
                                 incidents.stop_publisher))
        indexer = Indexer(source, store, policy=pol, policy_mode=policy_mode,
                          resolve=resolver, rules=rules, anchor_did=args.anchor_did or None)
        await indexer.anchors.publish_status(store)
        services.append(("indexer", indexer.run, indexer.stop))
        # Outside milestone transactions, in their own tasks.
        periodic = Every("rules", args.periodic_s,
                         lambda: rules.periodic(now_ms=_now_ms()))
        rescanner = Rescanner(source, store, rules, batch=args.rescan_batch)
        rescan = Every("re-scan", args.rescan_s, rescanner.run_once,
                       initial_delay_s=args.rescan_s)
        services.append(("rules", periodic.run, periodic.stop))
        services.append(("re-scan", rescan.run, rescan.stop))

        validator: Any = _NoValidation()
        if args.validate:
            from .hornet_rest import HornetRest
            from .validator import Validator, ValidatorConfig

            hornet = HornetRest(args.rest)
            closers.insert(0, hornet.close)
            validator = Validator(store, hornet, ValidatorConfig())
            resume = getattr(validator, "resume", None)  # pick up validations cut short
            if resume is not None:
                log.info("re-queued %d unfinished validations", await resume())
            services.append(("validator", validator.run, validator.stop))
            if args.reverify_every_s > 0:
                reverify = Every("re-verify", args.reverify_every_s,
                                 validator.scheduled_reverify,
                                 initial_delay_s=args.reverify_every_s)
                services.append(("re-verify", reverify.run, reverify.stop))
            else:
                await store.set_service_status("reverify", "disabled")
        if args.mqtt:
            from .ingest import MqttIngest

            ingest = MqttIngest(store, validator, args.mqtt)
            services.append(("ingest", ingest.run, ingest.stop))
        return await _supervise(services, stop)
    finally:
        for close in closers:
            try:
                await close()
            except Exception:
                log.exception("error while shutting down")


async def _supervise(services: list[Service], stop: asyncio.Event) -> int:
    loop = asyncio.get_running_loop()
    if sys.platform != "win32":
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, stop.set)
    tasks = {asyncio.create_task(run(), name=name): (name, halt)
             for name, run, halt in services}
    waiter = asyncio.create_task(stop.wait(), name="stop")
    code = 0
    try:
        done, _ = await asyncio.wait([*tasks, waiter], return_when=asyncio.FIRST_COMPLETED)
        for t in done:
            if t is waiter:
                log.info("shutting down")
                continue
            name = tasks[t][0]
            exc = None if t.cancelled() else t.exception()
            log.error("%s stopped unexpectedly%s", name, f": {exc!r}" if exc else "")
            code = 1
    finally:
        waiter.cancel()
        for t, (name, halt) in reversed(list(tasks.items())):
            if not t.done():
                try:
                    await halt()
                except Exception:
                    log.exception("error while stopping %s", name)
                t.cancel()
        await asyncio.gather(*tasks, waiter, return_exceptions=True)
        if sys.platform != "win32":
            for sig in (signal.SIGINT, signal.SIGTERM):
                loop.remove_signal_handler(sig)
    return code


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(level=args.log_level.upper(),
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)  # one line per request otherwise
    # psycopg's async driver needs a selector loop; Windows defaults to the proactor loop.
    factory = asyncio.SelectorEventLoop if sys.platform == "win32" else None
    with asyncio.Runner(loop_factory=factory) as runner:
        try:
            return runner.run(amain(args))
        except KeyboardInterrupt:  # Ctrl+C on Windows: amain's cleanup already ran
            log.info("interrupted")
            return 0
