"""`witness`: offline proof verifier and query client for the Witness explorer.

Exit codes of `verify`: 0 VALID, 1 INVALID, 2 PARTIAL. Elsewhere: 3 missing or
unusable configuration (verifier config, token), 4 input, network or API errors.
"""

from __future__ import annotations

import base64
import json
import os
import re
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Annotated, Any, NoReturn
from urllib.parse import quote

import httpx
import typer
from rich.console import Console
from rich.table import Table
from witness_core import bundle as wbundle
from witness_core.ids import from_hex

EXIT_VALID, EXIT_INVALID, EXIT_PARTIAL, EXIT_CONFIG, EXIT_ERROR = 0, 1, 2, 3, 4
DEFAULT_API = "http://127.0.0.1:7200"
TIMEOUT = 15.0

app = typer.Typer(add_help_option=True, no_args_is_help=True, pretty_exceptions_enable=False,
                  help="Verify Witness proof bundles offline and query a Witness explorer.")
keys_app = typer.Typer(no_args_is_help=True, help="Component signing keys.")
app.add_typer(keys_app, name="keys")

ApiOpt = Annotated[str, typer.Option("--api", envvar="WITNESS_API_URL", help="Explorer API URL")]
JsonOpt = Annotated[bool, typer.Option("--json", help="Machine-readable output")]
TokenFileOpt = Annotated[Path | None, typer.Option(
    "--token-file", help="Read the bearer token from this file (default: the environment)")]


def out() -> Console:
    return Console(highlight=False, soft_wrap=False)


def fail(message: str, code: int = EXIT_ERROR) -> NoReturn:
    typer.echo(f"witness: {message}", err=True)
    raise typer.Exit(code)


def emit_json(doc: Any) -> None:
    typer.echo(json.dumps(doc, indent=2, ensure_ascii=False))


def read_json_file(path: Path, what: str, code: int = EXIT_ERROR) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        fail(f"cannot read {what} {path}: {exc.strerror or type(exc).__name__}", code)
    except ValueError:
        fail(f"{what} {path} is not valid JSON", code)


# ---------------------------------------------------------------- HTTP

def call(method: str, base: str, path: str, *, token: str | None = None,
         params: dict[str, Any] | None = None, body: Any = None) -> Any:
    """One API call; every failure becomes a one-line error and exit 4."""
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    url = base.rstrip("/") + path
    try:
        with httpx.Client(timeout=TIMEOUT, follow_redirects=False) as client:
            resp = client.request(method, url, params=params, json=body, headers=headers)
    except httpx.HTTPError as exc:
        fail(f"cannot reach {base}: {type(exc).__name__}")
    if resp.status_code >= 400:
        detail: Any = None
        try:
            doc = resp.json()
            detail = doc.get("detail") or doc.get("error") if isinstance(doc, dict) else None
        except ValueError:
            pass
        fail(f"{method} {path}: HTTP {resp.status_code}" + (f": {str(detail)[:300]}" if detail else ""))
    try:
        return resp.json()
    except ValueError:
        fail(f"{method} {path}: response is not JSON")


def token_from(env_name: str, token_file: Path | None, *, required: bool) -> str | None:
    """Bearer tokens come from a file or the environment, never from an argument."""
    token: str | None = None
    if token_file is not None:
        try:
            token = token_file.read_text(encoding="utf-8").strip()
        except OSError as exc:
            fail(f"cannot read token file {token_file}: {exc.strerror or type(exc).__name__}",
                 EXIT_CONFIG)
    else:
        token = os.environ.get(env_name, "").strip() or None
    if required and not token:
        fail(f"no token: set {env_name} or pass --token-file", EXIT_CONFIG)
    return token or None


# ---------------------------------------------------------------- verify

def load_config(path: Path | None) -> wbundle.VerifierConfig:
    """The pinned verifier config. It is never fetched from the network."""
    if path is None:
        fail("no verifier config: pass --config <file> or set WITNESS_VERIFIER_CONFIG "
             "(verification is pinned to a local file, never to what an API serves)", EXIT_CONFIG)
    doc = read_json_file(path, "verifier config", EXIT_CONFIG)

    def pick(camel: str, snake: str) -> Any:
        return doc.get(camel, doc.get(snake)) if isinstance(doc, dict) else None

    try:
        network = pick("network", "network")
        raw_keys = pick("trustedCoordinatorKeys", "trusted_coordinator_keys")
        threshold = pick("threshold", "threshold")
        rebased = pick("rebasedNetwork", "rebased_network")
        trail = pick("trailId", "trail_id")
        if not isinstance(network, str) or not network:
            raise ValueError("network must be a non-empty string")
        if not isinstance(raw_keys, list) or not raw_keys:
            raise ValueError("trustedCoordinatorKeys must be a non-empty list")
        keys = {from_hex(k) for k in raw_keys}
        if any(len(k) != 32 for k in keys):
            raise ValueError("coordinator keys must be 32 bytes")
        if isinstance(threshold, bool) or not isinstance(threshold, int) or threshold < 1:
            raise ValueError("threshold must be a positive integer")
        if rebased is not None and not isinstance(rebased, str):
            raise ValueError("rebasedNetwork must be a string")
        if trail is not None and not isinstance(trail, str):
            raise ValueError("trailId must be a string")
    except (ValueError, TypeError) as exc:
        fail(f"verifier config {path} is unusable: {exc}", EXIT_CONFIG)
    return wbundle.VerifierConfig(network=network, trusted_coordinator_keys=keys,
                                  threshold=threshold, rebased_network=rebased, trail_id=trail)


def anchor_fetcher(base: str, cfg: wbundle.VerifierConfig) -> Callable[[dict], dict | None]:
    """Reads the on-chain record via the anchor service; only the pinned trail counts."""

    def fetch(anchor: dict) -> dict | None:
        record = anchor["rebased"]["record"]
        resp = httpx.get(f"{base.rstrip('/')}/checkpoints/{record}", timeout=TIMEOUT,
                         follow_redirects=False)
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        doc = resp.json()
        if not (isinstance(doc, dict) and doc.get("source") == "chain"
                and doc.get("trail") == cfg.trail_id and doc.get("network") == cfg.rebased_network
                and doc.get("record") == record):
            raise ValueError("anchor service answered for another trail, network or record")
        return {k: doc[k] for k in ("checkpointHash", "checkpoint") if k in doc}

    return fetch


def did_resolver(base: str) -> Callable[[str], dict | None]:
    def resolve(did: str) -> dict | None:
        resp = httpx.get(f"{base.rstrip('/')}/resolve/{quote(did, safe='')}", timeout=TIMEOUT,
                         follow_redirects=False)
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return resp.json()

    return resolve


def render_ladder(ladder: wbundle.Ladder) -> None:
    table = Table(title="Proof ladder")
    for col in ("#", "step", "result", "detail"):
        table.add_column(col)
    style = {True: "[green]ok[/]", False: "[red]FAILED[/]", None: "[yellow]not checked[/]"}
    for i, s in enumerate(ladder.steps, 1):
        table.add_row(str(i), s.name, style[s.ok], s.detail, end_section=False)
    c = out()
    c.print(table)
    color = {"VALID": "green", "INVALID": "red", "PARTIAL": "yellow"}[ladder.overall]
    c.print(f"[bold {color}]{ladder.overall}[/]")


@app.command()
def verify(
    bundle: Annotated[str, typer.Argument(help="Bundle file ('-' for stdin), or a block id "
                                          "with --from-api")],
    config: Annotated[Path | None, typer.Option(
        "--config", envvar="WITNESS_VERIFIER_CONFIG",
        help="Pinned verifier config JSON (required)")] = None,
    anchor: Annotated[bool, typer.Option(
        "--anchor/--no-anchor", help="Check step 5 against the anchor service when one is "
        "configured")] = True,
    anchor_url: Annotated[str | None, typer.Option(
        "--anchor-url", envvar="WITNESS_ANCHOR_URL", help="Anchor service URL")] = None,
    resolver: Annotated[str | None, typer.Option(
        "--resolver", envvar="WITNESS_RESOLVER_URL",
        help="Trusted DID resolver URL (the anchor service's /resolve)")] = None,
    did_snapshot: Annotated[Path | None, typer.Option(
        "--did-snapshot", help="Trusted DID document file ({doc, version, keys})")] = None,
    from_api: Annotated[bool, typer.Option(
        "--from-api", help="Treat BUNDLE as a block id and fetch its bundle from the API")] = False,
    api: ApiOpt = DEFAULT_API,
    as_json: JsonOpt = False,
) -> None:
    """Verify a proof bundle offline: exit 0 VALID, 1 INVALID, 2 PARTIAL."""
    cfg = load_config(config)
    if from_api:
        doc = call("GET", api, f"/proofs/{quote(bundle, safe='')}")
    elif bundle == "-":
        try:
            doc = json.loads(sys.stdin.read())
        except ValueError:
            fail("stdin is not valid JSON")
    else:
        doc = read_json_file(Path(bundle), "bundle")

    resolve_did = None
    if did_snapshot is not None:
        snapshot = read_json_file(did_snapshot, "DID snapshot")
        resolve_did = lambda _did: snapshot
    elif resolver:
        resolve_did = did_resolver(resolver)
    fetch = anchor_fetcher(anchor_url, cfg) if anchor and anchor_url else None

    ladder = wbundle.verify(doc, cfg, fetch, resolve_did)
    if as_json:
        emit_json({"overall": ladder.overall, "steps": [
            {"name": s.name, "ok": s.ok, "detail": s.detail} for s in ladder.steps]})
    else:
        render_ladder(ladder)
    raise typer.Exit({"VALID": EXIT_VALID, "INVALID": EXIT_INVALID,
                      "PARTIAL": EXIT_PARTIAL}[ladder.overall])


# ---------------------------------------------------------------- queries

def short(v: Any) -> str:
    return "" if v is None else str(v)


def message_table(rows: list[dict], title: str) -> Table:
    table = Table(title=title)
    for col in ("block id", "date", "tag", "verdict", "IE", "issuer", "ms"):
        table.add_column(col, overflow="fold")
    for m in rows:
        table.add_row(short(m.get("blockId")), short(m.get("date")), short(m.get("tag")),
                      short(m.get("verdict")), short(m.get("ieId")), short(m.get("iss")),
                      short(m.get("msIndex")))
    return table


@app.command()
def search(
    tag: Annotated[str | None, typer.Option(help="Exact tag")] = None,
    ie: Annotated[str | None, typer.Option(help="Infrastructure Element id")] = None,
    iss: Annotated[str | None, typer.Option(help="Issuer DID")] = None,
    verdict: Annotated[str | None, typer.Option(help="Envelope verdict")] = None,
    kind: Annotated[str | None, typer.Option(help="Envelope kind")] = None,
    since: Annotated[str | None, typer.Option(help="From this date or time (ISO 8601)")] = None,
    until: Annotated[str | None, typer.Option(help="Up to this date or time (ISO 8601)")] = None,
    block_id: Annotated[str | None, typer.Option("--block-id", help="Block id")] = None,
    query: Annotated[str | None, typer.Option("--query", "-q", help="Full-text in the body")] = None,
    jsonpath: Annotated[str | None, typer.Option(help="path=value inside the JSON body")] = None,
    cursor: Annotated[str | None, typer.Option(help="Continue from a previous page")] = None,
    limit: Annotated[int, typer.Option(min=1, max=500)] = 50,
    api: ApiOpt = DEFAULT_API,
    as_json: JsonOpt = False,
) -> None:
    """Search stored messages."""
    wanted = {"tag": tag, "ie": ie, "iss": iss, "verdict": verdict, "kind": kind,
              "date_from": since, "date_to": until, "block_id": block_id, "q": query,
              "jsonpath": jsonpath, "cursor": cursor}
    params = {k: v for k, v in wanted.items() if v is not None} | {"limit": limit}
    page = call("GET", api, "/messages", params=params)
    if as_json:
        emit_json(page)
        return
    c = out()
    c.print(message_table(page.get("items", []), f"{len(page.get('items', []))} messages"))
    if page.get("nextCursor"):
        c.print(f"next page: --cursor {page['nextCursor']}")


@app.command()
def lookup(
    file: Annotated[Path, typer.Argument(help="JSON document to look up by canonical hash")],
    api: ApiOpt = DEFAULT_API,
    as_json: JsonOpt = False,
) -> None:
    """Find the ledger messages whose body is this document (RFC 8785 hash match)."""
    result = call("POST", api, "/lookup", body=read_json_file(file, "document"))
    if as_json:
        emit_json(result)
        return
    c = out()
    c.print(f"canon hash: {short(result.get('canonHash'))}")
    matches = result.get("matches", [])
    if matches:
        c.print(message_table(matches, f"{len(matches)} matches"))
    else:
        c.print("no matching message")


@app.command()
def lineage(
    ie_id: Annotated[str, typer.Argument(help="Infrastructure Element id")],
    limit: Annotated[int, typer.Option(min=1, max=10000)] = 1000,
    api: ApiOpt = DEFAULT_API,
    as_json: JsonOpt = False,
) -> None:
    """Score lineage of an IE against Orion."""
    doc = call("GET", api, f"/ie/{quote(ie_id, safe=':')}/lineage", params={"limit": limit})
    if as_json:
        emit_json(doc)
        return
    table = Table(title=f"Lineage of {ie_id} ({doc.get('total', 0)} messages)")
    for col in ("seq", "kind", "verdict", "ms", "at", "score", "block id"):
        table.add_column(col, overflow="fold")
    for e in doc.get("entries", []):
        table.add_row(short(e.get("seq")), short(e.get("kind")), short(e.get("verdict")),
                      short(e.get("msIndex")), short(e.get("at")), short(e.get("score")),
                      short(e.get("blockId")))
    c = out()
    c.print(table)
    ledger, orion = doc.get("ledger") or {}, doc.get("orion") or {}
    c.print(f"ledger score: {short(ledger.get('score'))}   orion: {short(orion.get('value'))} "
            f"({short(orion.get('status'))})   drift: {short(doc.get('drift'))} "
            f"(epsilon {short(doc.get('epsilon'))})")


@app.command()
def report(
    ie: Annotated[str | None, typer.Option(help="Limit to one Infrastructure Element")] = None,
    ms_from: Annotated[int | None, typer.Option("--from", min=0, help="First milestone")] = None,
    ms_to: Annotated[int | None, typer.Option("--to", min=0, help="Last milestone")] = None,
    out_file: Annotated[Path | None, typer.Option("--out", help="Write the full result JSON")] = None,
    report_hash: Annotated[str | None, typer.Option(
        "--hash", help="Fetch an existing report instead of building one")] = None,
    token_file: TokenFileOpt = None,
    api: ApiOpt = DEFAULT_API,
    as_json: JsonOpt = False,
) -> None:
    """Build and anchor an audit report (token: WITNESS_REPORT_TOKEN), or fetch one by hash."""
    if report_hash:
        result = call("GET", api, f"/reports/{quote(report_hash, safe='')}")
    else:
        token = token_from("WITNESS_REPORT_TOKEN", token_file, required=True)
        body = {k: v for k, v in {"ie": ie, "msFrom": ms_from, "msTo": ms_to}.items()
                if v is not None}
        result = call("POST", api, "/reports", token=token, body=body)
    if out_file is not None:
        try:
            out_file.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n",
                                encoding="utf-8")
        except OSError as exc:
            fail(f"cannot write {out_file}: {exc.strerror or type(exc).__name__}")
    if as_json:
        emit_json(result)
        return
    c = out()
    c.print(f"report hash: {short(result.get('reportHash'))}")
    c.print(f"anchored:    {short(result.get('anchored'))}  block: {short(result.get('blockId'))}")
    if out_file is not None:
        c.print(f"written to {out_file}")


@app.command()
def posture(
    scan: Annotated[bool, typer.Option("--scan", help="Run a new passive scan "
                                       "(WITNESS_POSTURE_TOKEN)")] = False,
    active: Annotated[bool, typer.Option("--active", help="Scan with active probes "
                                         "(implies --scan)")] = False,
    token_file: TokenFileOpt = None,
    api: ApiOpt = DEFAULT_API,
    as_json: JsonOpt = False,
) -> None:
    """Show the last node posture scan, or run a new one."""
    if scan or active:
        token = token_from("WITNESS_POSTURE_TOKEN", token_file, required=True)
        doc = call("POST", api, "/posture/scan", token=token,
                   params={"active": "true" if active else "false"})
    else:
        doc = call("GET", api, "/posture")
    if as_json:
        emit_json(doc)
        return
    table = Table(title=f"Node posture ({short(doc.get('scannedAt')) or 'never scanned'})")
    for col in ("severity", "id", "title", "fix"):
        table.add_column(col, overflow="fold")
    colors = {"high": "red", "medium": "yellow", "low": "cyan", "info": "white"}
    for f in doc.get("findings", []):
        sev = short(f.get("severity"))
        table.add_row(f"[{colors.get(sev, 'white')}]{sev}[/]", short(f.get("id")),
                      short(f.get("title")), short(f.get("fix")))
    out().print(table)


# ---------------------------------------------------------------- keys

_COMPONENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


@keys_app.command("gen")
def keys_gen(
    component: Annotated[str, typer.Argument(help="Component name, e.g. relay or sdk-demo")],
    out_dir: Annotated[Path, typer.Option("--out-dir", help="Secrets directory")] = Path("secrets"),
    did: Annotated[str | None, typer.Option(help="Issuer DID, to form the kid <did>#sig-1")] = None,
    as_json: JsonOpt = False,
) -> None:
    """Generate an Ed25519 signing key. The private JWK goes to a file; only the public half is printed."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    if not _COMPONENT.fullmatch(component):
        fail("component must be a plain name (letters, digits, '.', '_', '-')")
    kid = f"{did or component}#sig-1"
    key = Ed25519PrivateKey.generate()
    public = {"kty": "OKP", "crv": "Ed25519", "x": _b64u(key.public_key().public_bytes_raw()),
              "kid": kid}
    private = public | {"d": _b64u(key.private_bytes_raw())}
    target = out_dir / component / "sig-1.jwk.json"
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
                     0o600)
    except FileExistsError:
        fail(f"{target} already exists; refusing to overwrite a key")
    except OSError as exc:
        fail(f"cannot create {target}: {exc.strerror or type(exc).__name__}")
    with os.fdopen(fd, "wb") as f:
        f.write((json.dumps(private, indent=2) + "\n").encode("ascii"))
    if as_json:
        emit_json({"component": component, "kid": kid, "publicJwk": public,
                   "keyFile": str(target)})
        return
    c = out()
    c.print(f"kid:         {kid}")
    c.print(f"public JWK:  {json.dumps(public)}")
    c.print(f"private key: {target} (keep it secret; it is not shown)")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
