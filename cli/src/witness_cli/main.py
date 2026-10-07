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
import unicodedata
from collections.abc import Callable
from pathlib import Path
from typing import Annotated, Any, NoReturn
from urllib.parse import quote

import httpx
import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text
from witness_core import bundle as wbundle
from witness_core import nesting, rebased
from witness_core.didkey import with_did_key
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


def strip_ctrl(s: str) -> str:
    """Make server text inert: no control (Cc) or format (Cf: bidi, zero-width) characters.

    Tabs, line and paragraph breaks become a space, so a value stays on one line.
    """
    kept = []
    for ch in s:
        cat = unicodedata.category(ch)
        if ch in "\t\n\r" or cat in ("Zl", "Zp"):
            kept.append(" ")
        elif cat not in ("Cc", "Cf"):
            kept.append(ch)
    return "".join(kept)


def out() -> Console:
    # Nothing a server or bundle says is ever interpreted as markup, emoji or ANSI.
    return Console(markup=False, emoji=False, highlight=False, soft_wrap=False)


def err_console() -> Console:
    return Console(stderr=True, markup=False, emoji=False, highlight=False, soft_wrap=False)


def cell(v: Any, style: str | None = None) -> Text:
    """An untrusted value as a plain, control-free cell."""
    return Text(strip_ctrl(short(v)), style=style or "")


def warn(message: str) -> None:
    err_console().print(Text(f"witness: warning: {' '.join(strip_ctrl(message).split())}"))


def fail(message: str, code: int = EXIT_ERROR) -> NoReturn:
    err_console().print(Text(f"witness: {' '.join(strip_ctrl(message).split())}"))
    raise typer.Exit(code)


def emit_json(doc: Any) -> None:
    # ASCII-escaped: control and C1 characters in server data cannot reach the terminal.
    typer.echo(json.dumps(doc, indent=2, ensure_ascii=True))


def read_json_file(path: Path, what: str, code: int = EXIT_ERROR) -> Any:
    try:
        return nesting.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        fail(f"cannot read {what} {path}: {exc.strerror or type(exc).__name__}", code)
    except nesting.JsonTooDeep as exc:
        fail(f"{what} {path} is {exc}", code)
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
        rebased_network = pick("rebasedNetwork", "rebased_network")
        trail = pick("trailId", "trail_id")
        rpc = pick("rebasedRpc", "rebased_rpc")
        package = pick("auditTrailPackage", "audit_trail_package")
        writer = pick("anchorWriter", "anchor_writer")
        if not isinstance(network, str) or not network:
            raise ValueError("network must be a non-empty string")
        if not isinstance(raw_keys, list) or not raw_keys:
            raise ValueError("trustedCoordinatorKeys must be a non-empty list")
        keys = {from_hex(k) for k in raw_keys}
        if any(len(k) != 32 for k in keys):
            raise ValueError("coordinator keys must be 32 bytes")
        if isinstance(threshold, bool) or not isinstance(threshold, int) or threshold < 1:
            raise ValueError("threshold must be a positive integer")
        for name, value in (("rebasedNetwork", rebased_network), ("trailId", trail),
                            ("rebasedRpc", rpc), ("auditTrailPackage", package),
                            ("anchorWriter", writer)):
            if value is not None and not isinstance(value, str):
                raise ValueError(f"{name} must be a string")
    except (ValueError, TypeError) as exc:
        fail(f"verifier config {path} is unusable: {exc}", EXIT_CONFIG)
    return wbundle.VerifierConfig(
        network=network, trusted_coordinator_keys=keys, threshold=threshold,
        rebased_network=rebased_network, trail_id=trail, rebased_rpc=rpc,
        audit_trail_package=package, anchor_writer=writer)


def did_resolver(base: str) -> Callable[[str], dict | None]:
    def resolve(did: str) -> dict | None:
        resp = httpx.get(f"{base.rstrip('/')}/resolve/{quote(did, safe='')}", timeout=TIMEOUT,
                         follow_redirects=False)
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return resp.json()

    return resolve


_STEP_STATUS = {True: ("ok", "green"), False: ("FAILED", "red"), None: ("not checked", "yellow")}
_OVERALL_STYLE = {"VALID": "bold green", "INVALID": "bold red", "PARTIAL": "bold yellow"}


def render_ladder(ladder: wbundle.Ladder) -> None:
    table = Table(title="Proof ladder")
    for col in ("#", "step", "result", "detail"):
        table.add_column(col)
    for i, s in enumerate(ladder.steps, 1):
        label, color = _STEP_STATUS[s.ok]
        table.add_row(str(i), cell(s.name), Text(label, style=color), cell(s.detail))
    c = out()
    c.print(table)
    # The verdict line comes from a fixed vocabulary, never from bundle or server text.
    c.print(Text(ladder.overall, style=_OVERALL_STYLE[ladder.overall]))


@app.command()
def verify(
    bundle: Annotated[str, typer.Argument(help="Bundle file ('-' for stdin), or a block id "
                                          "with --from-api")],
    config: Annotated[Path | None, typer.Option(
        "--config", envvar="WITNESS_VERIFIER_CONFIG",
        help="Pinned verifier config JSON (required)")] = None,
    anchor: Annotated[bool, typer.Option(
        "--anchor/--no-anchor", help="Check step 5 by reading the anchor record from the pinned "
        "IOTA Rebased RPC (the config must pin rebasedRpc, trailId and auditTrailPackage)")] = True,
    rebased_rpc: Annotated[str | None, typer.Option(
        "--rebased-rpc", envvar="WITNESS_REBASED_RPC",
        help="Override the pinned rebasedRpc (https JSON-RPC of an IOTA Rebased fullnode); "
        "the trail and package pins still apply, and a differing value is noted on stderr")] = None,
    insecure_rpc: Annotated[bool, typer.Option(
        "--insecure-rpc", help="Allow a plain-http Rebased RPC (local tests only)")] = False,
    resolver: Annotated[str | None, typer.Option(
        "--resolver", envvar="WITNESS_RESOLVER_URL",
        help="Trusted DID resolver URL (the anchor service's /resolve); use https")] = None,
    did_snapshot: Annotated[Path | None, typer.Option(
        "--did-snapshot", help="Trusted DID document file ({doc, version, keys})")] = None,
    from_api: Annotated[bool, typer.Option(
        "--from-api", help="Treat BUNDLE as a block id and fetch its bundle from the API")] = False,
    api: ApiOpt = DEFAULT_API,
    as_json: JsonOpt = False,
) -> None:
    """Verify a proof bundle offline: exit 0 VALID, 1 INVALID, 2 PARTIAL.

    The verifier config (--config) pins: network, trustedCoordinatorKeys, threshold and, for
    step 5, rebasedNetwork, trailId, rebasedRpc and auditTrailPackage (the package id in the
    trail object's type) and, optionally, anchorWriter (the address that writes the records).
    It is never taken from an API.
    """
    cfg = load_config(config)
    if from_api:
        doc = call("GET", api, f"/proofs/{quote(bundle, safe='')}")
        served = wbundle.served_block_id(doc)
        if served != bundle.lower():
            fail(f"the API served a proof for another block ({served or 'none'}), "
                 f"not {bundle}", EXIT_INVALID)
    elif bundle == "-":
        try:
            doc = nesting.loads(sys.stdin.read())
        except nesting.JsonTooDeep as exc:
            fail(f"stdin is {exc}")
        except ValueError:
            fail("stdin is not valid JSON")
    else:
        doc = read_json_file(Path(bundle), "bundle")

    resolve_did = None
    if did_snapshot is not None:
        snapshot = read_json_file(did_snapshot, "DID snapshot")
        resolve_did = lambda _did: snapshot
    elif resolver:
        if resolver.lower().startswith("http://"):
            warn("the DID resolver is plain http: issuer keys are fetched without "
                 "authentication; use https or --did-snapshot")
        resolve_did = did_resolver(resolver)
    fetch = None
    if rebased_rpc and rebased_rpc != cfg.rebased_rpc:
        warn(f"using Rebased RPC {rebased_rpc} instead of the pinned "
             f"{cfg.rebased_rpc or 'none'}")
    if anchor and (rebased_rpc or cfg.rebased_rpc):
        fetch = rebased.make_fetcher(cfg, rpc_url=rebased_rpc, timeout=TIMEOUT,
                                     allow_http=insecure_rpc)

    # A did:key signer is its own key: resolved here, never asked of the resolver (the
    # anchor service only resolves did:iota), as the indexer does.
    ladder = wbundle.verify(doc, cfg, fetch, with_did_key(resolve_did))
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
        table.add_row(*(cell(m.get(k)) for k in (
            "blockId", "date", "tag", "verdict", "ieId", "iss", "msIndex")))
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
    ms_from: Annotated[int | None, typer.Option("--ms-from", min=0,
                                                help="First milestone index")] = None,
    ms_to: Annotated[int | None, typer.Option("--ms-to", min=0,
                                              help="Last milestone index")] = None,
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
              "jsonpath": jsonpath, "cursor": cursor, "ms_from": ms_from, "ms_to": ms_to}
    params = {k: v for k, v in wanted.items() if v is not None} | {"limit": limit}
    page = call("GET", api, "/messages", params=params)
    if as_json:
        emit_json(page)
        return
    c = out()
    items = page.get("items", [])
    c.print(message_table(items, f"{len(items)} messages"))
    if page.get("nextCursor"):
        c.print(Text("next page: --cursor ") + cell(page["nextCursor"]))


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
    c.print(Text("canon hash: ") + cell(result.get("canonHash")))
    matches = result.get("matches", [])
    if matches:
        c.print(message_table(matches, f"{len(matches)} matches"))
    else:
        c.print(Text("no matching message"))


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
    table = Table(title=cell(f"Lineage of {ie_id} ({short(doc.get('total'))} messages)"))
    for col in ("seq", "kind", "verdict", "ms", "at", "score", "block id"):
        table.add_column(col, overflow="fold")
    for e in doc.get("entries", []):
        table.add_row(*(cell(e.get(k)) for k in (
            "seq", "kind", "verdict", "msIndex", "at", "score", "blockId")))
    c = out()
    c.print(table)
    ledger, orion = doc.get("ledger") or {}, doc.get("orion") or {}
    c.print(cell(f"ledger score: {short(ledger.get('score'))}   orion: "
                 f"{short(orion.get('value'))} ({short(orion.get('status'))})   drift: "
                 f"{short(doc.get('drift'))} (epsilon {short(doc.get('epsilon'))})"))


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
    c.print(cell(f"report hash: {short(result.get('reportHash'))}"))
    c.print(cell(f"anchored:    {short(result.get('anchored'))}  "
                 f"block: {short(result.get('blockId'))}"))
    if out_file is not None:
        c.print(cell(f"written to {out_file}"))


_SEVERITY_STYLE = {"high": "red", "medium": "yellow", "low": "cyan", "info": "white"}


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
    table = Table(title=cell(f"Node posture ({short(doc.get('scannedAt')) or 'never scanned'})"))
    for col in ("severity", "id", "title", "fix"):
        table.add_column(col, overflow="fold")
    for f in doc.get("findings", []):
        sev = f.get("severity")
        style = _SEVERITY_STYLE.get(sev) if isinstance(sev, str) else None  # unknown: plain
        table.add_row(cell(sev, style), cell(f.get("id")), cell(f.get("title")),
                      cell(f.get("fix")))
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
    """Generate an Ed25519 signing key; only the public half is printed.

    The private JWK is written to <out-dir>/<component>/sig-1.jwk.json with mode 0600 and an
    existing file is never overwritten. On Windows the mode is not enforced: the file inherits
    the folder's ACL, so put --out-dir in a user-private folder (or tighten it with icacls).
    """
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
    c.print(cell(f"kid:         {kid}"))
    c.print(cell(f"public JWK:  {json.dumps(public)}"))
    c.print(cell(f"private key: {target} (keep it secret; it is not shown)"))
    if sys.platform == "win32":
        warn("Windows does not enforce file mode 0600; keep the key in a user-private folder")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
