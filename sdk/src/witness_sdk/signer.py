"""Producer-side signing: build `witness/v1` envelopes and send them through the relay."""

from __future__ import annotations

import json
import os
import threading
import time
from collections.abc import Mapping
from typing import Any

import httpx
from witness_core import commit, envelope

from .keys import load_component, load_key_file

_BLOCK_ID_LEN = 66  # "0x" + 32 bytes


class WitnessSigner:
    """Signs as one component. `seq` and `prev` (the block id of the last successful
    upload) live in `state_path`, so they survive restarts and are shared by every
    signer pointed at the same file."""

    def __init__(self, iss: str, kid: str, key_path: str, state_path: str):
        self.iss, self.kid = iss, kid
        self._key, _ = load_key_file(key_path)
        self._state_path = state_path
        self._lock = threading.Lock()

    # -- state ---------------------------------------------------------------------

    def _read(self) -> dict[str, Any]:
        try:
            with open(self._state_path, encoding="utf-8") as f:
                state = json.load(f)
        except FileNotFoundError:
            return {"seq": 0, "prev": None}
        return {"seq": int(state.get("seq", 0)), "prev": state.get("prev")}

    def _write(self, state: dict[str, Any]) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(self._state_path)), exist_ok=True)
        tmp = f"{self._state_path}.{os.getpid()}.{threading.get_ident()}.tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(state, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self._state_path)

    # -- sealing -------------------------------------------------------------------

    def seal(
        self,
        tag: str,
        body: dict,
        commitments: dict[str, Any] | None = None,
        *,
        min_seq: int = 0,
    ) -> tuple[dict, dict[str, str]]:
        """Sign `body` for `tag`. `commitments` maps names to values; the envelope
        carries salted commitments and the salts (hex) are returned, never sent."""
        salts: dict[str, bytes] = {}
        cmt: dict[str, str] | None = None
        if commitments:
            cmt = {}
            for name, value in commitments.items():
                salts[name] = commit.new_salt()
                cmt[name] = commit.commit(value, salts[name])
        with self._lock:
            state = self._read()
            seq = max(state["seq"] + 1, min_seq)
            env = envelope.seal(
                tag,
                body,
                iss=self.iss,
                kid=self.kid,
                sign_key=self._key,
                seq=seq,
                att_mode="producer",
                cmt=cmt,
                prev=state["prev"],
            )
            self._write({"seq": seq, "prev": state["prev"]})
        return env, {k: v.hex() for k, v in salts.items()}

    def _record_block(self, block_id: str) -> None:
        with self._lock:
            state = self._read()
            self._write({"seq": state["seq"], "prev": block_id})

    # -- upload --------------------------------------------------------------------

    def upload(
        self,
        relay_url: str,
        node: str,
        tag: str,
        body: dict,
        commitments: dict[str, Any] | None = None,
        *,
        timeout: float = 15.0,
    ) -> dict:
        """Seal and POST to the relay. Returns the relay's JSON reply plus `http_status`,
        and `salts` when commitments were made. A REPLAY refusal (our seq fell behind
        the relay's) is retried once with seq jumped to the current time in ms."""
        url = relay_url.rstrip("/") + "/upload"
        min_seq = 0
        for attempt in (1, 2):
            env, salts = self.seal(tag, body, commitments, min_seq=min_seq)
            resp = httpx.post(
                url, params={"node": node}, json={"tag": tag, "message": env}, timeout=timeout
            )
            try:
                reply = resp.json()
            except ValueError:
                reply = {"error": resp.text}
            if not isinstance(reply, dict):
                reply = {"error": reply}
            if resp.status_code == 403 and reply.get("verdict") == "REPLAY" and attempt == 1:
                min_seq = max(env["seq"] + 1, int(time.time() * 1000))
                continue
            break
        block_id = (reply.get("witness") or {}).get("blockId")
        if resp.status_code == 200 and isinstance(block_id, str) and len(block_id) == _BLOCK_ID_LEN:
            self._record_block(block_id)
        if salts:
            reply["salts"] = salts
        reply["http_status"] = resp.status_code
        return reply


def signer_from_env(env: Mapping[str, str]) -> WitnessSigner | None:
    """Build a signer from WITNESS_* variables, or None when none are set."""
    state = env.get("WITNESS_STATE_PATH") or "witness-state.json"
    key_path = env.get("WITNESS_KEY_PATH")
    if key_path:
        _, jwk_kid = load_key_file(key_path)
        kid = env.get("WITNESS_KID") or jwk_kid
        if not kid:
            raise ValueError("WITNESS_KID is required for a key file without a kid")
        return WitnessSigner(env.get("WITNESS_ISS") or kid.partition("#")[0], kid, key_path, state)
    component = env.get("WITNESS_COMPONENT")
    if component:
        secrets_dir = env.get("WITNESS_SECRETS_DIR") or "secrets"
        iss, kid, _ = load_component(component, secrets_dir)
        return WitnessSigner(
            iss, kid, os.path.join(secrets_dir, component, "sig-1.jwk.json"), state
        )
    return None
