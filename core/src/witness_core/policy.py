"""Writer allow-list policy: which issuers may write to which tags."""

from __future__ import annotations

from dataclasses import dataclass, field

from . import canon


@dataclass(frozen=True)
class TagRule:
    allowed: list[str]
    require_signature: bool
    legacy_grace: bool


@dataclass(frozen=True)
class WriterPolicy:
    version: int
    tags: dict[str, TagRule] = field(default_factory=dict)
    default: TagRule = field(default_factory=lambda: TagRule([], False, True))


def _rule(d: dict) -> TagRule:
    return TagRule(
        allowed=list(d.get("allowed", [])),
        require_signature=bool(d.get("require_signature", False)),
        legacy_grace=bool(d.get("legacy_grace", True)),
    )


def _rule_dict(r: TagRule) -> dict:
    return {
        "allowed": list(r.allowed),
        "require_signature": r.require_signature,
        "legacy_grace": r.legacy_grace,
    }


def load(d: dict) -> WriterPolicy:
    return WriterPolicy(
        version=int(d["version"]),
        tags={tag: _rule(r) for tag, r in d.get("tags", {}).items()},
        default=_rule(d.get("default", {})),
    )


def to_dict(p: WriterPolicy) -> dict:
    return {
        "version": p.version,
        "tags": {tag: _rule_dict(r) for tag, r in p.tags.items()},
        "default": _rule_dict(p.default),
    }


def policy_hash(p: WriterPolicy) -> bytes:
    return canon.canon_hash(to_dict(p))


def allowed(p: WriterPolicy, tag: str, iss: str) -> bool:
    """True if `iss` may write `tag`; unlisted tags use the default rule."""
    rule = p.tags.get(tag, p.default)
    return "*" in rule.allowed or iss in rule.allowed
