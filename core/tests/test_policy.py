from witness_core import canon, policy


def _policy_dict():
    return {
        "version": 1,
        "tags": {
            "trust.score": {"allowed": ["did:A"], "require_signature": True, "legacy_grace": False},
            "LLO-K8s": {"allowed": ["*"], "require_signature": False, "legacy_grace": True},
        },
        "default": {"allowed": [], "require_signature": False, "legacy_grace": True},
    }


def test_policy_allowed():
    p = policy.load(_policy_dict())
    assert policy.allowed(p, "trust.score", "did:A") is True
    assert policy.allowed(p, "trust.score", "did:B") is False
    assert policy.allowed(p, "LLO-K8s", "did:anyone") is True
    assert policy.allowed(p, "unlisted", "did:A") is False


def test_policy_default_wildcard():
    d = _policy_dict()
    d["default"]["allowed"] = ["*"]
    assert policy.allowed(policy.load(d), "unlisted", "did:Z") is True


def test_policy_hash_stable():
    d = _policy_dict()
    reordered = {
        "default": d["default"],
        "tags": dict(reversed(list(d["tags"].items()))),
        "version": 1,
    }
    a, b = policy.load(d), policy.load(reordered)
    assert policy.policy_hash(a) == policy.policy_hash(b)
    assert policy.policy_hash(a) == canon.canon_hash(policy.to_dict(a))
    assert policy.to_dict(policy.load(policy.to_dict(a))) == policy.to_dict(a)
