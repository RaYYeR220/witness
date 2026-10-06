import pytest
from witness_api.settings import Settings

K1 = "0x" + "ED" * 32
K2 = "0x" + "f6" * 32


def test_from_env_defaults_and_lists():
    s = Settings.from_env({
        "WITNESS_DB": "postgresql://x", "WITNESS_COORDINATOR_KEYS": f" {K1}, {K2} ,",
        "WITNESS_CORS_ORIGINS": "http://a.test,http://b.test", "WITNESS_VALIDATE": "0",
        "WITNESS_TRAIL_ID": "", "WITNESS_INGEST_TOKEN": "x" * 20,
    })
    assert s.coordinator_keys == [K1.lower(), K2]
    assert s.threshold == 2  # every pinned key must sign unless told otherwise
    assert s.cors_origins == ["http://a.test", "http://b.test"]
    assert s.validate is False and s.trail_id is None
    assert s.port == 7200 and s.host == "127.0.0.1" and s.node_route == "witness/v1"
    assert s.hornet_url == "http://127.0.0.1:14265" and s.inx_addr is None
    assert s.network == "private_tangle1" and s.schema == "witness"


@pytest.mark.parametrize("env, message", [
    ({}, "WITNESS_DB"),
    ({"WITNESS_COORDINATOR_KEYS": "0x1234"}, "coordinator key"),
    ({"WITNESS_COORDINATOR_KEYS": K1, "WITNESS_THRESHOLD": "2"}, "threshold"),
    ({"WITNESS_THRESHOLD": "0"}, "threshold"),
    ({"WITNESS_INGEST_TOKEN": "short"}, "16 characters"),
    ({"WITNESS_PORT": "http"}, "WITNESS_PORT"),
    ({"WITNESS_VALIDATE": "maybe"}, "WITNESS_VALIDATE"),
])
def test_from_env_rejects_bad_values(env, message):
    if env:
        env = {"WITNESS_DB": "postgresql://x", **env}
    with pytest.raises(ValueError, match=message):
        Settings.from_env(env)


def test_validation_belongs_to_the_indexer_by_default():
    s = Settings.from_env({"WITNESS_DB": "postgresql://x"})
    assert s.validate is False
    assert s.verify_token is None and s.verify_concurrency == 4 and s.verify_cooldown_s == 20
    assert s.stream_max_subscribers == 200


def test_empty_hornet_url_disables_node_calls():
    assert Settings.from_env({"WITNESS_DB": "x", "WITNESS_HORNET_URL": ""}).hornet_url is None
    assert Settings.from_env({"WITNESS_DB": "x", "WITNESS_HORNET_URL": "http://n:1"}).hornet_url \
        == "http://n:1"


def test_verify_token_from_env():
    s = Settings.from_env({"WITNESS_DB": "x", "WITNESS_VERIFY_TOKEN": "v" * 24})
    assert s.verify_token == "v" * 24
    with pytest.raises(ValueError, match="WITNESS_VERIFY_TOKEN"):
        Settings.from_env({"WITNESS_DB": "x", "WITNESS_VERIFY_TOKEN": "short"})
