import random

import pytest
from witness_chaos import forge
from witness_core import bundle, checkpoint


def ladder(b, cfg, fetch):
    return {s.name: s.ok for s in bundle.verify(b, cfg, fetch).steps}


def test_real_bundle_baseline(real_bundle, cfg):
    got = ladder(real_bundle, cfg, lambda _a: forge.real_anchor_record(real_bundle))
    assert [got[n] for n in ("block_hash", "inclusion", "milestone_signatures")] == [True] * 3
    assert got["anchor"] is True


def test_forge_offline_and_sig_valid(real_bundle, cfg, sample_keys, no_network):
    fake = forge.forge_milestone_bundle(real_bundle, sample_keys)
    got = ladder(fake, cfg, lambda _a: forge.real_anchor_record(real_bundle))
    assert got["block_hash"] is True
    assert got["inclusion"] is True
    assert got["milestone_signatures"] is True
    assert got["anchor"] is False
    assert bundle.verify(fake, cfg, lambda _a: forge.real_anchor_record(real_bundle)).overall \
        == "INVALID"
    # Same milestone index, different milestone and block.
    assert fake["milestone"]["index"] == real_bundle["milestone"]["index"]
    assert fake["milestone"]["id"] != real_bundle["milestone"]["id"]
    assert fake["block"]["id"] != real_bundle["block"]["id"]


def test_forge_is_red_even_without_a_record_fetcher(real_bundle, cfg, sample_keys):
    fake = forge.forge_milestone_bundle(real_bundle, sample_keys)
    steps = {s.name: s for s in bundle.verify(fake, cfg).steps}
    assert steps["anchor"].ok is False
    assert "not in anchored checkpoint" in steps["anchor"].detail


def test_forge_accepts_seed_only_keys(real_bundle, cfg, sample_keys):
    fake = forge.forge_milestone_bundle(real_bundle, [k[:32] for k in sample_keys])
    assert ladder(fake, cfg, None)["milestone_signatures"] is True


def test_one_sample_key_is_below_threshold(real_bundle, cfg, sample_keys):
    fake = forge.forge_milestone_bundle(real_bundle, sample_keys[:1])
    assert ladder(fake, cfg, None)["milestone_signatures"] is False


def test_forge_needs_keys_and_anchor(real_bundle, sample_keys):
    with pytest.raises(ValueError):
        forge.forge_milestone_bundle(real_bundle, [])
    with pytest.raises(ValueError):
        forge.forge_milestone_bundle({**real_bundle, "anchor": None}, sample_keys)


def test_forge_does_not_mutate_input(real_bundle, sample_keys):
    import copy

    before = copy.deepcopy(real_bundle)
    forge.forge_milestone_bundle(real_bundle, sample_keys)
    assert real_bundle == before


@pytest.mark.parametrize("seed", range(10))
def test_byte_flip_fails_block_hash(real_bundle, cfg, seed):
    b = forge.tamper_bundle(real_bundle, "byte_flip", random.Random(seed))
    assert ladder(b, cfg, None)["block_hash"] is False


@pytest.mark.parametrize("seed", range(10))
def test_bad_merkle_path_fails_inclusion(real_bundle, cfg, seed):
    b = forge.tamper_bundle(real_bundle, "merkle_path", random.Random(seed))
    got = ladder(b, cfg, None)
    assert got["inclusion"] is False
    assert got["block_hash"] is True


def test_doctored_checkpoint_only_red_against_the_record(real_bundle, cfg):
    b = forge.tamper_bundle(real_bundle, "checkpoint", random.Random(1))
    assert checkpoint.shape_error(b["anchor"]["checkpoint"]) is None
    assert b["anchor"]["checkpoint"]["msgCount"] > real_bundle["anchor"]["checkpoint"]["msgCount"]
    got = ladder(b, cfg, lambda _a: forge.real_anchor_record(real_bundle))
    assert got["anchor"] is False
    assert got["block_hash"] and got["inclusion"] and got["milestone_signatures"]
    assert ladder(b, cfg, None)["anchor"] is None  # no record: undecided, never green


def test_tamper_rejects_unknown_kind(real_bundle):
    with pytest.raises(ValueError):
        forge.tamper_bundle(real_bundle, "nope")  # type: ignore[arg-type]
