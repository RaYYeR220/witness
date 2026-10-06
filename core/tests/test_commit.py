import pytest
from witness_core import commit


def test_commit_verify():
    salt = b"\x01" * 16
    c = commit.commit(0.42, salt)
    assert commit.verify(c, 0.42, salt)
    assert not commit.verify(c, 0.43, salt)
    assert not commit.verify(c, 0.42, b"\x02" * 16)


def test_new_salt_is_random_16_bytes():
    a, b = commit.new_salt(), commit.new_salt()
    assert len(a) == 16 and a != b


def test_shifted_salt_attack_rejected():
    salt = b"" * 16
    c = commit.commit(0.42, salt)
    assert not commit.verify(c, 42, salt + b"0.")
    assert not commit.verify(c, 42, salt[:-1])


@pytest.mark.parametrize("salt", [b"", b"" * 15, b"" * 17])
def test_bad_salt_length_rejected(salt):
    with pytest.raises(ValueError):
        commit.commit(1, salt)
    assert not commit.verify("x", 1, salt)


def test_verify_non_str_commitment():
    assert not commit.verify(None, 1, b"" * 16)  # type: ignore[arg-type]
    assert not commit.verify(b"abc", 1, b"" * 16)  # type: ignore[arg-type]
