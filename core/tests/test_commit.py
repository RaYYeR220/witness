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
