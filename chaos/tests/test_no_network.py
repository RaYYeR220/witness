"""The autouse guard in conftest cuts every real connection a chaos test could open.

The port is 9 (discard) on loopback, so even a broken guard sends nothing anywhere."""

import socket

import httpx
import pytest

TARGET = ("127.0.0.1", 9)


def _expect_blocked(attempts, fn):
    with pytest.raises(AssertionError, match="network access attempted"):
        fn()
    assert attempts, "the guard did not record the attempt"
    attempts.clear()  # this test made the attempt on purpose


def test_sync_sockets_are_blocked(_never_reach_a_stack):
    _expect_blocked(_never_reach_a_stack, lambda: socket.create_connection(TARGET, 1))

    def raw():
        with socket.socket() as s:
            s.connect(TARGET)

    _expect_blocked(_never_reach_a_stack, raw)
    _expect_blocked(_never_reach_a_stack,
                    lambda: httpx.get(f"http://{TARGET[0]}:{TARGET[1]}/", timeout=1))


async def test_async_http_is_blocked(_never_reach_a_stack):
    async with httpx.AsyncClient(timeout=1) as http:
        with pytest.raises(Exception):  # noqa: B017 - httpx may wrap the guard's error
            await http.get(f"http://{TARGET[0]}:{TARGET[1]}/")
    assert _never_reach_a_stack, "the guard did not record the attempt"
    _never_reach_a_stack.clear()


async def test_postgres_is_blocked(_never_reach_a_stack):
    import psycopg

    with pytest.raises(AssertionError, match="network access attempted"):
        await psycopg.AsyncConnection.connect("postgresql://u:p@127.0.0.1:9/x")
    with pytest.raises(AssertionError, match="network access attempted"):
        psycopg.connect("postgresql://u:p@127.0.0.1:9/x")
    _never_reach_a_stack.clear()


def test_socketpair_still_works():
    a, b = socket.socketpair()
    a.close()
    b.close()
