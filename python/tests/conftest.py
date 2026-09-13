"""Shared pytest fixtures for testing avogadro.connect against a fake
Avogadro RPC server (fake_rpc_server.FakeRPCServer).
"""

import pytest

from _load_avogadro import load_connect_module
from fake_rpc_server import FakeRPCServer

connect = load_connect_module().connect


@pytest.fixture
def fake_server():
    """A FakeRPCServer listening on its own throwaway socket name."""
    with FakeRPCServer() as server:
        yield server


@pytest.fixture
def avo(fake_server):
    """A connect() instance already talking to fake_server."""
    with connect(name=fake_server.name) as client:
        yield client
