"""
Tests for the length-prefix wire framing itself -- the part most likely
to be subtly wrong, per the MCP bridge plan. A reply larger than what a
single recv() call returns must still be read correctly.

Two angles are covered:

* A unit test that feeds connect._read_exactly()/._read() a hostile
  transport that only ever hands back a few bytes per call, regardless
  of how much was asked for. This is deterministic -- it does not depend
  on OS socket buffer sizes, which vary by platform and are not under
  test control.
* An end-to-end test through a real Unix domain socket and the fake
  server, with a payload large enough (multiple MB) that it is for all
  practical purposes certain to arrive across more than one recv() on
  every platform this runs on, as a realistic check that the two halves
  agree with each other.
"""

import json
import struct

from _load_avogadro import load_connect_module

_mod = load_connect_module()
connect = _mod.connect


class _ChunkedSocket:
    """
    A minimal socket stand-in that hands back only a few bytes per call,
    no matter how much the caller asked for. A read loop that assumes one
    recv() returns everything it asked for will read truncated or garbled
    data against this.
    """

    def __init__(self, data, chunk_size=3):
        self._data = data
        self._chunk_size = chunk_size
        self._pos = 0
        self.recv_calls = 0

    def recv(self, size):
        self.recv_calls += 1
        if self._pos >= len(self._data):
            return b""
        end = min(self._pos + min(size, self._chunk_size), len(self._data))
        chunk = self._data[self._pos : end]
        self._pos = end
        return chunk

    def settimeout(self, *_args, **_kwargs):
        pass

    def close(self):
        pass


def _make_client_with_socket(sock):
    """A connect instance wired to a fake socket, bypassing __init__ (and
    therefore the real network connection it would otherwise make)."""
    client = connect.__new__(connect)
    client._windows = False
    client.sock = sock
    return client


def test_read_exactly_survives_many_short_reads():
    payload = {"jsonrpc": "2.0", "id": 1, "result": {"blob": "x" * 5000}}
    body = json.dumps(payload).encode("utf-8")
    packet = struct.pack(">I", len(body)) + body

    sock = _ChunkedSocket(packet, chunk_size=7)
    client = _make_client_with_socket(sock)

    response = client._read()

    assert response == payload
    # Sanity: this really did require multiple recv() calls, i.e. the
    # test is actually exercising the loop and not a lucky single read.
    assert sock.recv_calls > len(packet) / 7


def test_read_exactly_handles_reads_that_split_the_length_header():
    # The 4-byte length header itself can arrive split across recv()
    # calls -- a chunk size smaller than 4 forces that.
    payload = {"jsonrpc": "2.0", "id": 2, "result": True}
    body = json.dumps(payload).encode("utf-8")
    packet = struct.pack(">I", len(body)) + body

    sock = _ChunkedSocket(packet, chunk_size=1)
    client = _make_client_with_socket(sock)

    response = client._read()

    assert response == payload


def test_large_reply_over_a_real_socket(avo, fake_server):
    # A multi-megabyte listCommands reply, round-tripped through the real
    # Unix domain socket connect() actually uses, and the fake server's
    # real send loop -- not just the unit-level mock above.
    big_commands = [
        {
            "name": "command%05d" % i,
            "description": "Test command number %d." % i,
            "kind": "extension",
            "plugin": "FakePlugin",
            "async": False,
            "schema": {},
        }
        for i in range(20000)
    ]
    fake_server.set_result("listCommands", big_commands)

    commands = avo.list_commands()

    assert len(commands) == len(big_commands)
    assert commands[0]["name"] == "command00000"
    assert commands[-1]["name"] == "command19999"
