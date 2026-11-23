"""
Tests for the READY frame that EnergyServer sends once its model is loaded.

energy.py only needs numpy and the standard library, so it is loaded straight
from the source tree rather than through the (compiled) avogadro package.
"""

import importlib.util
import io
import struct
import sys
from pathlib import Path

import pytest

_ENERGY_PY = Path(__file__).resolve().parent.parent / "avogadro" / "energy.py"
_spec = importlib.util.spec_from_file_location("avogadro_energy_under_test", _ENERGY_PY)
energy = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = energy  # dataclasses looks the module up
_spec.loader.exec_module(energy)


def _server(atom_count=3, stdin=b""):
    out = io.BytesIO()
    return energy.EnergyServer(io.BytesIO(stdin), out, atom_count), out


def test_ready_flag_value_is_distinct():
    flags = [
        energy.FLAG_REQUEST_GRADIENT,
        energy.FLAG_BATCH_MODE,
        energy.FLAG_REQUEST_ENERGY_AND_GRADIENT,
        energy.FLAG_REQUEST_HESSIAN,
        energy.FLAG_RESPONSE_ERROR,
    ]
    assert energy.FLAG_READY == 0x0010
    assert all(energy.FLAG_READY & f == 0 for f in flags)
    # A request must never be allowed to carry it.
    assert energy.FLAG_READY & energy.VALID_REQUEST_FLAGS == 0


def test_ready_sent_on_enter_when_requested(monkeypatch):
    monkeypatch.setenv("AVOGADRO_ENERGY_READY", "1")
    server, out = _server(atom_count=7)
    with server:
        pass
    # magic, version 1, flags 0x0010, atom_count 7, payload 0 -- byte exact.
    assert out.getvalue() == (
        b"AVB1" + b"\x01\x00" + b"\x10\x00" + b"\x07\x00\x00\x00" + b"\x00\x00\x00\x00"
    )


def test_ready_not_sent_without_variable(monkeypatch):
    monkeypatch.delenv("AVOGADRO_ENERGY_READY", raising=False)
    server, out = _server()
    with server:
        assert list(server.requests()) == []
    assert out.getvalue() == b""


@pytest.mark.parametrize("value", ["0", "", "true", "yes"])
def test_ready_only_for_exactly_one(monkeypatch, value):
    monkeypatch.setenv("AVOGADRO_ENERGY_READY", value)
    server, out = _server()
    with server:
        pass
    assert out.getvalue() == b""


def test_ready_sent_exactly_once(monkeypatch):
    monkeypatch.setenv("AVOGADRO_ENERGY_READY", "1")
    server, out = _server()
    with server:
        list(server.requests())
        server.send_ready()
    assert len(out.getvalue()) == energy.HEADER.size


def test_ready_sent_by_requests_without_context_manager(monkeypatch):
    monkeypatch.setenv("AVOGADRO_ENERGY_READY", "1")
    server, out = _server(atom_count=2)
    assert list(server.requests()) == []
    assert out.getvalue() == struct.pack("<4sHHII", b"AVB1", 1, 0x0010, 2, 0)


def test_ready_precedes_a_response(monkeypatch):
    monkeypatch.setenv("AVOGADRO_ENERGY_READY", "1")
    coords = struct.pack("<3d", 0.0, 0.0, 0.0)
    request = struct.pack("<4sHHII", b"AVB1", 1, 0, 1, len(coords)) + coords
    server, out = _server(atom_count=1, stdin=request)
    with server:
        for req in server.requests():
            req.send_energy(-1.5)
    data = out.getvalue()
    ready, rest = data[:16], data[16:]
    assert struct.unpack("<4sHHII", ready) == (b"AVB1", 1, 0x0010, 1, 0)
    assert struct.unpack("<4sHHII", rest[:16]) == (b"AVB1", 1, 0, 1, 8)
    assert struct.unpack("<d", rest[16:]) == (-1.5,)
