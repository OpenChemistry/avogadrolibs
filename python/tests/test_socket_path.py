"""Tests for avogadro.connect.socket_path, the client-side twin of the
server's private per-user socket directory.

The Linux/BSD rules are exercised on macOS too by patching sys.platform; the
tests need POSIX file ownership and are skipped on Windows.
"""

import os
import socket
import sys

import pytest

from _load_avogadro import load_connect_module

connect_module = load_connect_module()
socket_path = connect_module.socket_path

pytestmark = pytest.mark.skipif(os.name == "nt", reason="needs POSIX ownership")


@pytest.fixture
def linux(tmp_path, monkeypatch):
    """Pretend to be Linux with a private temp dir and no XDG_RUNTIME_DIR."""
    tmp = tmp_path / "tmp"
    tmp.mkdir()
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(connect_module.tempfile, "gettempdir", lambda: str(tmp))
    monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
    return tmp


def _private_dir(path):
    path.mkdir()
    path.chmod(0o700)
    return path


def test_absolute_name_is_unchanged(linux):
    assert socket_path("/some/where/sock") == "/some/where/sock"


def test_macos_uses_temp_dir(linux, monkeypatch):
    monkeypatch.setattr(sys, "platform", "darwin")
    assert socket_path("avogadro") == os.path.join(str(linux), "avogadro")


def test_xdg_runtime_dir_preferred(linux, tmp_path, monkeypatch):
    xdg = _private_dir(tmp_path / "xdg")
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(xdg))
    assert socket_path("avogadro") == str(xdg / "avogadro")


def test_xdg_with_group_access_falls_back(linux, tmp_path, monkeypatch):
    xdg = tmp_path / "xdg"
    xdg.mkdir()
    xdg.chmod(0o755)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(xdg))
    expected = os.path.join(str(linux), "avogadro-%d" % os.getuid(), "avogadro")
    assert socket_path("avogadro") == expected


def test_xdg_symlink_falls_back(linux, tmp_path, monkeypatch):
    real = _private_dir(tmp_path / "real")
    link = tmp_path / "link"
    link.symlink_to(real)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(link))
    assert str(real) not in socket_path("avogadro")
    assert "avogadro-%d" % os.getuid() in socket_path("avogadro")


def test_fallback_directory_not_created(linux):
    path = socket_path("avogadro")
    assert path == os.path.join(str(linux), "avogadro-%d" % os.getuid(), "avogadro")
    assert not os.path.exists(os.path.dirname(path))


def test_fallback_directory_with_bad_permissions_is_refused(linux):
    bad = linux / ("avogadro-%d" % os.getuid())
    bad.mkdir()
    bad.chmod(0o755)
    with pytest.raises(ConnectionError, match="Refusing"):
        socket_path("avogadro")


def test_fallback_directory_symlink_is_refused(linux, tmp_path):
    real = _private_dir(tmp_path / "real")
    (linux / ("avogadro-%d" % os.getuid())).symlink_to(real)
    with pytest.raises(ConnectionError, match="Refusing"):
        socket_path("avogadro")


def _make_socket(path):
    # AF_UNIX paths are short; tmp_path can exceed the limit, so chdir.
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    cwd = os.getcwd()
    try:
        os.chdir(os.path.dirname(path))
        sock.bind(os.path.basename(path))
    finally:
        os.chdir(cwd)
    return sock


def test_legacy_socket_owned_by_us_is_accepted(linux):
    legacy = os.path.join(str(linux), "avogadro")
    sock = _make_socket(legacy)
    try:
        assert socket_path("avogadro") == legacy
    finally:
        sock.close()


def test_new_location_wins_over_legacy(linux):
    legacy_sock = _make_socket(os.path.join(str(linux), "avogadro"))
    directory = _private_dir(linux / ("avogadro-%d" % os.getuid()))
    new_sock = _make_socket(str(directory / "avogadro"))
    try:
        assert socket_path("avogadro") == str(directory / "avogadro")
    finally:
        legacy_sock.close()
        new_sock.close()


def test_legacy_regular_file_is_not_used(linux):
    (linux / "avogadro").write_text("not a socket")
    expected = os.path.join(str(linux), "avogadro-%d" % os.getuid(), "avogadro")
    assert socket_path("avogadro") == expected


def test_legacy_socket_owned_by_someone_else_is_refused(linux, monkeypatch):
    legacy = os.path.join(str(linux), "avogadro")
    sock = _make_socket(legacy)
    # Pretend to be a different user rather than needing root to chown.
    monkeypatch.setattr(os, "getuid", lambda: os.stat(legacy).st_uid + 1)
    try:
        with pytest.raises(ConnectionError, match="owned by another user"):
            socket_path("avogadro")
    finally:
        sock.close()


def test_connect_refuses_unsafe_directory(linux):
    bad = linux / ("avogadro-%d" % os.getuid())
    bad.mkdir()
    bad.chmod(0o777)
    with pytest.raises(ConnectionError, match="Refusing"):
        connect_module.connect()
