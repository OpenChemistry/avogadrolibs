"""
A fake Avogadro RPC server, for testing ``avogadro.connect`` (and anything
built on top of it) without a running Avogadro instance.

It speaks the real wire protocol described in
``two.avogadro.cc/source/develop/rpc.md``: a 4-byte big-endian length
prefix followed by that many bytes of UTF-8 JSON-RPC 2.0, on a Unix domain
socket named the way ``avogadro.connect.connect`` expects
(``$TMPDIR/<name>``).

Reuse from another package
---------------------------

This module has no dependency on ``avogadro`` itself -- only the standard
library -- so another project (``avogadro-mcp`` is the intended consumer,
per the MCP bridge plan) can use it as a test fixture by putting this
file's directory on ``sys.path`` (e.g. a checked-out ``avogadrolibs``
tree, ``.../avogadrolibs/python/tests``) and importing it directly::

    import sys
    sys.path.insert(0, "/path/to/avogadrolibs/python/tests")
    from fake_rpc_server import FakeRPCServer

    with FakeRPCServer() as server:
        # point a client at server.name / server.path

A pytest fixture wrapping it lives in ``conftest.py`` next to this file.

Platform limitation
--------------------

Only the Unix domain socket transport is implemented, matching Linux,
macOS and BSD. Windows Avogadro listens on a named pipe
(``\\\\.\\pipe\\<name>``) instead; a named-pipe variant of this server
would need the ``pywin32`` (or ``ctypes`` + the Win32 API) overlapped-IO
calls and is not attempted here. Tests that use this module do not run on
Windows as a result -- skip them there rather than trying to fake the
pipe transport.
"""

import json
import os
import socket
import struct
import sys
import tempfile
import threading
import uuid
import zlib


def _png_chunk(tag, data):
    """Build one PNG chunk: length + tag + data + CRC32."""
    return (
        struct.pack(">I", len(data))
        + tag
        + data
        + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
    )


def _make_tiny_png():
    """
    Build a minimal, valid 1x1 white PNG using only the standard library
    (struct + zlib), so render_image() tests have real image bytes to
    base64-decode and check, without shipping a binary fixture file.
    """
    signature = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)  # 1x1, 8-bit RGB
    raw = b"\x00" + b"\xff\xff\xff"  # filter-type byte + one white pixel
    idat = zlib.compress(raw)
    return (
        signature
        + _png_chunk(b"IHDR", ihdr)
        + _png_chunk(b"IDAT", idat)
        + _png_chunk(b"IEND", b"")
    )


#: A real (if trivial) PNG, used to answer renderImage.
TINY_PNG_BYTES = _make_tiny_png()


def _default_render_image(params):
    width = params.get("width", 1600)
    height = params.get("height", 1200)
    filename = params.get("fileName")
    if filename:
        if "." not in os.path.basename(filename):
            filename = filename + ".png"
        return {"width": width, "height": height, "fileName": filename}
    import base64

    return {
        "width": width,
        "height": height,
        "format": "png",
        "data": base64.b64encode(TINY_PNG_BYTES).decode("ascii"),
    }


def _default_get_molecule(params):
    fmt = params.get("format", "cjson")
    return {"format": fmt, "content": '{"chemical json": 1, "atoms": {}}'}


def _default_export_file(params):
    # Mirrors the real app: exportFile writes on a background thread, so
    # without wait it answers immediately with True, and with wait it
    # holds the reply for the "finished" shape carrying the results.
    if params.get("wait"):
        return {
            "status": "finished",
            "message": "Export finished",
            "data": {"fileName": params.get("fileName")},
        }
    return True


#: Canned results for every phase 1 method, per Appendix A of the MCP
#: bridge plan. Each entry is either a plain value or a callable taking
#: the request's params dict and returning the "result" payload.
DEFAULT_RESPONSES = {
    "internalPing": "pong",
    "version": {
        "avogadroApp": "1.103.0",
        "avogadroLibs": "2.0.0",
        "qt": "6.8.3",
        "platform": "macos",
        "rpcProtocol": 2,
    },
    "listCommands": [
        {
            "name": "openFile",
            "description": "Read a file from disk and make it the active molecule.",
            "kind": "builtin",
            "plugin": "",
            "async": False,
            "schema": {},
        },
        {
            "name": "renderMO",
            "description": "Render a molecular orbital.",
            "kind": "extension",
            "plugin": "Surfaces",
            "async": False,
            "schema": {},
        },
    ],
    "moleculeInfo": {
        "atomCount": 24,
        "bondCount": 25,
        "formula": "C8H10N4O2",
        "mass": 194.19,
        "totalCharge": 0,
        "spinMultiplicity": 1,
        "coordinateSetCount": 0,
        "selectedAtomCount": 0,
        "residueCount": 0,
        "hasResidues": False,
        "hasUnitCell": False,
        "hasCustomElements": False,
        "hasBasisSet": False,
        "orbitalCount": 0,
        "homoIndex": -1,
        "cubeCount": 0,
        "vibrationCount": 0,
        "fileName": "/path/to/caffeine.cml",
    },
    "getMolecule": _default_get_molecule,
    "renderImage": _default_render_image,
    "listDisplayTypes": [
        {
            "name": "BallStick",
            "displayName": "Ball and Stick",
            "enabled": True,
            "applicable": True,
            "hasSettings": True,
        },
        {
            "name": "Wireframe",
            "displayName": "Wireframe",
            "enabled": False,
            "applicable": True,
            "hasSettings": False,
        },
    ],
    "setRenderTypes": True,
    "setProjection": True,
    "openFile": True,
    "loadMolecule": True,
    "saveGraphic": True,
    "exportFile": _default_export_file,
    "kill": True,
}


class FakeRPCServer:
    """
    A background-thread Unix-socket server that answers JSON-RPC 2.0
    requests framed the way Avogadro frames them.

    Use it as a context manager, or call start()/stop() directly::

        with FakeRPCServer() as server:
            server.set_error("openFile", -1, "No such file.")
            ...

    Every request the server receives is recorded in ``self.requests``
    (the parsed JSON-RPC objects, in order) so a test can assert on what
    was sent, not just what came back.

    :param name: The socket name, i.e. the file is
        ``$TMPDIR/<name>``, matching what ``avogadro.connect.connect``
        expects for its ``name`` argument. Defaults to a random name so
        parallel test runs, and a real running Avogadro, never collide.
    :param responses: Extra or overriding canned responses, merged over
        DEFAULT_RESPONSES. Same shape: method name -> value or
        callable(params) -> value.
    """

    def __init__(self, name=None, responses=None):
        self.name = name or ("avogadro-test-%s" % uuid.uuid4().hex[:8])
        self.path = os.path.join(tempfile.gettempdir(), self.name)
        self._responses = dict(DEFAULT_RESPONSES)
        if responses:
            self._responses.update(responses)
        self._overrides = {}
        self.requests = []
        self._socket = None
        self._thread = None
        self._stop = threading.Event()

    def set_result(self, method, result):
        """Answer the next (and all subsequent) calls to method with result."""
        self._overrides[method] = ("result", result)

    def set_error(self, method, code, message, data=None):
        """
        Answer calls to method with a JSON-RPC error instead of a result.

        :param code: One of the RPCError codes, e.g. -1, -2, -3, -32601.
        :param message: The error message text.
        :param data: Optional extra error data.
        """
        self._overrides[method] = ("error", (code, message, data))

    def clear_override(self, method):
        """Go back to the default canned response for method."""
        self._overrides.pop(method, None)

    def start(self):
        """Bind the socket and start answering requests in a background thread."""
        if sys.platform.startswith("win"):
            raise NotImplementedError(
                "FakeRPCServer only implements the Unix domain socket "
                "transport; there is no named-pipe variant yet."
            )
        if os.path.exists(self.path):
            os.unlink(self.path)
        self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._socket.bind(self.path)
        self._socket.listen(1)
        self._socket.settimeout(0.5)
        self._stop.clear()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        return self

    def stop(self):
        """Stop answering requests and remove the socket file."""
        self._stop.set()
        if self._socket is not None:
            try:
                self._socket.close()
            except OSError:
                pass
            self._socket = None
        if self._thread is not None:
            self._thread.join(timeout=2)
            self._thread = None
        if os.path.exists(self.path):
            os.unlink(self.path)

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.stop()
        return False

    # -- internals ---------------------------------------------------

    def _serve(self):
        # Bind the listening socket to a local first: stop() runs on another
        # thread and clears self._socket right after setting the stop flag,
        # so reading the attribute inside the loop can come back None between
        # the flag check and the accept() call. Once stop() closes it, the
        # accept below raises OSError and the thread returns as before.
        server = self._socket
        if server is None:
            return
        while not self._stop.is_set():
            try:
                conn, _ = server.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                self._handle_connection(conn)
            finally:
                conn.close()

    def _handle_connection(self, conn):
        conn.settimeout(5.0)
        while not self._stop.is_set():
            header = self._recv_exactly(conn, 4)
            if header is None:
                return
            (size,) = struct.unpack(">I", header)
            body = self._recv_exactly(conn, size)
            if body is None:
                return
            request = json.loads(body.decode("utf-8"))
            self.requests.append(request)
            reply = self._build_reply(request)
            payload = json.dumps(reply).encode("utf-8")
            conn.sendall(struct.pack(">I", len(payload)) + payload)

    @staticmethod
    def _recv_exactly(conn, size):
        """Read exactly size bytes, or None if the peer closes early."""
        if size == 0:
            return b""
        chunks = []
        remaining = size
        while remaining > 0:
            try:
                chunk = conn.recv(remaining)
            except (socket.timeout, OSError):
                return None
            if not chunk:
                return None
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def _build_reply(self, request):
        method = request.get("method")
        params = request.get("params") or {}
        reply = {"jsonrpc": "2.0", "id": request.get("id")}

        if method in self._overrides:
            kind, payload = self._overrides[method]
            if kind == "error":
                code, message, data = payload
                error = {"code": code, "message": message}
                if data is not None:
                    error["data"] = data
                reply["error"] = error
            else:
                reply["result"] = payload
            return reply

        if method not in self._responses:
            reply["error"] = {
                "code": -32601,
                "message": "Method not found",
                "data": {"request": {"method": method, "params": params}},
            }
            return reply

        responder = self._responses[method]
        reply["result"] = responder(params) if callable(responder) else responder
        return reply
