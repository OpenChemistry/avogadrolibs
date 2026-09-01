"""
/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-clause BSD License, (the "License").
******************************************************************************/
"""

import json
import os
import socket
import struct
import tempfile

DEFAULT_SERVER = "avogadro"


class RPCError(RuntimeError):
    """Raised when Avogadro returns a JSON-RPC error response."""

    def __init__(self, code, message, data=None):
        super().__init__("Avogadro RPC error %s: %s" % (code, message))
        self.code = code
        self.message = message
        self.data = data


class connect:
    """
    Send JSON-RPC requests to Avogadro through a named pipe.

    This class is intended to be used by external scripts that are
    run on the same machine as Avogadro.

    The named pipe is created by Avogadro and is named "avogadro".
    If it does not exist, Avogadro is not running.

    Example::

        from avogadro.connect import connect

        with connect() as avo:
            avo.open_file("caffeine.cml")
            # generate and render the vdW surface
            avo.command("renderVanDerWaals", isovalue=0.001)
            avo.save_graphic("caffeine.png")
    """

    def __init__(self, name=DEFAULT_SERVER, timeout=10.0):
        """
        Connect to the local named pipe.

        :param name: The name of the named pipe (server) to connect to.
        :param timeout: Seconds to wait for a reply before giving up.
        :raises ConnectionError: if Avogadro is not listening.
        """
        self._windows = os.name == "nt"
        self._id = 0
        self.sock = None

        try:
            if self._windows:
                self.sock = open("//./pipe/" + name, "w+b", 0)
            else:
                self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                self.sock.settimeout(timeout)
                self.sock.connect(os.path.join(tempfile.gettempdir(), name))
        except Exception as exception:
            self.sock = None
            raise ConnectionError(
                "Could not connect to the '%s' server: %s. Is Avogadro running?"
                % (name, exception)
            ) from exception

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
        return False

    def _write(self, data):
        """Write a length-prefixed packet to the pipe."""
        if self.sock is None:
            raise ConnectionError("Not connected to Avogadro.")

        packet = struct.pack(">I", len(data)) + data
        if self._windows:
            self.sock.write(packet)
        else:
            self.sock.sendall(packet)

    def _read_exactly(self, size):
        """Read exactly size bytes, or raise if the connection closes."""
        chunks = []
        remaining = size
        while remaining > 0:
            if self._windows:
                chunk = self.sock.read(remaining)
            else:
                chunk = self.sock.recv(remaining)
            if not chunk:
                raise ConnectionError("Connection closed by Avogadro.")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def _read(self):
        """Read one length-prefixed JSON packet and decode it."""
        if self.sock is None:
            raise ConnectionError("Not connected to Avogadro.")

        (size,) = struct.unpack(">I", self._read_exactly(4))
        return json.loads(self._read_exactly(size).decode("utf-8"))

    def send(self, method, params=None, wait=True):
        """
        Send a JSON-RPC request and (optionally) return the response.

        This is the general entry point - every method understood by
        Avogadro can be reached through it, including the commands
        registered by tool and extension plugins.

        :param method: The JSON-RPC method name, e.g. "openFile".
        :param params: Dict of parameters for the method.
        :param wait: If True, block until the response arrives.
        :returns: The decoded response object, or None if wait is False.
        :raises RPCError: if Avogadro reports an error for the request.
        """
        self._id += 1
        message = {
            "jsonrpc": "2.0",
            "id": self._id,
            "method": method,
            "params": params if params is not None else {},
        }
        self._write(json.dumps(message).encode("utf-8"))

        if not wait:
            return None

        response = self._read()
        if "error" in response:
            error = response["error"]
            raise RPCError(
                error.get("code"), error.get("message"), error.get("data")
            )
        return response

    def command(self, name, **params):
        """
        Run a command registered by a tool or extension plugin.

        Keyword arguments are passed through as the command options, e.g.
        ``avo.command("renderMO", orbital="homo", isovalue=0.02)``.

        :param name: The registered command name.
        :returns: The decoded response object.
        """
        return self.send(name, params)

    def open_file(self, filename):
        """
        Open a file from a path on disk. The format is inferred from
        the file extension.

        :param filename: Path to the file to read.
        """
        return self.send("openFile", {"fileName": str(filename)})

    def load_molecule(self, content, format="cjson"):
        """
        Load molecular data directly, without writing a file to disk.

        :param content: The file contents as a string.
        :param format: Any file format Avogadro can read, e.g. "xyz".
        """
        return self.send("loadMolecule", {"content": content, "format": format})

    def export_file(self, filename):
        """
        Write the active molecule to a file. The format is inferred from
        the file extension.

        :param filename: Path to write.
        """
        return self.send("exportFile", {"fileName": str(filename)})

    def save_graphic(self, filename):
        """
        Save a bitmap image of the current view. PNG is used if the
        filename has no extension.

        :param filename: Path to write.
        """
        return self.send("saveGraphic", {"fileName": str(filename)})

    def ping(self):
        """
        Check that the server is alive.

        :returns: True if Avogadro answered.
        """
        try:
            return self.send("internalPing").get("result") == "pong"
        except (RPCError, ConnectionError):
            return False

    def kill(self):
        """
        Ask Avogadro to quit. This is only honored if Avogadro was
        started with the '--testing' flag.
        """
        return self.send("kill")

    def close(self):
        """Close the socket to the named pipe"""
        if self.sock is not None:
            self.sock.close()
            self.sock = None


# Older scripts referred to the class as Connection.
Connection = connect
