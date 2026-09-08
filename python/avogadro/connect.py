"""
/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-clause BSD License, (the "License").
******************************************************************************/
"""

import base64
import json
import os
import socket
import struct
import tempfile

DEFAULT_SERVER = "avogadro"

#: Seconds Avogadro waits for a command before giving up on it.
DEFAULT_COMMAND_TIMEOUT = 60


class RPCError(RuntimeError):
    """Raised when Avogadro returns a JSON-RPC error response."""

    #: A command that was started failed, or timed out.
    COMMAND_FAILED = -2
    #: The plugin is already running a command.
    PLUGIN_BUSY = -3
    #: No tool or extension claims this method.
    METHOD_NOT_FOUND = -32601

    def __init__(self, code, message, data=None):
        super().__init__("Avogadro RPC error %s: %s" % (code, message))
        self.code = code
        self.message = message
        self.data = data


def result_data(response):
    """
    Return the data a waited command handed back, or an empty dict.

    Only commands sent with wait=True return data, and only some of them
    have anything to say.

    :param response: A response from send() or command().
    """
    if not isinstance(response, dict):
        return {}
    result = response.get("result")
    if not isinstance(result, dict):
        return {}
    data = result.get("data", {})
    return data if isinstance(data, dict) else {}


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
        :param timeout: Seconds to wait for a reply before giving up. This is
            enforced on Linux, macOS and BSD only. On Windows the named pipe
            is read as an ordinary file, which has no read timeout, so a
            server that stops answering blocks the caller indefinitely; the
            backstop there is Avogadro's own command timeout, which makes it
            answer with an error rather than go quiet.
        :raises ConnectionError: if Avogadro is not listening.
        """
        self._windows = os.name == "nt"
        self._id = 0
        self._timeout = timeout
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
            # The pipe is opened unbuffered (buffering=0), so write() is raw
            # file I/O and may write fewer bytes than asked, unlike a
            # socket's sendall(). Retry with the unsent suffix until the
            # whole packet is out.
            sent = 0
            while sent < len(packet):
                written = self.sock.write(packet[sent:])
                if not written:
                    raise ConnectionError("Connection closed by Avogadro.")
                sent += written
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

    def send(self, method, params=None, wait=False, timeout=None):
        """
        Send a JSON-RPC request and return the response.

        This is the general entry point - every method understood by
        Avogadro can be reached through it, including the commands
        registered by tool and extension plugins.

        Most commands finish before they reply. Some, such as rendering a
        surface or an orbital, hand the work to a background thread and
        would otherwise reply while the work is still running. Pass
        wait=True for those: Avogadro then holds the reply until the
        command has actually finished, and the response can carry results.

        :param method: The JSON-RPC method name, e.g. "openFile".
        :param params: Dict of parameters for the method.
        :param wait: If True, do not reply until the command has finished.
        :param timeout: Seconds Avogadro should wait for the command before
            giving up, when wait is True. Defaults to a minute.
        :returns: The decoded response object.
        :raises RPCError: if Avogadro reports an error for the request.
        """
        options = dict(params) if params else {}
        if wait:
            options["wait"] = True
            if timeout is not None:
                options["timeout"] = timeout

        self._id += 1
        message = {
            "jsonrpc": "2.0",
            "id": self._id,
            "method": method,
            "params": options,
        }
        self._write(json.dumps(message).encode("utf-8"))

        # Do not give up on the socket before Avogadro gives up on the plugin.
        if wait:
            command_timeout = (
                DEFAULT_COMMAND_TIMEOUT if timeout is None else timeout
            )
            self._set_socket_timeout(command_timeout + 5)
        try:
            response = self._read()
        finally:
            if wait:
                self._set_socket_timeout(self._timeout)

        if "error" in response:
            error = response["error"]
            raise RPCError(
                error.get("code"), error.get("message"), error.get("data")
            )
        return response

    def command(self, name, /, wait=False, timeout=None, **params):
        """
        Run a command registered by a tool or extension plugin.

        Keyword arguments are passed through as the command options, e.g.
        ``avo.command("renderMO", orbital="homo", isovalue=0.02)``.

        The command name is positional-only, so a command may have an
        option of its own called ``name`` without colliding with it --
        ``avo.command("fetchByName", name="caffeine")`` passes "caffeine"
        through as the option. Only ``wait`` and ``timeout`` are reserved.

        :param name: The registered command name.
        :param wait: If True, do not return until the command has finished.
        :param timeout: Seconds to allow the command, when wait is True.
        :returns: The decoded response object. Use result_data() to pull out
            anything the command handed back.
        """
        return self.send(name, params, wait=wait, timeout=timeout)

    def _set_socket_timeout(self, seconds):
        """
        Adjust the read timeout, where the platform has one.

        Windows has none: the pipe is opened as a file object, and bounding
        its reads needs the overlapped-IO win32 calls rather than anything
        the socket module offers. Reads there are unbounded -- see __init__.
        """
        if self._windows:
            return
        if self.sock is not None:
            self.sock.settimeout(seconds)

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

    def fetch_by_name(self, name, wait=True, timeout=None):
        """
        Download a structure by name and load it, replacing the active
        molecule.

        The lookup queries the NIH Cactus resolver first, then retries
        against PubChem's 3D endpoint if Cactus errors or returns 2D-only
        coordinates. Like export_file(), this hands the work to the network
        and would otherwise reply before it finishes, so ``wait`` defaults
        to True here, unlike send() and command().

        :param name: A common or IUPAC chemical name, e.g. "caffeine".
        :param wait: If True (the default), do not return until the
            structure has been downloaded and loaded.
        :param timeout: Seconds to allow the command, when wait is True.
        :returns: With wait=True, the dict of data the command reported --
            ``name`` and ``source`` ("cactus" or "pubchem") always,
            ``atomCount`` and ``formula`` when available; with wait=False,
            the raw response.
        :raises RPCError: with code -2 if name is empty, or if no match was
            found in either database.
        """
        response = self.send(
            "fetchByName", {"name": name}, wait=wait, timeout=timeout
        )
        if wait:
            return result_data(response)
        return response

    def version(self):
        """
        Report the versions Avogadro is running, for compatibility checks.

        This is answered before the "no active window" check that every
        other method requires, so it can be used to probe a starting
        instance. A build old enough to have no ``version`` method raises
        RPCError with code ``RPCError.METHOD_NOT_FOUND``; treat that as
        ``rpcProtocol`` 1, the immediate-reply era before ``wait`` existed.

        :returns: A dict with keys ``avogadroApp``, ``avogadroLibs``,
            ``qt``, ``platform`` (one of "macos", "windows", "linux",
            "bsd", "unknown"), and ``rpcProtocol`` (an int, 2 once a build
            honours ``wait``).
        """
        response = self.send("version")
        return response["result"]

    def list_commands(self):
        """
        List every command Avogadro will answer, built-in and plugin alike.

        :returns: A list of dicts, sorted by name, each with keys ``name``,
            ``description``, ``kind`` ("builtin", "tool" or "extension"),
            ``plugin`` (the owning plugin's name, empty for builtins),
            ``async`` (currently always False), and ``schema`` (currently
            always ``{}``).
        """
        response = self.send("listCommands")
        return response["result"]

    def molecule_info(self):
        """
        Summarize the active molecule: counts, formula, and what it has.

        Every key is always present, even with no molecule open, in which
        case the counts are 0 and the strings are empty.

        :returns: A dict with keys ``atomCount``, ``bondCount``,
            ``formula``, ``mass``, ``totalCharge``, ``spinMultiplicity``,
            ``coordinateSetCount``, ``selectedAtomCount``, ``residueCount``,
            ``hasResidues``, ``hasUnitCell``, ``hasCustomElements``,
            ``hasBasisSet``, ``orbitalCount``, ``homoIndex`` (zero-based,
            -1 with no basis set), ``cubeCount``, ``vibrationCount``, and
            ``fileName`` (empty for a molecule loaded with load_molecule()).
        """
        response = self.send("moleculeInfo")
        return response["result"]

    def get_molecule(self, format="cjson"):
        """
        Read the active molecule back as text, without writing a file.

        :param format: Any file format Avogadro can write, e.g. "xyz".
            Defaults to "cjson".
        :returns: The molecule's content as a string.
        :raises RPCError: with code -1 for an unknown format, a write
            failure, or no molecule open.
        """
        response = self.send("getMolecule", {"format": format})
        return response["result"]["content"]

    def export_file(self, filename, wait=True):
        """
        Write the active molecule to a file. The format is inferred from
        the file extension.

        The write happens on a background thread, so without waiting this
        call can return before the file exists on disk -- the bug the
        completion protocol exists to fix. ``wait`` therefore defaults to
        True here, unlike send() and command(), whose wait defaults stay
        False.

        :param filename: Path to write.
        :param wait: If True (the default), do not return until the write
            has finished.
        :returns: With wait=True, the dict of data the command reported
            (currently just ``{"fileName": ...}``); with wait=False, the
            raw response, as before.
        """
        response = self.send("exportFile", {"fileName": str(filename)}, wait=wait)
        if wait:
            return result_data(response)
        return response

    def save_graphic(self, filename):
        """
        Save a bitmap image of the current view. PNG is used if the
        filename has no extension.

        :param filename: Path to write.
        """
        return self.send("saveGraphic", {"fileName": str(filename)})

    def render_image(self, width=None, height=None, transparent=False, filename=None):
        """
        Render the current view, at any size, in or out of process memory.

        Unlike save_graphic(), this can render larger or smaller than the
        on-screen view, and can hand back the image bytes directly instead
        of only writing a file.

        :param width: Image width in pixels. Defaults to the current view
            size. Clamped to the range [1, 8192].
        :param height: Image height in pixels. Same default and clamping
            as width.
        :param transparent: If True, render with a transparent background.
        :param filename: Path to write the PNG to. ".png" is appended if
            the name has no extension, matching save_graphic(). If left
            out, the image is returned inline instead of written to disk.
        :returns: bytes of a PNG image when filename is not given;
            True when it is (the file was written). No PIL dependency --
            decode the bytes yourself if you want an image object, e.g.
            with ``PIL.Image.open(io.BytesIO(data))``.
        :raises RPCError: with code -1 for an unwritable path.
        """
        params = {}
        if width is not None:
            params["width"] = width
        if height is not None:
            params["height"] = height
        if transparent:
            params["transparentBackground"] = True
        if filename is not None:
            params["fileName"] = str(filename)

        response = self.send("renderImage", params)
        if filename is not None:
            return True
        return base64.b64decode(response["result"]["data"])

    def list_display_types(self):
        """
        List the scene display types (ball-and-stick, wireframe, etc.)
        and whether each is on, applicable, and configurable.

        :returns: A list of dicts, each with keys ``name`` (the stable
            identifier, e.g. "BallStick" -- pass this to
            set_display_types(), not ``displayName``), ``displayName``
            (translated for the interface language), ``enabled``,
            ``applicable`` (false for e.g. a crystal-only type on a
            molecule with no unit cell), and ``hasSettings``.
        """
        response = self.send("listDisplayTypes")
        return response["result"]

    def set_display_types(self, types):
        """
        Choose which scene display types are active.

        :param types: Either a list of type names to turn on (e.g.
            ``["BallStick", "VanDerWaals"]``), or a dict mapping names to
            booleans, which can also turn types off (e.g.
            ``{"BallStick": True, "Wireframe": False}``). A name matches
            either a type's identifier or its translated display name;
            prefer the identifier, since it does not change with the
            interface language.
        """
        if isinstance(types, dict):
            params = dict(types)
        else:
            params = {"types": list(types)}
        return self.send("setRenderTypes", params)

    def set_projection(self, kind):
        """
        Switch the camera projection.

        :param kind: "perspective" or "orthographic".
        """
        return self.send("setProjection", {"type": kind})

    def get_camera(self):
        """
        Report the active view's camera.

        :returns: A dict with keys ``distance`` (to the camera's own focus
            point -- the number that matters for framing a molecule),
            ``focus`` (a 3-element list), ``projection`` ("perspective" or
            "orthographic"), ``orthographicScale``, and ``modelView`` (the
            4x4 model view matrix as 16 floats in row-major order: element
            ``[row * 4 + col]`` is ``modelView[row][col]``). Save this and
            pass it to set_camera() to restore this exact view later.
        :raises RPCError: with code -1 if there is no active view.
        """
        response = self.send("getCamera")
        return response["result"]

    def set_camera(self, model_view=None, projection=None, orthographic_scale=None):
        """
        Apply a saved camera view.

        Give any combination of the three; anything left out is unchanged.

        :param model_view: The 16-float row-major model view matrix from a
            previous get_camera() call. Must be exactly 16 numbers.
        :param projection: "perspective" or "orthographic".
        :param orthographic_scale: The orthographic zoom factor.
        :returns: The resulting camera state, the same shape get_camera()
            returns.
        :raises RPCError: with code -1 for a model_view that is not exactly
            16 numbers, or if there is no active view.
        """
        params = {}
        if model_view is not None:
            params["modelView"] = list(model_view)
        if projection is not None:
            params["projection"] = projection
        if orthographic_scale is not None:
            params["orthographicScale"] = orthographic_scale

        response = self.send("setCamera", params)
        return response["result"]

    def ping(self):
        """
        Check that the server is alive.

        :returns: True if Avogadro answered.
        """
        try:
            return self.send("internalPing").get("result") == "pong"
        except (RPCError, ConnectionError, socket.timeout):
            # socket.timeout is not a ConnectionError, so a server that has
            # stopped answering would otherwise raise out of a check whose
            # whole purpose is to report that as False.
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
