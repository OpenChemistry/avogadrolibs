"""
/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-clause BSD License, (the "License").
******************************************************************************/
"""

from __future__ import annotations
from dataclasses import dataclass
import struct
from typing import TYPE_CHECKING

import numpy as np

if TYPE_CHECKING:
    from typing import BinaryIO, Optional, Tuple
    import numpy.typing as npt

MAGIC = b"AVB1"
VERSION = 1
HEADER = struct.Struct("<4sHHII")

FLAG_REQUEST_GRADIENT = 0x0001
FLAG_BATCH_MODE = 0x0002
FLAG_RESPONSE_ERROR = 0x8000
VALID_REQUEST_FLAGS = FLAG_REQUEST_GRADIENT | FLAG_BATCH_MODE


class BinaryProtocolError(RuntimeError):
    pass


@dataclass(slots=True, frozen=True)
class Frame:
    """One binary-v1 frame."""

    flags: int
    atom_count: int
    payload: bytes


@dataclass(slots=True, frozen=True)
class CoordinateFrame:
    """Decoded coordinate request payload."""

    flags: int
    atom_count: int
    coords: "npt.NDArray"

    @property
    def wants_gradient(self) -> bool:
        return wants_gradient(self.flags)

    @property
    def is_batch(self) -> bool:
        return is_batch_mode(self.flags)

    @property
    def batch_size(self) -> int:
        if self.coords.ndim == 2:
            return 1
        return self.coords.shape[0]


def read_exact(stream: "BinaryIO", nbytes: int) -> "Optional[bytes]":
    """
    Read exactly nbytes from stream.

    Returns None only for clean EOF before any bytes are read.
    Raises BinaryProtocolError on truncated reads.
    """
    data = bytearray()
    while len(data) < nbytes:
        chunk = stream.read(nbytes - len(data))
        if not chunk:
            if not data:
                return None
            raise BinaryProtocolError(
                f"Unexpected EOF while reading {nbytes} bytes "
                f"(got {len(data)} bytes)."
            )
        data.extend(chunk)
    return bytes(data)


def _parse_header(raw_header: bytes) -> "Tuple[int, int, int]":
    if len(raw_header) != HEADER.size:
        raise BinaryProtocolError("Invalid header size.")

    magic, version, flags, atom_count, payload_bytes = HEADER.unpack(raw_header)
    if magic != MAGIC:
        raise BinaryProtocolError("Invalid binary-v1 magic.")
    if version != VERSION:
        raise BinaryProtocolError("Unsupported binary-v1 version.")

    return flags, atom_count, payload_bytes


def _pack_header(flags: int, atom_count: int, payload_bytes: int) -> bytes:
    return HEADER.pack(MAGIC, VERSION, flags, atom_count, payload_bytes)


def _parse_single_coords(payload: bytes, atom_count: int) -> "npt.NDArray":
    """Parse a single-frame coordinate payload into a numpy array of shape (N, 3)."""
    expected_size = atom_count * 3 * 8
    if len(payload) != expected_size:
        raise BinaryProtocolError(
            f"Single-frame payload size mismatch: "
            f"expected {expected_size} bytes, got {len(payload)}"
        )
    return np.frombuffer(payload, dtype="<f8").reshape(atom_count, 3)


def _parse_batch_coords(payload: bytes, atom_count: int) -> "Tuple[int, npt.NDArray]":
    """
    Parse a batch coordinate payload into (batch_size, coords).

    Returns:
      (batch_size, coords) where coords has shape (batch_size, atom_count, 3)
    """
    if len(payload) < 4:
        raise BinaryProtocolError("Batch payload too short for batch_size field")

    batch_size = struct.unpack("<I", payload[:4])[0]
    coords_data = payload[4:]

    expected_size = batch_size * atom_count * 3 * 8
    if len(coords_data) != expected_size:
        raise BinaryProtocolError(
            f"Batch coordinate payload size mismatch: "
            f"expected {expected_size} bytes, got {len(coords_data)}"
        )

    coords = np.frombuffer(coords_data, dtype="<f8").reshape(batch_size, atom_count, 3)
    return batch_size, coords


def _validate_request_flags(flags: int) -> None:
    unknown = flags & ~VALID_REQUEST_FLAGS
    if unknown:
        raise BinaryProtocolError(f"Unsupported request flag bits: 0x{unknown:04x}")


def read_frame(
    stream: "BinaryIO", expected_atom_count: "Optional[int]" = None
) -> "Optional[Frame]":
    """
    Read one binary-v1 frame.

    Returns:
      Frame or None on clean EOF.
    """
    raw_header = read_exact(stream, HEADER.size)
    if raw_header is None:
        return None

    flags, atom_count, payload_bytes = _parse_header(raw_header)
    if expected_atom_count is not None and atom_count != expected_atom_count:
        raise BinaryProtocolError("Atom count mismatch.")

    payload = read_exact(stream, payload_bytes)
    if payload is None:
        raise BinaryProtocolError("Unexpected EOF while reading payload.")

    return Frame(flags=flags, atom_count=atom_count, payload=payload)


def write_frame(
    stream: "BinaryIO",
    flags: int,
    atom_count: int,
    payload: bytes = b"",
    flush: bool = True,
) -> None:
    """
    Write one binary-v1 frame.

    The payload can be bytes-like. This primitive is intentionally generic so
    future protocols can layer batched/typed messages above it.
    """
    data = memoryview(payload)
    header = _pack_header(flags, atom_count, data.nbytes)
    stream.write(header)
    stream.write(data)
    if flush:
        stream.flush()


def _write_frame_parts(
    stream: "BinaryIO",
    flags: int,
    atom_count: int,
    parts: "Tuple[object, ...]",
    flush: bool = True,
) -> None:
    """
    Write one frame from multiple payload parts to avoid temporary large copies.
    """
    views = [memoryview(part) for part in parts]
    payload_bytes = sum(view.nbytes for view in views)
    header = _pack_header(flags, atom_count, payload_bytes)
    stream.write(header)
    for view in views:
        stream.write(view)
    if flush:
        stream.flush()


def wants_gradient(flags: int) -> bool:
    return (flags & FLAG_REQUEST_GRADIENT) != 0


def is_batch_mode(flags: int) -> bool:
    """Check if FLAG_BATCH_MODE is set in the request flags."""
    return (flags & FLAG_BATCH_MODE) != 0


def _write_single_energy(
    stream: "BinaryIO", atom_count: int, energy: float, flush: bool = True
) -> None:
    payload = struct.pack("<d", float(energy))
    write_frame(stream, 0, atom_count, payload, flush=flush)


def _write_single_gradient(
    stream: "BinaryIO", atom_count: int, gradient: "npt.NDArray", flush: bool = True
) -> None:
    grad = np.asarray(gradient, dtype=np.float64)
    if grad.shape == (atom_count * 3,):
        grad = grad.reshape(atom_count, 3)
    if grad.shape != (atom_count, 3):
        raise BinaryProtocolError("Gradient shape must be (atom_count, 3).")

    grad = np.ascontiguousarray(grad, dtype="<f8")
    _write_frame_parts(stream, 0, atom_count, (grad,), flush=flush)


def _write_error(
    stream: "BinaryIO", atom_count: int, message: str, flush: bool = True
) -> None:
    payload = str(message).encode("utf-8")
    write_frame(stream, FLAG_RESPONSE_ERROR, atom_count, payload, flush=flush)


def _write_batch_energies(
    stream: "BinaryIO", atom_count: int, energies: "npt.NDArray", flush: bool = True
) -> None:
    """
    Write a batched energy response.

    The payload structure is:
      - batch_size: uint32 LE (4 bytes)
      - energies: batch_size doubles (LE)
    """
    energies_arr = np.asarray(energies, dtype="<f8")
    if energies_arr.ndim != 1:
        raise BinaryProtocolError(
            f"Energies must be 1D array, got shape {energies_arr.shape}"
        )
    energies_arr = np.ascontiguousarray(energies_arr)
    batch_size = struct.pack("<I", len(energies_arr))
    _write_frame_parts(
        stream, FLAG_BATCH_MODE, atom_count, (batch_size, energies_arr), flush=flush
    )


def _write_batch_gradients(
    stream: "BinaryIO", atom_count: int, gradients: "npt.NDArray", flush: bool = True
) -> None:
    """
    Write a batched gradient response.

    The payload structure is:
      - batch_size: uint32 LE (4 bytes)
      - gradients: batch_size x atom_count x 3 doubles (LE)
    """
    grad = np.asarray(gradients, dtype="<f8")
    if grad.ndim != 3:
        raise BinaryProtocolError(f"Gradients must be 3D array, got shape {grad.shape}")

    if grad.shape[1:] != (atom_count, 3):
        raise BinaryProtocolError(
            f"Gradient batch shape must be (batch_size, {atom_count}, 3), "
            f"got {grad.shape}"
        )

    grad = np.ascontiguousarray(grad)
    batch_size = struct.pack("<I", grad.shape[0])
    _write_frame_parts(
        stream,
        FLAG_BATCH_MODE | FLAG_REQUEST_GRADIENT,
        atom_count,
        (batch_size, grad),
        flush=flush,
    )


def read_coordinates(
    stream: "BinaryIO", expected_atom_count: "Optional[int]" = None
) -> "Optional[CoordinateFrame]":
    """
    Read coordinates from stream (single-frame or batched).

    Args:
      stream: binary input stream
      expected_atom_count: expected number of atoms (validates if provided)

    Returns:
      CoordinateFrame or None on EOF.
      CoordinateFrame.coords has shape:
        - (atom_count, 3) for single-frame
        - (batch_size, atom_count, 3) for batch mode

    Raises:
      BinaryProtocolError: on protocol violations or invalid data
    """
    frame = read_frame(stream, expected_atom_count)
    if frame is None:
        return None

    _validate_request_flags(frame.flags)

    if is_batch_mode(frame.flags):
        _, coords = _parse_batch_coords(frame.payload, frame.atom_count)
    else:
        coords = _parse_single_coords(frame.payload, frame.atom_count)

    return CoordinateFrame(
        flags=frame.flags, atom_count=frame.atom_count, coords=coords
    )


class EnergyServer:
    """
    Context manager for Avogadro "energy server" main loop using a binary protocol.

    Simplifies script implementation by handling the request/response protocol
    and providing convenient methods for sending results.

    Args:
      input_stream: binary input stream
      output_stream: binary output stream
      atom_count: number of atoms (to track size of requests/responses)
      auto_flush: automatically flush output stream (default: True)

    Example (basic usage):
        with EnergyServer(sys.stdin.buffer, sys.stdout.buffer, atom_count) as server:
            for request in server.requests():
                if request.wants_gradient:
                    gradient = compute_gradient(request.coords)
                    request.send_gradient(gradient)
                else:
                    energy = compute_energy(request.coords)
                    request.send_energy(energy)

    Example (with batching):
        with EnergyServer(sys.stdin.buffer, sys.stdout.buffer, atom_count) as server:
            for request in server.requests():
                # request.coords is (N, 3) or (batch, N, 3) automatically
                if request.is_batch:
                    energies = model.compute_batch(request.coords)
                    request.send_energies(energies)
                else:
                    energy = model.compute_single(request.coords)
                    request.send_energy(energy)
    """

    __slots__ = ("input", "output", "atom_count", "auto_flush")

    def __init__(
        self,
        input_stream: "BinaryIO",
        output_stream: "BinaryIO",
        atom_count: int,
        auto_flush: bool = True,
    ):
        self.input = input_stream
        self.output = output_stream
        self.atom_count = atom_count
        self.auto_flush = auto_flush

    def __enter__(self) -> "EnergyServer":
        return self

    def __exit__(self, *args) -> None:
        try:
            self.output.flush()
        except Exception:
            pass

    def requests(self):
        """
        Iterate over incoming coordinate requests.

        Yields Request objects with:
          - coords: numpy array (atom_count, 3) or (batch_size, atom_count, 3)
          - flags: request flags
          - wants_gradient: bool property
          - is_batch: bool property
          - send_energy / send_energies / send_gradient / send_gradients
          - send_error(message): send error response
        """
        while True:
            request_frame = read_coordinates(self.input, self.atom_count)
            if request_frame is None:
                break

            yield Request(self, request_frame)


class Request:
    """
    Represents a single energy/gradient request.

    This is a lightweight wrapper around the request data that provides
    convenient methods for sending responses.

    Args:
      server: EnergyServer instance
      frame: CoordinateFrame

    """

    __slots__ = ("_server", "flags", "coords", "_sent")

    def __init__(self, server: EnergyServer, frame: CoordinateFrame):
        self._server = server
        self.flags = frame.flags
        self.coords = frame.coords
        self._sent = False

        if frame.atom_count != server.atom_count:
            raise BinaryProtocolError(
                f"Request atom_count mismatch: expected {server.atom_count}, "
                f"got {frame.atom_count}"
            )
        if self.is_batch:
            if self.coords.ndim != 3:
                raise BinaryProtocolError(
                    "Batch request coords must have shape (batch, atom_count, 3)."
                )
            if self.coords.shape[1:] != (self._server.atom_count, 3):
                raise BinaryProtocolError(
                    f"Batch coords shape mismatch: expected (batch, "
                    f"{self._server.atom_count}, 3), got {self.coords.shape}"
                )
        else:
            if self.coords.shape != (self._server.atom_count, 3):
                raise BinaryProtocolError(
                    f"Single coords shape mismatch: expected "
                    f"({self._server.atom_count}, 3), got {self.coords.shape}"
                )

    @property
    def wants_gradient(self) -> bool:
        """True if gradient is requested (FLAG_REQUEST_GRADIENT set)."""
        return wants_gradient(self.flags)

    @property
    def is_batch(self) -> bool:
        """True if this is a batch request (FLAG_BATCH_MODE set)."""
        return is_batch_mode(self.flags)

    @property
    def batch_size(self) -> int:
        """
        Batch size (1 for single-frame, >1 for batch mode).

        Returns:
          1 if single-frame, or coords.shape[0] if batch
        """
        if self.coords.ndim == 2:
            return 1
        return self.coords.shape[0]

    def _check_unsent(self) -> None:
        if self._sent:
            raise BinaryProtocolError("A response was already sent for this request.")

    def _mark_sent(self) -> None:
        self._check_unsent()
        self._sent = True

    def send(self, result: "npt.NDArray") -> None:
        """
        Send response (automatically detects energy vs gradient, single vs batch).

        Args:
          result: energy/gradient data as numpy array
            - For single energy: scalar or shape (1,)
            - For batch energies: shape (batch_size,)
            - For single gradient: shape (atom_count, 3)
            - For batch gradients: shape (batch_size, atom_count, 3)
        """
        if self.is_batch:
            if self.wants_gradient:
                self.send_gradients(result)
            else:
                self.send_energies(result)
        elif self.wants_gradient:
            self.send_gradient(result)
        else:
            self.send_energy(result)

    def send_energy(self, energy: float) -> None:
        """Send single-geometry energy response."""
        if self.is_batch:
            raise BinaryProtocolError(
                "send_energy() is invalid for batch requests; use send_energies()."
            )
        if self.wants_gradient:
            raise BinaryProtocolError(
                "send_energy() is invalid when a gradient was requested."
            )
        self._mark_sent()
        _write_single_energy(
            self._server.output,
            self._server.atom_count,
            energy,
            flush=self._server.auto_flush,
        )

    def send_energies(self, energies: "npt.NDArray") -> None:
        """Send batched energy response."""
        if not self.is_batch:
            raise BinaryProtocolError(
                "send_energies() is invalid for single requests; use send_energy()."
            )
        if self.wants_gradient:
            raise BinaryProtocolError(
                "send_energies() is invalid when gradients were requested."
            )
        self._mark_sent()
        _write_batch_energies(
            self._server.output,
            self._server.atom_count,
            energies,
            flush=self._server.auto_flush,
        )

    def send_gradient(self, gradient: "npt.NDArray") -> None:
        """Send single-geometry gradient response."""
        if self.is_batch:
            raise BinaryProtocolError(
                "send_gradient() is invalid for batch requests; use send_gradients()."
            )
        if not self.wants_gradient:
            raise BinaryProtocolError(
                "send_gradient() is invalid when only energy was requested."
            )
        self._mark_sent()
        _write_single_gradient(
            self._server.output,
            self._server.atom_count,
            gradient,
            flush=self._server.auto_flush,
        )

    def send_gradients(self, gradients: "npt.NDArray") -> None:
        """Send batched gradient response."""
        if not self.is_batch:
            raise BinaryProtocolError(
                "send_gradients() is invalid for single requests; use send_gradient()."
            )
        if not self.wants_gradient:
            raise BinaryProtocolError(
                "send_gradients() is invalid when only energies were requested."
            )
        self._mark_sent()
        _write_batch_gradients(
            self._server.output,
            self._server.atom_count,
            gradients,
            flush=self._server.auto_flush,
        )

    def send_error(self, message: str) -> None:
        """Send error response."""
        self._mark_sent()
        _write_error(
            self._server.output,
            self._server.atom_count,
            message,
            flush=self._server.auto_flush,
        )
