"""
Tests for connect.render_image(), which has two reply shapes: inline
base64-encoded PNG bytes when no filename is given, and a small dict
reporting where the file was written when one is.
"""

import base64

from fake_rpc_server import TINY_PNG_BYTES


def test_render_image_inline_returns_real_png_bytes(avo, fake_server):
    data = avo.render_image()
    assert isinstance(data, bytes)
    # The fake server's canned reply is a real (if trivial) PNG; check the
    # base64 round-trip landed on the exact same bytes, and that it is a
    # real PNG (starts with the PNG signature), not just opaque data.
    assert data == TINY_PNG_BYTES
    assert data[:8] == b"\x89PNG\r\n\x1a\n"


def test_render_image_inline_request_shape(avo, fake_server):
    avo.render_image(width=800, height=600, transparent=True)
    request = fake_server.requests[-1]
    assert request["method"] == "renderImage"
    assert request["params"] == {
        "width": 800,
        "height": 600,
        "transparentBackground": True,
    }


def test_render_image_omits_unset_params(avo, fake_server):
    avo.render_image()
    request = fake_server.requests[-1]
    assert request["params"] == {}


def test_render_image_with_filename_returns_true(avo, fake_server):
    result = avo.render_image(filename="/tmp/homo.png")
    assert result is True
    request = fake_server.requests[-1]
    assert request["params"]["fileName"] == "/tmp/homo.png"


def test_render_image_base64_matches_server_encoding(avo):
    # Belt and braces: re-derive what the server sent and compare, rather
    # than only trusting the shared TINY_PNG_BYTES constant.
    expected = base64.b64encode(TINY_PNG_BYTES)
    data = avo.render_image()
    assert base64.b64encode(data) == expected
