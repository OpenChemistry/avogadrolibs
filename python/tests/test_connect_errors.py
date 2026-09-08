"""
Tests that RPCError is raised with the right code/message/data for every
documented failure, across a representative set of the new helpers plus
the general send()/command() entry points.
"""

import pytest

from _load_avogadro import load_connect_module

_mod = load_connect_module()
RPCError = _mod.RPCError


def test_command_could_not_be_carried_out(avo, fake_server):
    # -1: "could not be carried out" -- no molecule open, bad path, etc.
    fake_server.set_error("getMolecule", -1, "No molecule is open.")
    with pytest.raises(RPCError) as excinfo:
        avo.get_molecule()
    assert excinfo.value.code == -1
    assert excinfo.value.message == "No molecule is open."


def test_command_failed_or_timed_out(avo, fake_server):
    fake_server.set_error(
        "renderImage", RPCError.COMMAND_FAILED, "The command timed out."
    )
    with pytest.raises(RPCError) as excinfo:
        avo.render_image()
    assert excinfo.value.code == -2
    assert excinfo.value.code == RPCError.COMMAND_FAILED


def test_plugin_busy(avo, fake_server):
    fake_server.set_error(
        "exportFile",
        RPCError.PLUGIN_BUSY,
        "That plugin is already running a command.",
    )
    with pytest.raises(RPCError) as excinfo:
        avo.export_file("/tmp/out.cml")
    assert excinfo.value.code == -3
    assert excinfo.value.code == RPCError.PLUGIN_BUSY


def test_method_not_found(avo, fake_server):
    # No override needed -- any method the fake server's table does not
    # know about behaves like an older Avogadro build that predates it.
    with pytest.raises(RPCError) as excinfo:
        avo.send("aFutureMethodThisBuildDoesNotHave")
    assert excinfo.value.code == -32601
    assert excinfo.value.code == RPCError.METHOD_NOT_FOUND


def test_version_method_not_found_means_protocol_1(avo, fake_server):
    # Appendix A: a build old enough to lack `version` raises
    # METHOD_NOT_FOUND, and callers are told to assume rpcProtocol 1.
    fake_server.clear_override("version")
    fake_server._responses.pop("version", None)
    with pytest.raises(RPCError) as excinfo:
        avo.version()
    assert excinfo.value.code == RPCError.METHOD_NOT_FOUND


def test_error_data_is_preserved(avo, fake_server):
    fake_server.set_error(
        "getMolecule", -1, "Unknown format.", data={"format": "bogus"}
    )
    with pytest.raises(RPCError) as excinfo:
        avo.get_molecule(format="bogus")
    assert excinfo.value.data == {"format": "bogus"}
