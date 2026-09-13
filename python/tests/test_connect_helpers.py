"""
Happy-path tests for the phase 1 introspection helpers on
avogadro.connect.connect, against the fake RPC server.
"""

from _load_avogadro import load_connect_module

_mod = load_connect_module()
result_data = _mod.result_data


def test_version(avo):
    info = avo.version()
    assert info == {
        "avogadroApp": "1.103.0",
        "avogadroLibs": "2.0.0",
        "qt": "6.8.3",
        "platform": "macos",
        "rpcProtocol": 2,
    }


def test_list_commands(avo):
    commands = avo.list_commands()
    assert isinstance(commands, list)
    names = {entry["name"] for entry in commands}
    assert "openFile" in names
    assert "renderMO" in names
    for entry in commands:
        assert set(entry) == {
            "name",
            "description",
            "kind",
            "plugin",
            "async",
            "schema",
        }
        assert entry["kind"] in ("builtin", "tool", "extension")


def test_molecule_info(avo):
    info = avo.molecule_info()
    assert info["atomCount"] == 24
    assert info["formula"] == "C8H10N4O2"
    assert info["homoIndex"] == -1
    assert info["hasResidues"] is False


def test_get_molecule_default_format(avo, fake_server):
    content = avo.get_molecule()
    assert content == '{"chemical json": 1, "atoms": {}}'
    request = fake_server.requests[-1]
    assert request["method"] == "getMolecule"
    # Default format is applied by the server when the client omits it,
    # but connect.get_molecule() always sends one explicitly.
    assert request["params"]["format"] == "cjson"


def test_get_molecule_explicit_format(avo, fake_server):
    avo.get_molecule(format="xyz")
    request = fake_server.requests[-1]
    assert request["params"]["format"] == "xyz"


def test_list_display_types(avo):
    types_ = avo.list_display_types()
    names = {entry["name"] for entry in types_}
    assert names == {"BallStick", "Wireframe"}
    ball_stick = next(t for t in types_ if t["name"] == "BallStick")
    assert ball_stick["enabled"] is True
    assert ball_stick["applicable"] is True
    assert ball_stick["hasSettings"] is True


def test_set_display_types_with_list(avo, fake_server):
    avo.set_display_types(["BallStick", "VanDerWaals"])
    request = fake_server.requests[-1]
    assert request["method"] == "setRenderTypes"
    assert request["params"] == {"types": ["BallStick", "VanDerWaals"]}


def test_set_display_types_with_dict(avo, fake_server):
    avo.set_display_types({"BallStick": True, "Wireframe": False})
    request = fake_server.requests[-1]
    assert request["params"] == {"BallStick": True, "Wireframe": False}


def test_set_projection(avo, fake_server):
    avo.set_projection("orthographic")
    request = fake_server.requests[-1]
    assert request["method"] == "setProjection"
    assert request["params"] == {"type": "orthographic"}


def test_export_file_waits_by_default(avo, fake_server):
    data = avo.export_file("/tmp/out.cml")
    assert data == {"fileName": "/tmp/out.cml"}
    request = fake_server.requests[-1]
    assert request["method"] == "exportFile"
    assert request["params"]["fileName"] == "/tmp/out.cml"
    assert request["params"]["wait"] is True


def test_export_file_wait_false_returns_raw_response(avo, fake_server):
    response = avo.export_file("/tmp/out.cml", wait=False)
    assert response["result"] is True
    request = fake_server.requests[-1]
    assert "wait" not in request["params"]


def test_export_file_wait_true_uses_result_data(avo, fake_server):
    # export_file() with wait=True should agree with what a caller doing
    # this by hand through send()/result_data() would see.
    response = avo.send("exportFile", {"fileName": "/tmp/x.cml"}, wait=True)
    assert result_data(response) == {"fileName": "/tmp/x.cml"}
