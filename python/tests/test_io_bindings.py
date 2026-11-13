"""Error handling tests for the avogadro.io pybind11 bindings.

These need the compiled extension modules (a built wheel), so they skip
cleanly in a source checkout.
"""

import pytest

core = pytest.importorskip("avogadro.core")
io = pytest.importorskip("avogadro.io")

ETHANE_XYZ = """8
Ethane
H      1.18508   -0.00384    0.98752
C      0.75162   -0.02244   -0.02084
H      1.16693    0.83301   -0.56931
H      1.11552   -0.93289   -0.51453
C     -0.75159    0.02250    0.02089
H     -1.16688   -0.83337    0.56870
H     -1.11569    0.93261    0.51508
H     -1.18499    0.00442   -0.98752
"""


@pytest.fixture
def manager():
    return io.FileFormatManager()


def test_read_string_success(manager):
    mol = core.Molecule()
    assert manager.read_string(mol, ETHANE_XYZ, "xyz") is True
    assert mol.atom_count() == 8


def test_read_string_unknown_format_raises(manager):
    with pytest.raises(RuntimeError, match="nosuchformat"):
        manager.read_string(core.Molecule(), ETHANE_XYZ, "nosuchformat")


def test_read_string_malformed_input_raises(manager):
    with pytest.raises(RuntimeError):
        manager.read_string(core.Molecule(), "not an xyz file\n", "xyz")


def test_read_file_missing_raises(manager, tmp_path):
    with pytest.raises(RuntimeError):
        manager.read_file(core.Molecule(), str(tmp_path / "missing.xyz"))


def test_read_file_unknown_extension_raises(manager, tmp_path):
    path = tmp_path / "mol.nosuchformat"
    path.write_text(ETHANE_XYZ)
    with pytest.raises(RuntimeError):
        manager.read_file(core.Molecule(), str(path))


def test_file_roundtrip_success(manager, tmp_path):
    mol = core.Molecule()
    assert manager.read_string(mol, ETHANE_XYZ, "xyz")
    path = str(tmp_path / "out.xyz")
    assert manager.write_file(mol, path) is True
    again = core.Molecule()
    assert manager.read_file(again, path) is True
    assert again.atom_count() == 8


def test_write_file_unwritable_path_raises(manager, tmp_path):
    mol = core.Molecule()
    assert manager.read_string(mol, ETHANE_XYZ, "xyz")
    with pytest.raises(RuntimeError):
        manager.write_file(mol, str(tmp_path / "no_such_dir" / "out.xyz"))


def test_write_file_unknown_extension_raises(manager, tmp_path):
    with pytest.raises(RuntimeError):
        manager.write_file(core.Molecule(), str(tmp_path / "x.nosuchformat"))


def test_write_string_success(manager):
    mol = core.Molecule()
    assert manager.read_string(mol, ETHANE_XYZ, "xyz")
    text = manager.write_string(mol, "xyz")
    assert text.splitlines()[0].strip() == "8"


def test_write_string_unknown_format_raises(manager):
    with pytest.raises(RuntimeError, match="nosuchformat"):
        manager.write_string(core.Molecule(), "nosuchformat")


def test_error_does_not_leak_into_next_call(manager):
    with pytest.raises(RuntimeError):
        manager.read_string(core.Molecule(), ETHANE_XYZ, "nosuchformat")
    with pytest.raises(RuntimeError) as info:
        manager.read_string(core.Molecule(), "not an xyz file\n", "xyz")
    assert "nosuchformat" not in str(info.value)
    mol = core.Molecule()
    assert manager.read_string(mol, ETHANE_XYZ, "xyz") is True
