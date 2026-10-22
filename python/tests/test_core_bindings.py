"""Safety tests for the avogadro.core pybind11 bindings.

These need the compiled extension modules (a built wheel), so they skip
cleanly in a source checkout.
"""

import gc

import pytest

core = pytest.importorskip("avogadro.core")


def make_water():
    mol = core.Molecule()
    mol.add_atom(8)
    mol.add_atom(1)
    mol.add_atom(1)
    mol.add_bond(0, 1, 1)
    mol.add_bond(0, 2, 1)
    return mol


# --- Atom/Bond lifetime ---


def test_atom_outlives_molecule_reference():
    atom = core.Molecule().add_atom(6)
    gc.collect()
    assert atom.atomic_number == 6
    assert atom.is_valid()


def test_atom_from_index_outlives_molecule_reference():
    atom = make_water().atom(0)
    gc.collect()
    assert atom.atomic_number == 8


def test_bond_and_its_atoms_outlive_molecule_reference():
    bond = make_water().bond(0)
    gc.collect()
    assert bond.order == 1
    assert bond.atom1().atomic_number == 8
    assert bond.atom2().atomic_number == 1


def test_add_bond_result_outlives_molecule_reference():
    mol = core.Molecule()
    a = mol.add_atom(6)
    b = mol.add_atom(6)
    bond = mol.add_bond(a, b, 2)
    del mol, a, b
    gc.collect()
    assert bond.order == 2


def test_bond_between_atoms_outlives_molecule_reference():
    mol = make_water()
    bond = mol.bond(mol.atom(0), mol.atom(1))
    bond2 = mol.bond(0, 2)
    del mol
    gc.collect()
    assert bond.order == 1
    assert bond2.atom2().atomic_number == 1


# --- Out-of-range / invalid proxies ---


@pytest.mark.parametrize("index", [3, 1000, 2**40])
def test_atom_index_out_of_range(index):
    with pytest.raises(IndexError):
        make_water().atom(index)


@pytest.mark.parametrize("index", [2, 1000, 2**40])
def test_bond_index_out_of_range(index):
    with pytest.raises(IndexError):
        make_water().bond(index)


def test_negative_index_rejected():
    mol = make_water()
    with pytest.raises((IndexError, TypeError)):
        mol.atom(-1)
    with pytest.raises((IndexError, TypeError)):
        mol.bond(-1)


def test_missing_bond_is_invalid_and_guarded():
    mol = core.Molecule()
    mol.add_atom(6)
    bond = mol.bond(0, 0)
    assert not bond.is_valid()
    with pytest.raises(RuntimeError, match="invalid bond"):
        bond.atom1()
    with pytest.raises(RuntimeError, match="invalid bond"):
        bond.atom2()
    with pytest.raises(RuntimeError, match="invalid bond"):
        bond.order
    with pytest.raises(RuntimeError, match="invalid bond"):
        bond.order = 2


def test_bond_with_out_of_range_atoms_is_invalid():
    bond = make_water().bond(0, 99)
    assert not bond.is_valid()
    with pytest.raises(RuntimeError, match="invalid bond"):
        bond.atom1()


def test_unbonded_pair_is_invalid():
    mol = make_water()
    bond = mol.bond(1, 2)  # the two hydrogens
    assert not bond.is_valid()
    with pytest.raises(RuntimeError):
        bond.atom1()


def test_valid_proxies_still_work():
    mol = make_water()
    assert mol.atom(1).atomic_number == 1
    assert mol.atom(0).index == 0
    assert mol.bond(1).atom1().index == 0
    assert mol.bond(1).atom2().index == 2
    assert mol.bond(mol.atom(0), mol.atom(2)).index == 1
    assert mol.bond(2, 0).index == 1
    atom = mol.atom(0)
    atom.atomic_number = 16
    assert mol.atom(0).atomic_number == 16


def test_bond_rejects_atom_from_another_molecule():
    mol = make_water()
    other = make_water()
    with pytest.raises(ValueError):
        mol.bond(mol.atom(0), other.atom(1))
