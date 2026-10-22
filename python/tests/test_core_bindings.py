"""Safety tests for the avogadro.core pybind11 bindings.

These need the compiled extension modules (a built wheel), so they skip
cleanly in a source checkout.
"""

import gc

import pytest

np = pytest.importorskip("numpy")
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


# --- Bulk arrays are copies ---


def test_positions_survive_reallocation():
    mol = core.Molecule()
    mol.add_atom(6)
    mol.positions = np.array([[1.0, 2.0, 3.0]])
    old = mol.positions
    expected = old.copy()
    for _ in range(1000):
        mol.add_atom(1)
    mol.positions = np.full((1001, 3), 7.0)
    assert np.array_equal(old, expected)


def test_atomic_numbers_survive_reallocation():
    mol = make_water()
    old = mol.atomic_numbers
    for _ in range(1000):
        mol.add_atom(6)
    mol.atomic_numbers = np.full(1003, 9, dtype=np.uint8)
    assert old.tolist() == [8, 1, 1]


def test_bond_arrays_survive_reallocation():
    mol = make_water()
    pairs, orders = mol.bond_pairs, mol.bond_orders
    for _ in range(500):
        a = mol.add_atom(6)
        b = mol.add_atom(6)
        mol.add_bond(a, b, 3)
    assert pairs.tolist() == [[0, 1], [0, 2]]
    assert orders.tolist() == [1, 1]


def test_writing_returned_array_does_not_change_molecule():
    mol = make_water()
    mol.positions = np.arange(9, dtype=float).reshape(3, 3)
    mol.formal_charges = np.array([-1, 0, 1], dtype=np.int8)

    mol.atomic_numbers[0] = 99
    mol.positions[0, 0] = 99.0
    mol.formal_charges[0] = 5
    mol.bond_orders[0] = 3
    mol.bond_pairs[0, 0] = 2

    assert mol.atomic_numbers.tolist() == [8, 1, 1]
    assert mol.positions[0, 0] == 0.0
    assert mol.formal_charges.tolist() == [-1, 0, 1]
    assert mol.bond_orders.tolist() == [1, 1]
    assert mol.bond_pairs.tolist() == [[0, 1], [0, 2]]


def test_write_does_not_leak_into_copied_molecule():
    # Core::Array is copy-on-write; a write through a view of the shared
    # buffer used to be visible in every molecule sharing it.
    mol = make_water()
    mol.positions = np.ones((3, 3))
    other = core.Molecule()
    for z in (8, 1, 1):
        other.add_atom(z)
    other.positions = mol.positions
    view = mol.positions
    view[:] = -5.0
    assert np.all(other.positions == 1.0)
    assert np.all(mol.positions == 1.0)


def test_bulk_array_shapes_and_dtypes():
    mol = make_water()
    mol.positions = np.zeros((3, 3))
    assert mol.positions.shape == (3, 3)
    assert mol.positions.dtype == np.float64
    assert mol.atomic_numbers.shape == (3,)
    assert mol.atomic_numbers.dtype == np.uint8
    assert mol.formal_charges.dtype == np.int8
    assert mol.bond_pairs.shape == (2, 2)
    assert mol.bond_pairs.dtype == np.uintp
    assert mol.bond_orders.shape == (2,)
    assert mol.bond_orders.dtype == np.uint8
    assert mol.positions.flags.c_contiguous
    assert mol.bond_pairs.flags.c_contiguous


def test_empty_bulk_arrays():
    mol = core.Molecule()
    assert mol.positions.shape == (0, 3)
    assert mol.force_vectors.shape == (0, 3)
    assert mol.bond_pairs.shape == (0, 2)
    assert mol.atomic_numbers.shape == (0,)
    assert mol.formal_charges.shape == (0,)
    assert mol.bond_orders.shape == (0,)
    assert mol.positions.dtype == np.float64
    assert mol.bond_pairs.dtype == np.uintp


def make_cube(points=(3, 4, 5)):
    mol = core.Molecule()
    cube = mol.add_cube()
    assert cube.set_limits(np.zeros(3), np.array(points, dtype=np.int32), 0.5)
    return mol, cube


def test_cube_data_is_read_only_view():
    mol, cube = make_cube()
    cube.fill(1.0)
    data = cube.data
    assert data.shape == (3, 4, 5)
    assert not data.flags.writeable
    with pytest.raises(ValueError):
        data[0, 0, 0] = 5.0
    assert cube.value(0, 0, 0) == 1.0


def test_cube_data_assignment_still_works():
    mol, cube = make_cube()
    cube.data = np.arange(60, dtype=np.float32).reshape(3, 4, 5)
    assert cube.value(1, 2, 3) == np.float32(1 * 20 + 2 * 5 + 3)
    assert cube.data[1, 2, 3] == np.float32(33)


# --- Setters validate their input ---


def test_set_positions_roundtrip():
    mol = make_water()
    pos = np.arange(9, dtype=float).reshape(3, 3)
    mol.positions = pos
    assert np.array_equal(mol.positions, pos)


@pytest.mark.parametrize("rows", [0, 2, 4, 100])
def test_set_positions_wrong_length(rows):
    mol = make_water()
    mol.positions = np.ones((3, 3))
    if rows == 0:
        # An empty array is accepted by the core (it clears the positions)
        mol.positions = np.zeros((0, 3))
        assert mol.positions.shape == (0, 3)
        return
    with pytest.raises(ValueError, match="3.*%d|%d.*3" % (rows, rows)):
        mol.positions = np.zeros((rows, 3))
    assert np.all(mol.positions == 1.0)


@pytest.mark.parametrize("shape", [(3,), (3, 2), (3, 4), (1, 3, 3), ()])
def test_set_positions_wrong_shape(shape):
    mol = make_water()
    with pytest.raises(ValueError):
        mol.positions = np.zeros(shape)


def test_set_atomic_numbers_roundtrip():
    mol = make_water()
    mol.atomic_numbers = np.array([6, 7, 8], dtype=np.uint8)
    assert mol.atomic_numbers.tolist() == [6, 7, 8]
    assert mol.atom(1).atomic_number == 7


@pytest.mark.parametrize("count", [0, 2, 4])
def test_set_atomic_numbers_wrong_length(count):
    mol = make_water()
    with pytest.raises(ValueError, match="3.*%d|%d.*3" % (count, count)):
        mol.atomic_numbers = np.ones(count, dtype=np.uint8)
    assert mol.atomic_numbers.tolist() == [8, 1, 1]


def test_set_atomic_numbers_wrong_ndim():
    mol = make_water()
    with pytest.raises(ValueError):
        mol.atomic_numbers = np.array(6, dtype=np.uint8)  # 0-d
    with pytest.raises(ValueError):
        mol.atomic_numbers = np.ones((3, 1), dtype=np.uint8)
    assert mol.atomic_numbers.tolist() == [8, 1, 1]


def test_set_formal_charges():
    mol = make_water()
    mol.formal_charges = np.array([-2, 1, 1], dtype=np.int8)
    assert mol.formal_charges.tolist() == [-2, 1, 1]
    with pytest.raises(ValueError, match="3.*2|2.*3"):
        mol.formal_charges = np.zeros(2, dtype=np.int8)
    with pytest.raises(ValueError):
        mol.formal_charges = np.array(1, dtype=np.int8)
    assert mol.formal_charges.tolist() == [-2, 1, 1]


def test_set_atomic_numbers_updates_element_state():
    mol = make_water()
    mol.atomic_numbers = np.array([6, 6, 6], dtype=np.uint8)
    assert mol.formula() == "C3"


def test_cube_data_wrong_size():
    mol, cube = make_cube((3, 4, 5))
    with pytest.raises(ValueError, match="60"):
        cube.data = np.zeros(59, dtype=np.float32)
    with pytest.raises(ValueError):
        cube.data = np.zeros((3, 4, 6), dtype=np.float32)
    with pytest.raises(ValueError):
        cube.data = np.zeros(0, dtype=np.float32)


def test_cube_data_flat_array_of_right_size():
    mol, cube = make_cube((3, 4, 5))
    cube.data = np.arange(60, dtype=np.float32)
    assert cube.data.shape == (3, 4, 5)
    assert cube.data[0, 0, 4] == 4.0


def test_cube_data_before_limits_rejected():
    cube = core.Molecule().add_cube()
    with pytest.raises(ValueError):
        cube.data = np.ones(8, dtype=np.float32)
