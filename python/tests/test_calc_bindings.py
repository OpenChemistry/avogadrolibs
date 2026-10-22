"""Tests for the avogadro.calc pybind11 bindings (force fields, optimizer).

These need the compiled extension modules (a built wheel), so they skip
cleanly in a source checkout.
"""

import gc
import math

import pytest

np = pytest.importorskip("numpy")
core = pytest.importorskip("avogadro.core")
calc = pytest.importorskip("avogadro.calc")


def make_water():
    mol = core.Molecule()
    mol.add_atom(8)
    mol.add_atom(1)
    mol.add_atom(1)
    mol.add_bond(0, 1, 1)
    mol.add_bond(0, 2, 1)
    # Distorted: long bonds and an obtuse angle (as in
    # tests/calc/energyoptimizertest.cpp).
    mol.positions = np.array(
        [[0.0, 0.0, 0.0], [1.30, 0.35, 0.0], [-1.05, 0.55, 0.0]]
    )
    return mol


def make_alkane(n_carbons=4):
    """A bonded n-alkane with every coordinate displaced by a fixed
    pseudo-random offset. Mirrors perturbedAlkane() in
    tests/calc/energyoptimizertest.cpp."""
    mol = core.Molecule()
    pos = []
    carbons = []
    for i in range(n_carbons):
        carbons.append(mol.add_atom(6).index)
        pos.append([1.25 * i, 0.4 if i % 2 else 0.0, 0.0])
        if i > 0:
            mol.add_bond(carbons[i - 1], carbons[i], 1)
    side = 1.0 if n_carbons > 0 else 0.0
    for i in range(n_carbons):
        up = 1.0 if i % 2 else -1.0
        n_h = 3 if i == 0 or i + 1 == n_carbons else 2
        for h in range(n_h):
            dz = 0.9 if h == 0 else -0.9
            pos.append(
                [
                    pos[i][0] + (-0.6 * side if h == 2 else 0.0),
                    pos[i][1] + 0.5 * up,
                    pos[i][2] + (0.0 if h == 2 else dz),
                ]
            )
            a = mol.add_atom(1).index
            mol.add_bond(carbons[i], a, 1)
    pos = np.array(pos)
    offsets = np.sin(12.9898 * np.arange(pos.size, dtype=float) + 1.0)
    pos = pos + 0.1 * offsets.reshape(pos.shape)
    mol.positions = pos
    return mol


def make_dimer(distance):
    mol = core.Molecule()
    mol.add_atom(6)
    mol.add_atom(6)
    mol.positions = np.array([[0.0, 0.0, 0.0], [distance, 0.0, 0.0]])
    return mol


def make_ff(factory, mol):
    ff = factory()
    ff.set_molecule(mol)
    return ff


def max_gradient(state):
    return np.abs(state.gradient).max()


def run_chunks(ff, x, options, state, max_chunks, tol=1e-4):
    energies = []
    for _ in range(max_chunks):
        x = calc.optimize_steps(ff, x, options, state)
        energies.append(state.energy)
        if max_gradient(state) < tol:
            break
    return x, energies


FACTORIES = [calc.UFF, calc.LennardJones]


# --- Registry ---


def test_models():
    assert calc.models() == ["LJ", "UFF"]
    assert calc.model_name("UFF") == "UFF"
    assert calc.model_name("LJ") == "Lennard-Jones"


def test_models_for_molecule_and_recommended():
    mol = make_water()
    assert calc.models_for_molecule(mol) == ["LJ", "UFF"]
    assert calc.recommended_model(mol) == "UFF"


def test_model_with_element_uff_lacks():
    mol = core.Molecule()
    mol.add_atom(6)
    mol.add_atom(110)
    assert calc.models_for_molecule(mol) == ["LJ"]
    assert calc.recommended_model(mol) == "LJ"


def test_unknown_model_name():
    with pytest.raises(ValueError, match="LJ, UFF"):
        calc.model_name("MMFF94")


def test_calculator_properties():
    uff = calc.UFF()
    assert uff.identifier == "UFF"
    assert uff.name == "UFF"
    assert "Universal" in uff.description
    assert uff.accepts_ions and uff.accepts_radicals and uff.accepts_unit_cell
    assert uff.molecule is None
    lj = calc.EnergyCalculator("LJ")
    assert lj.identifier == "LJ"
    assert "LJ" in repr(lj)


def test_unknown_identifier():
    with pytest.raises(ValueError, match="available: LJ, UFF"):
        calc.EnergyCalculator("MMFF94")


def test_calculators_are_independent():
    a, b = calc.UFF(), calc.UFF()
    a.set_molecule(make_water())
    assert b.molecule is None


def test_no_python_subclasses():
    with pytest.raises(TypeError):

        class Sub(calc.EnergyCalculator):
            pass


# --- Energies and gradients ---


@pytest.mark.parametrize("factory", FACTORIES)
def test_energy_matches_energy_and_gradient(factory):
    # No C++ test asserts an absolute UFF / LJ energy, so this checks that
    # the separate energy() path agrees with the fused one.
    mol = make_alkane(3)
    ff = make_ff(factory, mol)
    energy = ff.energy()
    e2, grad = ff.energy_and_gradient()
    assert math.isfinite(energy)
    assert energy == pytest.approx(e2, rel=1e-10, abs=1e-8)
    assert grad.shape == (mol.atom_count(), 3)
    assert np.array_equal(grad, ff.gradient())
    assert energy == pytest.approx(ff.energy(mol.positions))


@pytest.mark.parametrize("factory", FACTORIES)
def test_gradient_matches_finite_difference(factory):
    mol = make_alkane(3)
    ff = make_ff(factory, mol)
    x = mol.positions
    grad = ff.gradient(x)
    numeric = np.zeros_like(x)
    h = 1e-5
    for i in range(x.shape[0]):
        for k in range(3):
            plus, minus = x.copy(), x.copy()
            plus[i, k] += h
            minus[i, k] -= h
            numeric[i, k] = (ff.energy(plus) - ff.energy(minus)) / (2 * h)
    assert np.abs(grad).max() > 1.0  # a meaningful test, not all zeros
    np.testing.assert_allclose(grad, numeric, rtol=1e-5, atol=1e-4)


def test_results_are_new_arrays():
    mol = make_water()
    ff = make_ff(calc.UFF, mol)
    g1 = ff.gradient()
    g1[:] = 0
    assert np.abs(ff.gradient()).max() > 0
    x = mol.positions
    ff.energy(x)
    assert np.array_equal(x, mol.positions)


def test_positions_accepts_lists_and_ints():
    mol = make_water()
    ff = make_ff(calc.UFF, mol)
    as_list = mol.positions.tolist()
    assert ff.energy(as_list) == ff.energy()


# --- Errors ---


def test_no_molecule():
    ff = calc.UFF()
    for call in (ff.energy, ff.gradient, ff.energy_and_gradient):
        with pytest.raises(RuntimeError, match="set_molecule"):
            call()
    with pytest.raises(RuntimeError):
        calc.optimize_steps(ff, np.zeros((3, 3)))
    with pytest.raises(RuntimeError):
        ff.mask = np.ones((3, 3))
    with pytest.raises(RuntimeError):
        ff.constraints = []
    assert ff.mask is None
    assert ff.constraints == []


@pytest.mark.parametrize(
    "positions",
    [
        np.zeros((2, 3)),  # wrong atom count
        np.zeros((4, 3)),
        np.zeros(9),  # flat
        np.zeros((3, 2)),
        np.zeros((3, 3, 1)),
        np.full((3, 3), np.nan),
        np.array([[0.0, 0, 0], [np.inf, 0, 0], [0, 1, 0]]),
    ],
)
def test_bad_positions(positions):
    ff = make_ff(calc.UFF, make_water())
    for call in (ff.energy, ff.gradient, ff.energy_and_gradient):
        with pytest.raises(ValueError):
            call(positions)
    with pytest.raises(ValueError):
        calc.optimize_steps(ff, positions)


def test_molecule_without_positions():
    mol = core.Molecule()
    mol.add_atom(6)
    mol.add_atom(1)
    mol.add_bond(0, 1, 1)
    for factory in FACTORIES:
        ff = make_ff(factory, mol)
        with pytest.raises(ValueError, match="3D positions"):
            ff.energy()
        with pytest.raises(ValueError):
            calc.optimize_steps(ff)
        assert math.isfinite(ff.energy(np.array([[0.0, 0, 0], [1.1, 0, 0]])))


def test_molecule_edited_after_set_molecule():
    mol = make_water()
    ff = make_ff(calc.UFF, mol)
    ff.energy()
    mol.add_atom(1)
    with pytest.raises(RuntimeError, match="set_molecule"):
        ff.energy()
    with pytest.raises(RuntimeError, match="set_molecule"):
        calc.optimize_steps(ff, np.zeros((4, 3)))
    mol.positions = np.vstack([mol.positions[:3], [[0.0, -1.0, 0.0]]])
    ff.set_molecule(mol)
    assert math.isfinite(ff.energy())
    mol.add_bond(0, 3, 1)  # a bond count change is caught as well
    with pytest.raises(RuntimeError, match="set_molecule"):
        ff.gradient()
    ff.set_molecule(mol)
    assert ff.gradient().shape == (4, 3)


def test_element_not_supported_by_uff():
    mol = core.Molecule()
    mol.add_atom(6)
    mol.add_atom(110)
    mol.positions = np.array([[0.0, 0, 0], [2.0, 0, 0]])
    ff = calc.UFF()
    with pytest.raises(ValueError, match="110"):
        ff.set_molecule(mol)
    assert ff.molecule is None
    lj = make_ff(calc.LennardJones, mol)
    assert math.isfinite(lj.energy())


def test_failed_set_molecule_keeps_previous_molecule():
    water = make_water()
    ff = make_ff(calc.UFF, water)
    bad = core.Molecule()
    bad.add_atom(110)
    with pytest.raises(ValueError):
        ff.set_molecule(bad)
    assert ff.molecule is water
    assert math.isfinite(ff.energy())


def test_set_molecule_wrong_type():
    ff = calc.UFF()
    for bad in (5, "water", None, [1, 2]):
        with pytest.raises(TypeError):
            ff.set_molecule(bad)


# --- Edge cases ---


@pytest.mark.parametrize("factory", FACTORIES)
@pytest.mark.parametrize("n_atoms", [0, 1, 2])
@pytest.mark.parametrize("algorithm", list(calc.OptimizationAlgorithm.__members__.values()))
def test_tiny_molecules(factory, n_atoms, algorithm):
    mol = core.Molecule()
    for _ in range(n_atoms):
        mol.add_atom(6)
    x0 = np.array([[0.0, 0.0, 0.0], [3.0, 0.0, 0.0]])[:n_atoms].reshape(n_atoms, 3)
    mol.positions = x0
    ff = make_ff(factory, mol)
    assert math.isfinite(ff.energy())
    assert ff.gradient().shape == (n_atoms, 3)
    options = calc.OptimizationOptions()
    options.algorithm = algorithm
    state = calc.OptimizerState()
    x = calc.optimize_steps(ff, options=options, state=state)
    assert x.shape == (n_atoms, 3)
    assert np.isfinite(x).all()


# --- Mask and constraints ---


@pytest.mark.parametrize("factory", FACTORIES)
def test_frozen_atoms_do_not_move(factory):
    mol = make_alkane(4)
    ff = make_ff(factory, mol)
    ff.freeze_atoms([0, 5])
    mask = ff.mask
    assert mask.shape == (mol.atom_count(), 3)
    assert not mask[[0, 5]].any()
    assert mask[[1, 2]].all()
    x0 = mol.positions
    assert not ff.gradient()[[0, 5]].any()
    state = calc.OptimizerState()
    options = calc.OptimizationOptions()
    options.chunk_iterations = 100
    x, _ = run_chunks(ff, x0, options, state, 5)
    assert np.array_equal(x[[0, 5]], x0[[0, 5]])
    assert np.abs(x - x0).max() > 1e-3


def test_mask_setter_forms():
    mol = make_water()
    ff = make_ff(calc.UFF, mol)
    assert ff.mask.shape == (3, 3) and ff.mask.all()  # no frozen atoms
    ff.mask = np.array([True, False, True])  # per atom
    assert ff.mask.tolist() == [[1, 1, 1], [0, 0, 0], [1, 1, 1]]
    ff.mask = [[1, 0, 1], [1, 1, 1], [1, 1, 1]]  # per coordinate
    assert ff.mask[0].tolist() == [1, 0, 1]
    assert ff.gradient()[0, 1] == 0
    ff.mask = None
    assert ff.mask is None
    assert ff.gradient()[0, 1] != 0


@pytest.mark.parametrize(
    "mask",
    [np.ones((2, 3)), np.ones(4), np.ones(9), np.ones((3, 2)), np.full((3, 3), 0.5)],
)
def test_bad_mask(mask):
    ff = make_ff(calc.UFF, make_water())
    ff.mask = np.ones(3)
    with pytest.raises(ValueError):
        ff.mask = mask
    assert ff.mask.all()  # unchanged by the failed assignment


def test_freeze_atoms_out_of_range():
    ff = make_ff(calc.UFF, make_water())
    with pytest.raises(ValueError):
        ff.freeze_atoms([0, 3])
    assert ff.mask.all()  # unchanged by the failed call


@pytest.mark.parametrize("factory", FACTORIES)
def test_set_molecule_resets_mask(factory):
    # set_molecule() starts again from the molecule's frozen atoms (none
    # here), for the same atom count and for a changed one
    mol = make_water()
    ff = make_ff(factory, mol)
    ff.freeze_atoms([0])
    ff.set_molecule(mol)
    assert ff.mask.shape == (3, 3) and ff.mask.all()
    ff.freeze_atoms([0])
    mol.add_atom(1)
    mol.positions = np.vstack([mol.positions[:3], [[0.0, -1.0, 0.0]]])
    ff.set_molecule(mol)
    assert ff.mask.shape == (4, 3) and ff.mask.all()


@pytest.mark.parametrize("factory", FACTORIES)
def test_distance_constraint_respected(factory):
    # Far from the unconstrained minimum of the dimer (UFF has no bond
    # here, so only the van der Waals well pulls the carbons together).
    target = 4.5
    mol = make_dimer(3.8)
    ff = make_ff(factory, mol)
    free, _ = run_chunks(
        ff, mol.positions, calc.OptimizationOptions(), calc.OptimizerState(), 200
    )
    free_distance = np.linalg.norm(free[0] - free[1])
    assert abs(free_distance - target) > 0.5

    ff.constraints = [core.Constraint([0, 1], target)]
    options = calc.OptimizationOptions()
    options.chunk_iterations = 50
    x, _ = run_chunks(ff, mol.positions, options, calc.OptimizerState(), 50)
    assert np.linalg.norm(x[0] - x[1]) == pytest.approx(target, rel=0.02)


@pytest.mark.parametrize("factory", FACTORIES)
def test_angle_constraint_value_is_in_degrees(factory):
    mol = make_water()
    ff = make_ff(factory, mol)
    ff.constraints = [core.Constraint([1, 0, 2], 90.0, 1e6)]
    options = calc.OptimizationOptions()
    options.chunk_iterations = 200
    x, _ = run_chunks(ff, mol.positions, options, calc.OptimizerState(), 20)
    v1, v2 = x[1] - x[0], x[2] - x[0]
    cosine = v1 @ v2 / np.linalg.norm(v1) / np.linalg.norm(v2)
    assert np.degrees(np.arccos(cosine)) == pytest.approx(90.0, abs=0.5)


def test_constraints_roundtrip_and_validation():
    mol = make_water()
    ff = make_ff(calc.UFF, mol)
    cs = [core.Constraint([0, 1], 1.0), core.Constraint([1, 0, 2], 104.5)]
    ff.constraints = cs
    back = ff.constraints
    assert [c.atoms for c in back] == [(0, 1), (1, 0, 2)]
    assert [c.value for c in back] == [1.0, 104.5]
    with pytest.raises(ValueError, match="constraint 1"):
        ff.constraints = [core.Constraint([0, 1], 1.0), core.Constraint([0, 3], 1.0)]
    assert len(ff.constraints) == 2  # failed assignment changed nothing
    ff.constraints = []
    assert ff.constraints == []


@pytest.mark.parametrize("factory", FACTORIES)
def test_constraint_energy_is_added_in_kj(factory):
    # A restraint adds exactly k * delta**2 kJ/mol under every model (UFF
    # used to scale it by 4.184 along with its own kcal/mol terms).
    mol = make_water()
    ff = make_ff(factory, mol)
    plain = ff.energy()
    x = mol.positions
    distance = np.linalg.norm(x[1] - x[0])
    ff.constraints = [core.Constraint([0, 1], distance - 0.1, 50.0)]
    assert ff.energy() - plain == pytest.approx(50.0 * 0.1**2, abs=1e-9)


def test_set_molecule_rejects_stale_constraints():
    mol = make_water()
    ff = make_ff(calc.UFF, mol)
    ff.constraints = [core.Constraint([0, 2], 1.0)]
    small = core.Molecule()
    small.add_atom(1)
    small.add_atom(1)
    small.positions = np.array([[0.0, 0, 0], [0.8, 0, 0]])
    with pytest.raises(ValueError, match="constraints"):
        ff.set_molecule(small)
    assert ff.molecule is mol
    ff.constraints = []
    ff.set_molecule(small)


def test_constraints_wrong_types():
    ff = make_ff(calc.UFF, make_water())
    for bad in (5, [5], ["a"], [(0, 1)], core.Constraint([0, 1], 1.0)):
        with pytest.raises(TypeError):
            ff.constraints = bad


# --- Optimizer options ---


def test_options_defaults_and_nested_assignment():
    opts = calc.OptimizationOptions()
    assert opts.algorithm == calc.OptimizationAlgorithm.Lbfgs
    assert opts.chunk_iterations == 5
    assert opts.lbfgs.max_step == 0.0
    assert opts.lbfgs.wolfe_gtol == 0.9
    assert opts.fire.dt0 == 0.05
    assert opts.fire.n_delay == 5
    assert opts.hybrid.switch_gradient == 5.0
    # def_readwrite on a struct member must edit opts itself, not a copy.
    opts.lbfgs.max_step = 0.1
    opts.fire.max_move = 0.01
    opts.hybrid.switch_gradient = 1.5
    assert opts.lbfgs.max_step == 0.1
    assert opts.fire.max_move == 0.01
    assert opts.hybrid.switch_gradient == 1.5
    held = opts.fire
    held.mass = 2.0
    assert opts.fire.mass == 2.0
    opts.fire = calc.FireParameters()
    assert opts.fire.mass == 1.0
    assert "chunk_iterations=5" in repr(opts)
    assert "max_move" in repr(opts.fire)
    assert "wolfe_gtol" in repr(opts.lbfgs)
    assert "switch_gradient" in repr(opts.hybrid)


def test_nested_options_reach_the_optimizer():
    mol = make_alkane(3)
    ff = make_ff(calc.UFF, mol)
    x0 = mol.positions
    big = calc.OptimizationOptions()
    big.chunk_iterations = 20
    small = calc.OptimizationOptions()
    small.chunk_iterations = 20
    small.lbfgs.max_step = 1e-3
    moved_big = np.abs(calc.optimize_steps(ff, x0, big) - x0).max()
    moved_small = np.abs(calc.optimize_steps(ff, x0, small) - x0).max()
    assert moved_small < moved_big
    assert moved_small <= 20 * 1e-3 * (1 + 1e-9)


def test_algorithm_enum():
    names = set(calc.OptimizationAlgorithm.__members__)
    assert names == {"Lbfgs", "Fire2", "AbcFire", "Hybrid"}


@pytest.mark.parametrize(
    "mutate",
    [
        lambda o: setattr(o, "chunk_iterations", 0),
        lambda o: setattr(o.lbfgs, "max_step", -1.0),
        lambda o: setattr(o.lbfgs, "wolfe_gtol", 1.5),
        lambda o: setattr(o.lbfgs, "max_step", float("nan")),
    ],
)
def test_bad_lbfgs_options(mutate):
    ff = make_ff(calc.UFF, make_water())
    opts = calc.OptimizationOptions()
    mutate(opts)
    with pytest.raises(ValueError):
        calc.optimize_steps(ff, options=opts)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda o: setattr(o.fire, "mass", 0.0),
        lambda o: setattr(o.fire, "dt0", -1.0),
        lambda o: setattr(o.fire, "f_dec", 1.0),
        lambda o: setattr(o.fire, "f_inc", 0.5),
        lambda o: setattr(o.fire, "n_delay", -1),
        lambda o: setattr(o.fire, "max_move", float("nan")),
        lambda o: setattr(o.hybrid, "switch_gradient", float("nan")),
    ],
)
def test_bad_fire_and_hybrid_options(mutate):
    ff = make_ff(calc.UFF, make_water())
    opts = calc.OptimizationOptions()
    opts.algorithm = calc.OptimizationAlgorithm.Hybrid
    mutate(opts)
    with pytest.raises(ValueError):
        calc.optimize_steps(ff, options=opts)


# --- Optimizer ---


@pytest.mark.parametrize("factory", FACTORIES)
@pytest.mark.parametrize(
    "algorithm",
    [calc.OptimizationAlgorithm.Lbfgs, calc.OptimizationAlgorithm.Hybrid],
)
def test_chunked_loop_converges(factory, algorithm):
    mol = make_alkane(4)
    ff = make_ff(factory, mol)
    x0 = mol.positions
    start = ff.energy(x0)
    options = calc.OptimizationOptions()
    options.algorithm = algorithm
    options.chunk_iterations = 50
    state = calc.OptimizerState()
    x, energies = run_chunks(ff, x0, options, state, 400)
    assert max_gradient(state) < 1e-4
    assert ff.energy(x) < start
    if algorithm == calc.OptimizationAlgorithm.Lbfgs:
        assert all(b <= a + 1e-9 for a, b in zip(energies, energies[1:]))
    if algorithm == calc.OptimizationAlgorithm.Hybrid:
        assert state.hybrid_switched


@pytest.mark.parametrize(
    "algorithm",
    [calc.OptimizationAlgorithm.Fire2, calc.OptimizationAlgorithm.AbcFire],
)
def test_fire_makes_progress(algorithm):
    mol = make_alkane(4)
    ff = make_ff(calc.UFF, mol)
    x0 = mol.positions
    start_energy, start_grad = ff.energy_and_gradient(x0)
    options = calc.OptimizationOptions()
    options.algorithm = algorithm
    options.chunk_iterations = 50
    state = calc.OptimizerState()
    x, _ = run_chunks(ff, x0, options, state, 100)
    assert ff.energy(x) < start_energy
    assert max_gradient(state) < 0.1 * np.abs(start_grad).max()


def test_optimize_steps_does_not_modify_molecule():
    mol = make_alkane(3)
    ff = make_ff(calc.UFF, mol)
    before = mol.positions
    x = calc.optimize_steps(ff)
    assert np.array_equal(mol.positions, before)
    assert x.shape == before.shape
    assert x is not before
    assert np.abs(x - before).max() > 0
    # Passed-in positions are not modified either.
    given = before.copy()
    y = calc.optimize_steps(ff, given)
    assert np.array_equal(given, before)
    assert np.array_equal(x, y)


def test_state_consistent_with_calculator():
    mol = make_alkane(3)
    ff = make_ff(calc.UFF, mol)
    state = calc.OptimizerState()
    assert math.isnan(state.energy)
    assert state.gradient is None
    assert not state.hybrid_switched
    assert "OptimizerState" in repr(state)
    for algorithm in calc.OptimizationAlgorithm.__members__.values():
        options = calc.OptimizationOptions()
        options.algorithm = algorithm
        x = calc.optimize_steps(ff, mol.positions, options, state)
        energy, grad = ff.energy_and_gradient(x)
        assert state.energy == pytest.approx(energy, rel=1e-9)
        np.testing.assert_allclose(state.gradient, grad, rtol=1e-9, atol=1e-9)
        assert state.gradient.shape == x.shape
        state.reset()
        assert math.isnan(state.energy)
        assert state.gradient is None


def test_state_gradient_is_a_copy():
    ff = make_ff(calc.UFF, make_alkane(3))
    state = calc.OptimizerState()
    calc.optimize_steps(ff, state=state)
    g = state.gradient
    g[:] = 0
    assert np.abs(state.gradient).max() > 0


@pytest.mark.parametrize(
    "algorithm",
    [
        calc.OptimizationAlgorithm.Lbfgs,
        calc.OptimizationAlgorithm.Fire2,
        calc.OptimizationAlgorithm.Hybrid,
    ],
)
def test_stale_state_is_discarded(algorithm):
    mol = make_alkane(3)
    ff = make_ff(calc.UFF, mol)
    options = calc.OptimizationOptions()
    options.algorithm = algorithm
    options.chunk_iterations = 10
    x1 = mol.positions
    x2 = x1 + 0.05 * np.cos(np.arange(x1.size)).reshape(x1.shape)

    state = calc.OptimizerState()
    calc.optimize_steps(ff, x1, options, state)
    reused = calc.optimize_steps(ff, x2, options, state)  # not x1's result
    fresh = calc.optimize_steps(ff, x2, options, calc.OptimizerState())
    assert np.array_equal(reused, fresh)

    # Changing the calculator setup also drops it.
    state = calc.OptimizerState()
    calc.optimize_steps(ff, x1, options, state)
    ff.freeze_atoms([0])
    reused = calc.optimize_steps(ff, x2, options, state)
    fresh = calc.optimize_steps(ff, x2, options, calc.OptimizerState())
    assert np.array_equal(reused, fresh)


def test_state_continues_across_chunks():
    ff = make_ff(calc.UFF, make_alkane(3))
    options = calc.OptimizationOptions()
    options.algorithm = calc.OptimizationAlgorithm.Fire2
    options.chunk_iterations = 10
    x = ff.molecule.positions
    state = calc.OptimizerState()
    for _ in range(3):
        x = calc.optimize_steps(ff, x, options, state)
    one = calc.OptimizationOptions()
    one.algorithm = calc.OptimizationAlgorithm.Fire2
    one.chunk_iterations = 30
    y = calc.optimize_steps(ff, ff.molecule.positions, one, calc.OptimizerState())
    np.testing.assert_allclose(x, y, atol=1e-9)


def test_hybrid_switch_flag_resets():
    ff = make_ff(calc.UFF, make_alkane(3))
    options = calc.OptimizationOptions()
    options.algorithm = calc.OptimizationAlgorithm.Hybrid
    options.hybrid.switch_gradient = 1e9  # switch at the first chance
    options.chunk_iterations = 5
    state = calc.OptimizerState()
    x = calc.optimize_steps(ff, None, options, state)
    assert not state.hybrid_switched
    calc.optimize_steps(ff, x, options, state)
    assert state.hybrid_switched
    state.reset()
    assert not state.hybrid_switched


def test_optimize_with_nonfinite_energy_does_not_raise():
    mol = make_dimer(3.0)
    ff = make_ff(calc.LennardJones, mol)
    x = calc.optimize_steps(ff, np.array([[0.0, 0, 0], [1e-300, 0, 0]]))
    assert x.shape == (2, 3)


# --- Lifetime ---


@pytest.mark.parametrize("factory", FACTORIES)
def test_calculator_keeps_molecule_alive(factory):
    ff = factory()
    ff.set_molecule(make_alkane(3))
    gc.collect()
    assert math.isfinite(ff.energy())
    assert ff.gradient().shape == (11, 3)
    assert ff.molecule.atom_count() == 11
    x = calc.optimize_steps(ff)
    assert x.shape == (11, 3)


def test_replacing_molecule_releases_old_one():
    ff = calc.UFF()
    ff.set_molecule(make_water())
    ff.set_molecule(make_alkane(2))
    gc.collect()
    assert ff.molecule.atom_count() == 8
    assert math.isfinite(ff.energy())


def test_calculator_outlives_module_references():
    def build():
        ff = calc.UFF()
        ff.set_molecule(make_water())
        return ff

    ff = build()
    gc.collect()
    assert math.isfinite(ff.energy())


# --- Wrong-typed arguments must raise TypeError, never crash ---
# pybind11 3.1 runs keep_alive post-call hooks even after a failed argument
# conversion; nothing in avogadro.calc uses keep_alive, and these calls
# prove that stays true.

WRONG = [5, "x", 2.5, object(), [object()], {}]


def test_wrong_typed_arguments():
    ff = make_ff(calc.UFF, make_water())
    for bad in (object(), "x", {}, [object()], [["a", "b", "c"]] * 3):
        for method in (ff.energy, ff.gradient, ff.energy_and_gradient):
            with pytest.raises((TypeError, ValueError)):
                method(bad)
    for bad in (object(), {}, "x", [[object()]] * 3):
        with pytest.raises(TypeError):
            ff.mask = bad
    for bad in (5, "x", [-1], ["a"], 2.5):
        with pytest.raises(TypeError):
            ff.freeze_atoms(bad)
    for bad in (5, 2.5, object(), [object()], {}, None):
        with pytest.raises(TypeError):
            calc.EnergyCalculator(bad)
        with pytest.raises(TypeError):
            calc.model_name(bad)
    for bad in WRONG:
        with pytest.raises(TypeError):
            calc.models_for_molecule(bad)
        with pytest.raises(TypeError):
            calc.recommended_model(bad)
        with pytest.raises(TypeError):
            calc.optimize_steps(bad)
        with pytest.raises(TypeError):
            calc.optimize_steps(ff, None, bad)
        with pytest.raises(TypeError):
            calc.optimize_steps(ff, None, None, bad)
    with pytest.raises(TypeError):
        calc.optimize_steps(ff, None, calc.OptimizationOptions(), core.Molecule())
    with pytest.raises(TypeError):
        calc.optimize_steps(ff, None, calc.OptimizerState(), None)
    with pytest.raises(TypeError):
        calc.optimize_steps(None, None)
    with pytest.raises(TypeError):
        calc.UFF(1)
    with pytest.raises(ValueError):  # a scalar converts, but has no shape
        ff.energy(positions=5)
    with pytest.raises(TypeError):
        ff.energy(not_a_keyword=1)
    with pytest.raises(TypeError):
        ff.energy(None, None)


def test_wrong_typed_options_fields():
    opts = calc.OptimizationOptions()
    for attr, bad in [
        ("algorithm", 5),
        ("algorithm", "Lbfgs"),
        ("chunk_iterations", "x"),
        ("chunk_iterations", -1),
        ("chunk_iterations", None),
        ("lbfgs", 5),
        ("fire", calc.LbfgsParameters()),
        ("hybrid", None),
    ]:
        with pytest.raises(TypeError):
            setattr(opts, attr, bad)
    with pytest.raises(TypeError):
        opts.lbfgs.max_step = "x"
    with pytest.raises(TypeError):
        opts.fire.n_delay = 1.5
    with pytest.raises(TypeError):
        calc.LbfgsParameters(1)
    with pytest.raises(TypeError):
        calc.OptimizerState(1)
    with pytest.raises(TypeError):
        calc.OptimizationOptions(1)


def test_unbound_methods_with_wrong_self():
    cls = calc.EnergyCalculator
    for name in ("energy", "gradient", "energy_and_gradient", "set_molecule"):
        method = getattr(cls, name)
        arg = (make_water(),) if name == "set_molecule" else ()
        for bad_self in (5, "x", None, object(), core.Molecule(), calc.OptimizerState()):
            with pytest.raises(TypeError):
                method(bad_self, *arg)
    with pytest.raises(TypeError):
        cls.energy(5)
    with pytest.raises(TypeError):
        cls.freeze_atoms(5, [0])
    for prop in ("identifier", "name", "description", "molecule", "mask", "constraints"):
        with pytest.raises(TypeError):
            getattr(cls, prop).__get__(5)
    with pytest.raises(TypeError):
        cls.mask.__set__(5, None)
    with pytest.raises(TypeError):
        cls.constraints.__set__(5, [])
    state_cls = calc.OptimizerState
    with pytest.raises(TypeError):
        state_cls.reset(5)
    with pytest.raises(TypeError):
        state_cls.energy.__get__(5)
    with pytest.raises(TypeError):
        calc.LbfgsParameters.max_step.__get__(5)
    with pytest.raises(TypeError):
        calc.OptimizationOptions.lbfgs.__get__(5)
    with pytest.raises(TypeError):
        calc.OptimizationOptions.lbfgs.__set__(5, calc.LbfgsParameters())
