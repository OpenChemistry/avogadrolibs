# avogadro/calc

Energies, gradients and charges: the `EnergyCalculator` interface, built-in
methods (UFF, Lennard-Jones), the optimizers, `EnergyManager`, and the charge
model interfaces (`ChargeModel`, `ChargeManager`, `DefaultModel`).

See the top-level [AGENTS.md](../../AGENTS.md) for the module map and the
rules that apply everywhere.

## Why it is separate

Calculators depend only on `Core` and Eigen, so they run from Python, from
tests and from background threads without Qt. Methods that need Qt or an
external program (Open Babel force fields, script-based energies and charges)
are wrapped in `qtplugins/forcefield` and `qtplugins/scriptcharges`, which
register them at runtime with `EnergyManager::registerModel` or
`ChargeManager::registerModel`.

## This code needs human review

Force-field terms, their derivatives, parameter tables and unit conversions
are exactly where small mistakes give results that look plausible but are
wrong. Any change here needs a reviewer who checks the math against the
original reference, and a test that compares the analytic gradient with a
finite-difference one (see `tests/calc/gradienttest.cpp`).

## Things to know

- Coordinates are passed as a flat `Eigen::VectorXd` of length 3N in Ångström
  (x0, y0, z0, x1, ...).
- **Units:** energies returned by `EnergyCalculator::value()` are in kJ/mol,
  and gradients in kJ/mol/Å. UFF parameters are in kcal/mol and are converted
  with `KCAL_TO_KJ` in [uff.cpp](uff.cpp). Restraints (`Core::Constraint`) are
  already in kJ/mol. Document the unit of every new term and convert at one
  clearly marked place.
- `gradient()` defaults to finite differences. Analytic gradients must agree
  with it.
- Derived classes add `constraintEnergies()` to the energy, and in the
  gradient call `cleanGradients()` (which zeroes frozen atoms per the mask) and
  `constraintGradients()`. Follow `UFF::evaluate()` and
  `LennardJones::evaluate()` rather than inventing a new order.
- **Every energy model must report kJ/mol**, including the scripted ones (the
  plugin contract requires it). The force field plugin relies on this when it
  records energies on the molecule. Users choose the units energies are shown
  in through the energy units setting (`QtGui::EnergyUnits` and
  `EnergyUnitsDialog`), so convert only for display, never inside a model.
- Use Eigen vector operations rather than element loops where it reads
  naturally.
- Guard against the degenerate cases: zero or one atom, coincident atoms
  (zero distance), collinear angles, and NaN or infinite values coming back
  from a term.
- A new built-in method is added in `EnergyManager`'s constructor
  ([energymanager.cpp](energymanager.cpp)) and must implement `newInstance()`,
  `identifier()`, `name()` and `elements()`.

## Tests

`tests/calc/` covers each calculator, the optimizer, the managers, edge cases
(`forcefieldedgecasetest.cpp`) and analytic-versus-numeric gradients, with a
libFuzzer harness in `fuzz-forcefield.cpp`.
