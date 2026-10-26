#include <pybind11/eigen.h>
#include <pybind11/numpy.h>
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include <avogadro/calc/energycalculator.h>
#include <avogadro/calc/energymanager.h>
#include <avogadro/calc/energyoptimizer.h>
#include <avogadro/calc/lennardjones.h>
#include <avogadro/calc/uff.h>
#include <avogadro/core/constraint.h>
#include <avogadro/core/molecule.h>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace py = pybind11;

using namespace Avogadro;

namespace {

using PositionArray =
  py::array_t<double, py::array::c_style | py::array::forcecast>;

// Every change to a calculator (new molecule, mask, constraints) takes a new
// value from this counter. An OptimizerState remembers the revision it was
// last used with, so a state cached for another calculator or setup is
// discarded instead of feeding a stale gradient to the optimizer. Only ever
// touched with the GIL held.
std::uint64_t nextRevision()
{
  static std::uint64_t counter = 0;
  return ++counter;
}

// Python wrapper around a Calc::EnergyCalculator. The C++ class hierarchy is
// not exposed: the calculator caches a raw Molecule pointer, so the wrapper
// also keeps the Python Molecule alive and remembers how big it was.
struct Calculator
{
  // molecule is declared first so that it is destroyed after impl, which
  // holds a pointer into it.
  py::object molecule; // None until set_molecule()
  std::unique_ptr<Calc::EnergyCalculator> impl;
  Index atomCount = 0;
  Index bondCount = 0;
  bool busy = false; // true while optimize_steps runs without the GIL
  std::uint64_t revision = nextRevision();

  explicit Calculator(std::unique_ptr<Calc::EnergyCalculator> model)
    : molecule(py::none()), impl(std::move(model))
  {
  }

  bool hasMolecule() const { return !molecule.is_none(); }
  Core::Molecule& mol() const { return molecule.cast<Core::Molecule&>(); }
};

// Python wrapper around Calc::OptimizerState. It also records which
// calculator setup and which positions the cached energy / gradient belong to.
struct OptimizerState
{
  Calc::OptimizerState state;
  Eigen::VectorXd lastPositions;
  std::uint64_t revision = 0;
  bool used = false;
  bool busy = false;

  void reset()
  {
    state = Calc::OptimizerState();
    lastPositions.resize(0);
    used = false;
  }
};

py::array_t<double> toArray(const double* data, Eigen::Index rows)
{
  py::array_t<double> result({ static_cast<Py_ssize_t>(rows), Py_ssize_t(3) });
  if (rows > 0)
    std::memcpy(result.mutable_data(), data,
                static_cast<size_t>(rows) * 3 * sizeof(double));
  return result;
}

py::array_t<double> toArray(const Eigen::VectorXd& vector)
{
  return toArray(vector.data(), vector.size() / 3);
}

void requireIdle(const Calculator& calc)
{
  if (calc.busy)
    throw std::runtime_error(
      "calculator is in use by optimize_steps() on another thread");
}

// The checks that come before every evaluation.
void requireCurrent(const Calculator& calc)
{
  requireIdle(calc);
  if (!calc.hasMolecule())
    throw std::runtime_error("no molecule set; call set_molecule() first");
  const Core::Molecule& molecule = calc.mol();
  if (molecule.atomCount() != calc.atomCount ||
      molecule.bondCount() != calc.bondCount)
    throw std::runtime_error(
      "molecule changed since set_molecule(); call set_molecule() again");
}

// Positions as the flat (x0, y0, z0, x1, ...) vector the C++ side wants.
Eigen::VectorXd resolvePositions(const Calculator& calc,
                                 const std::optional<PositionArray>& positions)
{
  const Index n = calc.atomCount;
  Eigen::VectorXd x(static_cast<Eigen::Index>(3 * n));
  if (positions) {
    auto buf = positions->request();
    if (buf.ndim != 2 || buf.shape[1] != 3)
      throw py::value_error("positions must have shape (N, 3)");
    if (static_cast<Index>(buf.shape[0]) != n)
      throw py::value_error("positions must have one row per atom (expected " +
                            std::to_string(n) + ", got " +
                            std::to_string(buf.shape[0]) + ")");
    if (n > 0)
      std::memcpy(x.data(), buf.ptr,
                  static_cast<size_t>(n) * 3 * sizeof(double));
  } else {
    const auto& pos = calc.mol().atomPositions3d();
    if (pos.size() != n)
      throw py::value_error(
        "the molecule has no 3D positions for every atom; pass positions");
    if (n > 0)
      std::memcpy(x.data(), pos.constData(),
                  static_cast<size_t>(n) * 3 * sizeof(double));
  }
  if (!x.allFinite())
    throw py::value_error("positions must be finite");
  return x;
}

void setMolecule(Calculator& calc, py::object molecule)
{
  requireIdle(calc);
  if (!py::isinstance<Core::Molecule>(molecule))
    throw py::type_error("molecule must be an avogadro.core.Molecule");
  Core::Molecule& mol = molecule.cast<Core::Molecule&>();
  const Calc::EnergyCalculator& model = *calc.impl;

  // Apply the same compatibility rules as
  // EnergyManager::identifiersForMolecule.
  const std::string who = model.identifier();
  if (mol.totalCharge() != 0 && !model.acceptsIons())
    throw py::value_error(who + " cannot handle charged molecules");
  if (mol.totalSpinMultiplicity() != 1 && !model.acceptsRadicals())
    throw py::value_error(who + " cannot handle radicals");
  if (mol.unitCell() != nullptr && !model.acceptsUnitCell())
    throw py::value_error(who + " cannot handle periodic systems");
  const auto present = mol.elements();
  const auto supported = model.elements();
  if ((supported & present).count() != present.count()) {
    std::string missing;
    for (size_t z = 0; z < present.size(); ++z)
      if (present[z] && !supported[z])
        missing += (missing.empty() ? "" : ", ") + std::to_string(z);
    throw py::value_error(who + " has no parameters for atomic number(s) " +
                          missing);
  }

  // Constraints set earlier name atoms of the old molecule.
  for (const auto& constraint : model.constraints())
    if (!constraint.isValid(mol.atomCount()))
      throw py::value_error(
        "existing constraints refer to atoms the molecule does not have; "
        "clear them first (calculator.constraints = [])");

  calc.molecule = std::move(molecule);
  calc.atomCount = mol.atomCount();
  calc.bondCount = mol.bondCount();
  // also resets the mask to the molecule's frozen atoms (all free if none)
  calc.impl->setMolecule(&mol);
  calc.revision = nextRevision();
}

Eigen::VectorXd parseMask(const Calculator& calc, const PositionArray& array)
{
  const Index n = calc.atomCount;
  auto buf = array.request();
  const double* data = static_cast<const double*>(buf.ptr);
  Eigen::VectorXd mask(static_cast<Eigen::Index>(3 * n));
  if (buf.ndim == 2 && buf.shape[1] == 3 &&
      static_cast<Index>(buf.shape[0]) == n) {
    if (n > 0)
      std::memcpy(mask.data(), data,
                  static_cast<size_t>(3 * n) * sizeof(double));
  } else if (buf.ndim == 1 && static_cast<Index>(buf.shape[0]) == n) {
    for (Index i = 0; i < n; ++i)
      mask.segment<3>(static_cast<Eigen::Index>(3 * i)).setConstant(data[i]);
  } else {
    throw py::value_error("mask must have shape (N, 3) or (N,), with N = " +
                          std::to_string(n) + " atoms");
  }
  for (Eigen::Index i = 0; i < mask.size(); ++i)
    if (mask[i] != 0.0 && mask[i] != 1.0)
      throw py::value_error("mask entries must be 0 (frozen) or 1 (free)");
  return mask;
}

void validateOptions(const Calc::OptimizationOptions& o)
{
  auto require = [](bool ok, const char* message) {
    if (!ok)
      throw py::value_error(message);
  };
  require(o.chunkIterations >= 1, "chunk_iterations must be at least 1");
  const auto& l = o.lbfgs;
  require(std::isfinite(l.maxStep) && l.maxStep >= 0.0,
          "lbfgs.max_step must be finite and >= 0 (0 disables the cap)");
  require(std::isfinite(l.wolfeGtol) && l.wolfeGtol >= 0.0 && l.wolfeGtol < 1.0,
          "lbfgs.wolfe_gtol must be in [0, 1)");
  const auto& f = o.fire;
  if (o.algorithm != Calc::OptimizationAlgorithm::Lbfgs) {
    require(std::isfinite(f.dt0) && f.dt0 > 0.0, "fire.dt0 must be > 0");
    require(std::isfinite(f.dtMax) && f.dtMax > 0.0, "fire.dt_max must be > 0");
    require(std::isfinite(f.alphaStart) && f.alphaStart >= 0.0 &&
              f.alphaStart <= 1.0,
            "fire.alpha_start must be in [0, 1]");
    require(std::isfinite(f.fAlpha) && f.fAlpha > 0.0 && f.fAlpha <= 1.0,
            "fire.f_alpha must be in (0, 1]");
    require(std::isfinite(f.fInc) && f.fInc >= 1.0, "fire.f_inc must be >= 1");
    require(std::isfinite(f.fDec) && f.fDec > 0.0 && f.fDec < 1.0,
            "fire.f_dec must be in (0, 1)");
    require(f.nDelay >= 0, "fire.n_delay must be >= 0");
    require(std::isfinite(f.maxMove) && f.maxMove >= 0.0,
            "fire.max_move must be finite and >= 0 (0 disables the cap)");
    require(std::isfinite(f.mass) && f.mass > 0.0, "fire.mass must be > 0");
  }
  if (o.algorithm == Calc::OptimizationAlgorithm::Hybrid)
    require(std::isfinite(o.hybrid.switchGradient) &&
              o.hybrid.switchGradient >= 0.0,
            "hybrid.switch_gradient must be finite and >= 0");
}

py::array_t<double> optimizeSteps(
  Calculator& calc, const std::optional<PositionArray>& positions,
  const std::optional<Calc::OptimizationOptions>& options,
  OptimizerState* state)
{
  requireCurrent(calc);
  Eigen::VectorXd x = resolvePositions(calc, positions);
  const Calc::OptimizationOptions opts =
    options ? *options : Calc::OptimizationOptions();
  validateOptions(opts);

  if (state != nullptr) {
    if (state->busy)
      throw std::runtime_error("state is in use by another optimize_steps()");
    // A state only describes the run that produced it: another calculator
    // setup, or positions other than the ones it returned, make its cached
    // energy and gradient wrong.
    if (state->used && (state->revision != calc.revision ||
                        state->lastPositions.size() != x.size() ||
                        !(state->lastPositions.array() == x.array()).all()))
      state->reset();
  }

  Calc::EnergyCalculator& model = *calc.impl;
  Calc::OptimizerState* statePtr = state ? &state->state : nullptr;
  bool ok = false;
  {
    // Flags are only read and written with the GIL held, so a second thread
    // that gets in while this one is computing sees them.
    struct Busy
    {
      bool& a;
      bool* b;
      Busy(bool& first, bool* second) : a(first), b(second)
      {
        a = true;
        if (b)
          *b = true;
      }
      ~Busy()
      {
        a = false;
        if (b)
          *b = false;
      }
    } busy(calc.busy, state ? &state->busy : nullptr);

    // Safe without the GIL: nothing in here calls back into Python, because
    // EnergyCalculator cannot be subclassed from Python.
    py::gil_scoped_release release;
    ok = Calc::optimizeSteps(model, x, opts, statePtr);
  }
  if (!ok)
    throw std::runtime_error("optimizeSteps failed");

  if (state != nullptr) {
    state->lastPositions = x;
    state->revision = calc.revision;
    state->used = true;
  }
  return toArray(x);
}

std::string join(const std::set<std::string>& names)
{
  std::string result;
  for (const auto& name : names)
    result += (result.empty() ? "" : ", ") + name;
  return result;
}

std::unique_ptr<Calculator> fromIdentifier(const std::string& identifier)
{
  std::unique_ptr<Calc::EnergyCalculator> model(
    Calc::EnergyManager::instance().model(identifier));
  if (!model)
    throw py::value_error(
      "unknown energy model '" + identifier +
      "'; available: " + join(Calc::EnergyManager::instance().identifiers()));
  return std::make_unique<Calculator>(std::move(model));
}

const Core::Molecule& requireMolecule(const py::object& molecule)
{
  if (!py::isinstance<Core::Molecule>(molecule))
    throw py::type_error("expected an avogadro.core.Molecule");
  return molecule.cast<const Core::Molecule&>();
}

} // namespace

PYBIND11_MODULE(calc, m)
{
  py::module_::import("avogadro.core"); // registers Molecule and Constraint

  m.doc() = "Force fields and geometry optimization.\n\n"
            "Units: coordinates in Angstrom, energies in kJ/mol, gradients "
            "in kJ/(mol*Angstrom).\n\n"
            "Only the built-in models, UFF and LJ (Lennard-Jones), exist in "
            "this package; MMFF94 and GAFF are provided by the Avogadro "
            "application's plugins.";

  // --- Optimizer options ---

  py::enum_<Calc::OptimizationAlgorithm>(m, "OptimizationAlgorithm")
    .value("Lbfgs", Calc::OptimizationAlgorithm::Lbfgs, "Limited-memory BFGS")
    .value("Fire2", Calc::OptimizationAlgorithm::Fire2, "FIRE 2.0")
    .value("AbcFire", Calc::OptimizationAlgorithm::AbcFire,
           "FIRE with bias correction (ABC-FIRE)")
    .value("Hybrid", Calc::OptimizationAlgorithm::Hybrid,
           "ABC-FIRE until the largest gradient component falls below "
           "HybridParameters.switch_gradient, then L-BFGS (one-way switch)");

  py::class_<Calc::LbfgsParameters>(m, "LbfgsParameters")
    .def(py::init<>())
    .def_readwrite("max_step", &Calc::LbfgsParameters::maxStep,
                   "Cap on the length of a step |x_new - x|, in Angstrom. 0 "
                   "disables the cap.")
    .def_readwrite("wolfe_gtol", &Calc::LbfgsParameters::wolfeGtol,
                   "Strong Wolfe curvature tolerance of the line search, "
                   "in [0, 1). Dimensionless; 0 uses the library default.")
    .def("__repr__", [](const Calc::LbfgsParameters& p) {
      return "LbfgsParameters(max_step=" + std::to_string(p.maxStep) +
             ", wolfe_gtol=" + std::to_string(p.wolfeGtol) + ")";
    });

  py::class_<Calc::FireParameters>(m, "FireParameters")
    .def(py::init<>())
    .def_readwrite("dt0", &Calc::FireParameters::dt0,
                   "Initial time step (unit mass per coordinate, forces in "
                   "kJ/(mol*Angstrom))")
    .def_readwrite("dt_max", &Calc::FireParameters::dtMax, "Largest time step")
    .def_readwrite("alpha_start", &Calc::FireParameters::alphaStart,
                   "Initial velocity mixing, in [0, 1]")
    .def_readwrite("f_alpha", &Calc::FireParameters::fAlpha,
                   "Factor applied to the mixing after n_delay uphill-free "
                   "steps, in (0, 1]")
    .def_readwrite("f_inc", &Calc::FireParameters::fInc,
                   "Factor to grow the time step by, >= 1")
    .def_readwrite("f_dec", &Calc::FireParameters::fDec,
                   "Factor to shrink the time step by, in (0, 1)")
    .def_readwrite("n_delay", &Calc::FireParameters::nDelay,
                   "Steps of downhill motion before the time step grows")
    .def_readwrite("max_move", &Calc::FireParameters::maxMove,
                   "Largest per-atom displacement per step, in Angstrom. 0 "
                   "disables the cap.")
    .def_readwrite("mass", &Calc::FireParameters::mass,
                   "Mass per coordinate, > 0 (unitless)")
    .def("__repr__", [](const Calc::FireParameters& p) {
      return "FireParameters(dt0=" + std::to_string(p.dt0) +
             ", dt_max=" + std::to_string(p.dtMax) +
             ", alpha_start=" + std::to_string(p.alphaStart) +
             ", f_alpha=" + std::to_string(p.fAlpha) +
             ", f_inc=" + std::to_string(p.fInc) +
             ", f_dec=" + std::to_string(p.fDec) +
             ", n_delay=" + std::to_string(p.nDelay) +
             ", max_move=" + std::to_string(p.maxMove) +
             ", mass=" + std::to_string(p.mass) + ")";
    });

  py::class_<Calc::HybridParameters>(m, "HybridParameters")
    .def(py::init<>())
    .def_readwrite("switch_gradient", &Calc::HybridParameters::switchGradient,
                   "Largest gradient component, in kJ/(mol*Angstrom), below "
                   "which the Hybrid algorithm hands off from ABC-FIRE to "
                   "L-BFGS")
    .def("__repr__", [](const Calc::HybridParameters& p) {
      return "HybridParameters(switch_gradient=" +
             std::to_string(p.switchGradient) + ")";
    });

  py::class_<Calc::OptimizationOptions>(m, "OptimizationOptions")
    .def(py::init<>())
    .def_readwrite("algorithm", &Calc::OptimizationOptions::algorithm,
                   "The OptimizationAlgorithm (default Lbfgs)")
    .def_readwrite("chunk_iterations",
                   &Calc::OptimizationOptions::chunkIterations,
                   "Iterations per optimize_steps() call, at least 1 "
                   "(default 5). L-BFGS memory is not carried from one call "
                   "to the next, so larger chunks need fewer total "
                   "iterations; FIRE state is carried by an OptimizerState.")
    .def_readwrite("lbfgs", &Calc::OptimizationOptions::lbfgs,
                   "LbfgsParameters (modified in place)")
    .def_readwrite("fire", &Calc::OptimizationOptions::fire,
                   "FireParameters (modified in place)")
    .def_readwrite("hybrid", &Calc::OptimizationOptions::hybrid,
                   "HybridParameters (modified in place)")
    .def("__repr__", [](const Calc::OptimizationOptions& o) {
      return "OptimizationOptions(chunk_iterations=" +
             std::to_string(o.chunkIterations) + ", ...)";
    });

  py::class_<OptimizerState>(
    m, "OptimizerState",
    "State carried between optimize_steps() calls: the energy and gradient "
    "at the last returned positions, plus the integrator state of the FIRE "
    "algorithms. It is discarded automatically if the next call uses a "
    "different calculator setup or positions other than the ones "
    "optimize_steps() last returned, so a stale gradient is never reused. "
    "Do not share one between threads.")
    .def(py::init<>())
    .def_property_readonly(
      "energy", [](const OptimizerState& self) { return self.state.energy; },
      "Energy in kJ/mol at the last returned positions; NaN before the first "
      "call (or if the energy was not finite)")
    .def_property_readonly(
      "gradient",
      [](const OptimizerState& self) -> py::object {
        if (self.state.gradient.size() == 0 ||
            self.state.gradient.size() % 3 != 0)
          return py::none();
        return toArray(self.state.gradient);
      },
      "Gradient in kJ/(mol*Angstrom) as an (N, 3) array at the last returned "
      "positions (a copy), or None before the first call")
    .def_property_readonly(
      "hybrid_switched",
      [](const OptimizerState& self) { return self.state.hybridSwitched; },
      "True once the Hybrid algorithm has switched from ABC-FIRE to L-BFGS")
    .def(
      "reset", [](OptimizerState& self) { self.reset(); },
      "Forget everything; the next optimize_steps() starts afresh")
    .def("__repr__", [](const OptimizerState& self) {
      return "OptimizerState(energy=" + std::to_string(self.state.energy) + ")";
    });

  // --- Calculators ---

  py::class_<Calculator>(
    m, "EnergyCalculator", py::is_final(),
    "An energy model (force field) bound to a molecule.\n\n"
    "EnergyCalculator('UFF') creates the model with that identifier; see "
    "models(). Call set_molecule(), then energy(), gradient() and "
    "energy_and_gradient(). Energies are in kJ/mol, gradients in "
    "kJ/(mol*Angstrom) and positions in Angstrom, as (N, 3) arrays.\n\n"
    "The calculator keeps the Molecule alive, but it analyses the molecule "
    "(atom types, non-bonded pairs) when set_molecule() is called. If you "
    "add or remove atoms or bonds afterwards, evaluations raise "
    "RuntimeError until you call set_molecule() again; it cannot see changes "
    "to bond orders or atomic numbers, so call set_molecule() after those "
    "too. Positions may change freely.\n\n"
    "Python subclasses are not supported. An instance is not thread-safe.")
    .def(py::init([](const std::string& identifier) {
           return fromIdentifier(identifier);
         }),
         py::arg("identifier"),
         "Create the model with this identifier (ValueError if unknown)")
    .def_property_readonly(
      "identifier", [](const Calculator& c) { return c.impl->identifier(); },
      "Short identifier of the model, e.g. 'UFF'")
    .def_property_readonly(
      "name", [](const Calculator& c) { return c.impl->name(); },
      "Name of the model")
    .def_property_readonly(
      "description", [](const Calculator& c) { return c.impl->description(); },
      "Description of the model")
    .def_property_readonly(
      "accepts_ions", [](const Calculator& c) { return c.impl->acceptsIons(); },
      "Whether the model can handle charged molecules")
    .def_property_readonly(
      "accepts_radicals",
      [](const Calculator& c) { return c.impl->acceptsRadicals(); },
      "Whether the model can handle radicals")
    .def_property_readonly(
      "accepts_unit_cell",
      [](const Calculator& c) { return c.impl->acceptsUnitCell(); },
      "Whether the model can handle periodic systems")
    .def_property_readonly(
      "molecule", [](const Calculator& c) { return c.molecule; },
      "The Molecule given to set_molecule(), or None")
    .def("set_molecule", &setMolecule, py::arg("molecule"),
         "Bind a molecule (or re-analyse it after editing it). ValueError if "
         "the model cannot handle its elements, charge, spin or unit cell. "
         "Resets the mask to the molecule's frozen atoms (every atom free "
         "if none are frozen); existing constraints must still be valid "
         "for the new atom count.")
    .def(
      "energy",
      [](Calculator& self, const std::optional<PositionArray>& positions) {
        requireCurrent(self);
        return self.impl->value(resolvePositions(self, positions));
      },
      py::arg("positions") = py::none(),
      "Energy in kJ/mol, including constraint restraints. positions is an "
      "(N, 3) array in Angstrom; None means the molecule's current "
      "positions (ValueError if it lacks 3D positions for every atom).")
    .def(
      "gradient",
      [](Calculator& self, const std::optional<PositionArray>& positions) {
        requireCurrent(self);
        Eigen::VectorXd x = resolvePositions(self, positions);
        Eigen::VectorXd grad;
        self.impl->evaluate(x, &grad);
        if (grad.size() != x.size())
          throw std::runtime_error("calculator returned a gradient of the "
                                   "wrong size");
        return toArray(grad);
      },
      py::arg("positions") = py::none(),
      "Gradient in kJ/(mol*Angstrom) as a new (N, 3) array. Components of "
      "frozen coordinates (see mask) are zero.")
    .def(
      "energy_and_gradient",
      [](Calculator& self, const std::optional<PositionArray>& positions) {
        requireCurrent(self);
        Eigen::VectorXd x = resolvePositions(self, positions);
        Eigen::VectorXd grad;
        const double energy = self.impl->evaluate(x, &grad);
        if (grad.size() != x.size())
          throw std::runtime_error("calculator returned a gradient of the "
                                   "wrong size");
        return py::make_tuple(energy, toArray(grad));
      },
      py::arg("positions") = py::none(),
      "(energy, gradient): kJ/mol and a new (N, 3) array in "
      "kJ/(mol*Angstrom)")
    .def_property(
      "mask",
      [](const Calculator& self) -> py::object {
        requireIdle(self);
        const Eigen::VectorXd mask = self.impl->mask();
        if (!self.hasMolecule() ||
            mask.size() != static_cast<Eigen::Index>(3 * self.atomCount))
          return py::none();
        return toArray(mask);
      },
      [](Calculator& self, const std::optional<PositionArray>& mask) {
        requireIdle(self);
        if (!mask) {
          self.impl->setMask(Eigen::VectorXd());
        } else {
          if (!self.hasMolecule())
            throw std::runtime_error(
              "no molecule set; call set_molecule() first");
          self.impl->setMask(parseMask(self, *mask));
        }
        self.revision = nextRevision();
      },
      "Which coordinates may move, as an (N, 3) array (0 = frozen, 1 = free; "
      "returned as a copy) or None for no mask. Accepts (N, 3) or one value "
      "per atom, shape (N,). Gradient components of frozen coordinates are "
      "zeroed, so the optimizers leave them alone. Needs set_molecule() "
      "first, which resets it to the molecule's frozen atoms.")
    .def(
      "freeze_atoms",
      [](Calculator& self, const std::vector<Index>& indices) {
        requireIdle(self);
        if (!self.hasMolecule())
          throw std::runtime_error(
            "no molecule set; call set_molecule() first");
        for (Index index : indices)
          if (index >= self.atomCount)
            throw py::value_error("atom index " + std::to_string(index) +
                                  " is out of range");
        const auto size = static_cast<Eigen::Index>(3 * self.atomCount);
        Eigen::VectorXd mask = self.impl->mask();
        if (mask.size() != size)
          mask = Eigen::VectorXd::Ones(size);
        for (Index index : indices)
          mask.segment<3>(static_cast<Eigen::Index>(3 * index)).setZero();
        self.impl->setMask(mask);
        self.revision = nextRevision();
      },
      py::arg("indices"),
      "Freeze all three coordinates of these atoms (added to the mask)")
    .def_property(
      "constraints",
      [](const Calculator& self) {
        requireIdle(self);
        return self.impl->constraints();
      },
      [](Calculator& self, const std::vector<Core::Constraint>& constraints) {
        requireIdle(self);
        if (!self.hasMolecule())
          throw std::runtime_error(
            "no molecule set; call set_molecule() first");
        for (size_t i = 0; i < constraints.size(); ++i)
          if (!constraints[i].isValid(self.atomCount))
            throw py::value_error("constraint " + std::to_string(i) +
                                  " names an atom the molecule does not have");
        self.impl->setConstraints(constraints);
        self.revision = nextRevision();
      },
      "List of avogadro.core.Constraint restraints added to the energy and "
      "gradient. Assigning replaces the list; every atom index is checked "
      "against the molecule. The getter returns copies, grouped by type "
      "(distances, angles, torsions) rather than in assignment order. Each "
      "adds k * (value - target)**2 in kJ/mol, with k in kJ/(mol*A**2) for "
      "distances and kJ/(mol*rad**2) for angles and torsions.")
    .def("__repr__", [](const Calculator& self) {
      return "<avogadro.calc.EnergyCalculator '" + self.impl->identifier() +
             (self.hasMolecule() ? "' with molecule>" : "'>");
    });

  m.def(
    "UFF",
    [] { return std::make_unique<Calculator>(std::make_unique<Calc::UFF>()); },
    "A new Universal Force Field calculator (elements 1-102)");
  m.def(
    "LennardJones",
    [] {
      return std::make_unique<Calculator>(
        std::make_unique<Calc::LennardJones>());
    },
    "A new Lennard-Jones calculator (all elements; a generic fallback, not "
    "a chemically accurate force field)");

  // --- Model registry ---

  m.def(
    "models",
    [] {
      const auto ids = Calc::EnergyManager::instance().identifiers();
      return std::vector<std::string>(ids.begin(), ids.end());
    },
    "Sorted identifiers of the available models ('LJ', 'UFF')");
  m.def(
    "models_for_molecule",
    [](const py::object& molecule) {
      const auto ids = Calc::EnergyManager::instance().identifiersForMolecule(
        requireMolecule(molecule));
      return std::vector<std::string>(ids.begin(), ids.end());
    },
    py::arg("molecule"),
    "Sorted identifiers of the models that can handle this molecule");
  m.def(
    "recommended_model",
    [](const py::object& molecule) {
      return Calc::EnergyManager::instance().recommendedModel(
        requireMolecule(molecule));
    },
    py::arg("molecule"),
    "Identifier of the best model for this molecule. In this package that "
    "is 'UFF' or, if UFF cannot handle it, 'LJ'.");
  m.def(
    "model_name",
    [](const std::string& identifier) {
      const auto& manager = Calc::EnergyManager::instance();
      const auto ids = manager.identifiers();
      if (ids.find(identifier) == ids.end())
        throw py::value_error("unknown energy model '" + identifier +
                              "'; available: " + join(ids));
      return manager.nameForModel(identifier);
    },
    py::arg("identifier"), "Name of the model with this identifier");

  // --- Optimizer ---

  m.def("optimize_steps", &optimizeSteps, py::arg("calculator"),
        py::arg("positions") = py::none(), py::arg("options") = py::none(),
        py::arg("state") = py::none(),
        "Run one chunk (options.chunk_iterations iterations) of geometry "
        "optimization and return the new positions as an (N, 3) array. The "
        "molecule is not modified, and the GIL is released while this runs.\n\n"
        "positions defaults to the molecule's current positions; options "
        "defaults to OptimizationOptions(); state is an optional "
        "OptimizerState that receives the energy and gradient at the result "
        "(and carries FIRE state between calls). If the energy becomes "
        "non-finite no exception is raised; check state.energy.\n\n"
        "Chunking: L-BFGS memory is not carried between calls, so larger "
        "chunks converge in fewer total iterations. Call it in a loop and "
        "decide yourself when to stop:\n\n"
        "    state = calc.OptimizerState()\n"
        "    x = mol.positions\n"
        "    for _ in range(max_chunks):\n"
        "        x = calc.optimize_steps(ff, x, opts, state)\n"
        "        if np.abs(state.gradient).max() < 1e-4:  # kJ/(mol*A), same "
        "test as the GUI\n"
        "            break\n"
        "    mol.positions = x\n\n"
        "A full optimize() with shared convergence criteria is planned.");
}
