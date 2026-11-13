#include "exporters.h"

#include <pybind11/eigen.h>
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include <avogadro/core/constraint.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/unitcell.h>

#include <cmath>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace py = pybind11;

using namespace Avogadro;
using namespace Avogadro::Core;

namespace {

// Atom and Bond are lightweight proxies (molecule pointer + index). One that
// is not valid (e.g. Molecule.bond(a, b) when there is no such bond) must not
// be dereferenced, so every accessor except index/is_valid goes through
// these wrappers and raises RuntimeError instead of crashing.
template <typename T, typename R>
auto guardedGet(R (T::*getter)() const, const char* what)
{
  return [getter, what](const T& self) -> R {
    if (!self.isValid())
      throw std::runtime_error(what);
    return (self.*getter)();
  };
}

template <typename T, typename R, typename Arg>
auto guardedSet(R (T::*setter)(Arg), const char* what)
{
  return [setter, what](T& self, Arg value) {
    if (!self.isValid())
      throw std::runtime_error(what);
    (self.*setter)(std::forward<Arg>(value));
  };
}

} // namespace

PYBIND11_MODULE(core, m)
{
  m.doc() = "AvogadroCore Python binding";

  // --- Atom ---

  using atomBase = AtomTemplate<Molecule>;
  py::class_<atomBase>(m, "atomBase");
  py::class_<Atom, atomBase>(m, "Atom")
    .def_property_readonly("index", &Atom::index, "Index in the molecule")
    .def_property(
      "atomic_number", guardedGet(&Atom::atomicNumber, "invalid atom"),
      guardedSet(&Atom::setAtomicNumber, "invalid atom"), "The atomic number")
    .def_property("position", guardedGet(&Atom::position3d, "invalid atom"),
                  guardedSet(&Atom::setPosition3d, "invalid atom"),
                  "The 3D position of the atom")
    .def_property("formal_charge",
                  guardedGet(&Atom::formalCharge, "invalid atom"),
                  guardedSet(&Atom::setFormalCharge, "invalid atom"),
                  "The formal charge of the atom")
    .def_property("is_selected", guardedGet(&Atom::selected, "invalid atom"),
                  guardedSet(&Atom::setSelected, "invalid atom"),
                  "Whether the atom is selected")
    .def("is_valid", &Atom::isValid, "Check if the object is valid");

  // --- Bond ---

  using bondBase = BondTemplate<Molecule>;
  py::class_<bondBase>(m, "bondBase");
  py::class_<Bond, bondBase>(m, "Bond")
    .def_property_readonly("index", &Bond::index, "Index in the molecule")
    .def_property("order", guardedGet(&Bond::order, "invalid bond"),
                  guardedSet(&Bond::setOrder, "invalid bond"),
                  "The order of the bond (single = 1, double = 2, etc)")
    .def("is_valid", &Bond::isValid, "Check if the object is valid")
    .def(
      "atom1",
      [](const Bond& self) {
        if (!self.isValid())
          throw std::runtime_error("invalid bond");
        return keepAlive(*self.molecule(), self.atom1());
      },
      "The first atom")
    .def(
      "atom2",
      [](const Bond& self) {
        if (!self.isValid())
          throw std::runtime_error("invalid bond");
        return keepAlive(*self.molecule(), self.atom2());
      },
      "The second atom");

  // --- UnitCell ---

  py::class_<UnitCell>(m, "UnitCell")
    .def(py::init<>())
    .def_property_readonly("a", &UnitCell::a, "The a lattice parameter")
    .def_property_readonly("b", &UnitCell::b, "The b lattice parameter")
    .def_property_readonly("c", &UnitCell::c, "The c lattice parameter")
    .def_property_readonly("alpha", &UnitCell::alpha,
                           "The alpha lattice parameter")
    .def_property_readonly("beta", &UnitCell::beta,
                           "The beta lattice parameter")
    .def_property_readonly("gamma", &UnitCell::gamma,
                           "The gamma lattice parameter")
    .def_property_readonly("volume", &UnitCell::volume,
                           "The volume of the unit cell")
    .def("set_cell_parameters", &UnitCell::setCellParameters,
         "Set the unit cell parameters a b c alpha beta gamma")
    .def_property("cell_matrix", &UnitCell::cellMatrix,
                  &UnitCell::setCellMatrix, "The unit cell vector matrix")
    .def("distance", &UnitCell::distance,
         "Calculate the distance between two points in the unit cell");

  // --- Constraint ---

  py::class_<Constraint> constraintClass(
    m, "Constraint",
    "A harmonic restraint on a distance, angle or torsion.\n\n"
    "Distances are in Angstrom and angles / torsions in DEGREES. The "
    "restraint energy is k * (x - x0)^2 (no factor of one half), with k in "
    "kJ/mol/Angstrom^2 for a distance and kJ/mol/radian^2 for an angle or "
    "torsion (the angle is converted to radians internally). Torsions are "
    "periodic. Immutable once created. Atom indices are checked against a "
    "molecule when the constraint is assigned to an "
    "avogadro.calc.EnergyCalculator.");

  py::enum_<Constraint::Type>(constraintClass, "Type")
    .value("Distance", Constraint::DistanceConstraint)
    .value("Angle", Constraint::AngleConstraint)
    .value("Torsion", Constraint::TorsionConstraint)
    .value("OutOfPlane", Constraint::OutOfPlaneConstraint)
    .value("Unknown", Constraint::UnknownConstraint);

  constraintClass
    .def(
      py::init([](const std::vector<Index>& atoms, double value,
                  std::optional<double> forceConstant) {
        if (atoms.size() < 2 || atoms.size() > 4)
          throw py::value_error(
            "atoms must have 2 (distance), 3 (angle) or 4 (torsion) indices");
        for (size_t i = 0; i < atoms.size(); ++i) {
          if (atoms[i] == MaxIndex)
            throw py::value_error("invalid atom index");
          for (size_t j = 0; j < i; ++j)
            if (atoms[i] == atoms[j])
              throw py::value_error("atoms must be distinct");
        }
        if (!std::isfinite(value))
          throw py::value_error("value must be finite");
        Constraint constraint(atoms[0], atoms[1],
                              atoms.size() > 2 ? atoms[2] : MaxIndex,
                              atoms.size() > 3 ? atoms[3] : MaxIndex, value);
        if (forceConstant) {
          const double k = *forceConstant;
          if (!std::isfinite(k) || k < 0.0)
            throw py::value_error("force_constant must be finite and >= 0");
          constraint.setK(k);
        }
        return constraint;
      }),
      py::arg("atoms"), py::arg("value"),
      py::arg("force_constant") = py::none(),
      "Create a constraint on 2 (distance), 3 (angle) or 4 (torsion) atoms. "
      "value is in Angstrom or degrees. force_constant defaults to "
      "Constraint.DEFAULT_DISTANCE_K or Constraint.DEFAULT_ANGULAR_K.")
    .def_property_readonly(
      "atoms",
      [](const Constraint& self) {
        std::vector<Index> atoms{ self.aIndex(), self.bIndex() };
        if (self.cIndex() != MaxIndex)
          atoms.push_back(self.cIndex());
        if (self.dIndex() != MaxIndex)
          atoms.push_back(self.dIndex());
        return py::tuple(py::cast(atoms));
      },
      "Tuple of the 2, 3 or 4 atom indices")
    .def_property_readonly("type", &Constraint::type,
                           "The Constraint.Type, inferred from the atoms")
    .def_property_readonly("value", &Constraint::value,
                           "Target value: Angstrom (distance) or degrees "
                           "(angle, torsion)")
    .def_property_readonly("force_constant", &Constraint::k,
                           "Harmonic force constant (see the class docs for "
                           "units)")
    .def("is_valid", &Constraint::isValid, py::arg("atom_count"),
         "True if every atom index is below atom_count")
    .def("__repr__",
         [](const Constraint& self) {
           std::string atoms;
           for (auto index :
                { self.aIndex(), self.bIndex(), self.cIndex(), self.dIndex() })
             if (index != MaxIndex)
               atoms += (atoms.empty() ? "" : ", ") + std::to_string(index);
           return "Constraint(atoms=(" + atoms +
                  "), value=" + std::to_string(self.value()) +
                  ", force_constant=" + std::to_string(self.k()) + ")";
         })
    .def_property_readonly_static(
      "DEFAULT_DISTANCE_K",
      [](py::object) { return Constraint::DefaultDistanceK; },
      "Default distance force constant, kJ/mol/Angstrom^2")
    .def_property_readonly_static(
      "DEFAULT_ANGULAR_K",
      [](py::object) { return Constraint::DefaultAngularK; },
      "Default angle / torsion force constant, kJ/mol/radian^2");

  // Register types from other files. Order matters: BasisSet and Cube must
  // be registered before Molecule (which references them via properties).
  exportBasisSet(m);
  exportCube(m);
  exportMolecule(m);
}
