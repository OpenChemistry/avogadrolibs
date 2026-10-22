#include "exporters.h"

#include <pybind11/eigen.h>
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include <avogadro/core/molecule.h>
#include <avogadro/core/unitcell.h>

#include <stdexcept>
#include <utility>

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
    // keep_alive is safe here (no arguments to fail converting), unlike on
    // Molecule's methods; see keepAlive in molecule.cpp.
    .def("atom1", guardedGet(&Bond::atom1, "invalid bond"), "The first atom",
         py::keep_alive<0, 1>())
    .def("atom2", guardedGet(&Bond::atom2, "invalid bond"), "The second atom",
         py::keep_alive<0, 1>());

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

  // Register types from other files. Order matters: BasisSet and Cube must
  // be registered before Molecule (which references them via properties).
  exportBasisSet(m);
  exportCube(m);
  exportMolecule(m);
}
