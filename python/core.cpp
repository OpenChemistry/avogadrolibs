#include "exporters.h"

#include <pybind11/eigen.h>
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include <avogadro/core/molecule.h>
#include <avogadro/core/unitcell.h>

namespace py = pybind11;

using namespace Avogadro;
using namespace Avogadro::Core;

PYBIND11_MODULE(core, m)
{
  m.doc() = "AvogadroCore Python binding";

  // --- Atom ---

  using atomBase = AtomTemplate<Molecule>;
  py::class_<atomBase>(m, "atomBase");
  py::class_<Atom, atomBase>(m, "Atom")
    .def_property_readonly("index", &Atom::index, "Index in the molecule")
    .def_property("atomic_number", &Atom::atomicNumber, &Atom::setAtomicNumber,
                  "The atomic number")
    .def_property("position", &Atom::position3d, &Atom::setPosition3d,
                  "The 3D position of the atom")
    .def_property("formal_charge", &Atom::formalCharge, &Atom::setFormalCharge,
                  "The formal charge of the atom")
    .def_property("is_selected", &Atom::selected, &Atom::setSelected,
                  "Whether the atom is selected")
    .def("is_valid", &Atom::isValid, "Check if the object is valid");

  // --- Bond ---

  using bondBase = BondTemplate<Molecule>;
  py::class_<bondBase>(m, "bondBase");
  py::class_<Bond, bondBase>(m, "Bond")
    .def_property_readonly("index", &Bond::index, "Index in the molecule")
    .def_property("order", &Bond::order, &Bond::setOrder,
                  "The order of the bond (single = 1, double = 2, etc)")
    .def("is_valid", &Bond::isValid, "Check if the object is valid")
    .def("atom1", &Bond::atom1, "The first atom")
    .def("atom2", &Bond::atom2, "The second atom");

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
