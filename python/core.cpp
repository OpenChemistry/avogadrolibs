#include <pybind11/pybind11.h>

#include <avogadro/core/cube.h>
#include <avogadro/core/gaussiansettools.h>
#include <avogadro/core/molecule.h>

namespace py = pybind11;

using namespace Avogadro;
using namespace Avogadro::Core;

PYBIND11_MODULE(core, m)
{
  m.doc() = "AvogadroCore Python binding";

  using atomBase = AtomTemplate<Molecule>;
  py::class_<atomBase>(m, "atomBase");
  py::class_<Atom, atomBase>(m, "Atom")
    .def_property_readonly("index", &Atom::index, "Index in the molecule")
    .def_property("atomic_number", &Atom::atomicNumber, &Atom::setAtomicNumber,
                  "The atomic number")
    .def("is_valid", &Atom::isValid, "Check if the object is valid");

  using bondBase = BondTemplate<Molecule>;
  py::class_<bondBase>(m, "bondBase");
  py::class_<Bond, bondBase>(m, "Bond")
    .def_property_readonly("index", &Bond::index, "Index in the molecule")
    .def_property("order", &Bond::order, &Bond::setOrder,
                  "The order of the bond (single = 1, double = 2, etc")
    .def("is_valid", &Bond::isValid, "Check if the object is valid")
    .def("atom1", &Bond::atom1, "The first atom")
    .def("atom2", &Bond::atom2, "The second atom");

  bool (Cube::*setLimits0)(const Molecule&, double, double) = &Cube::setLimits;
  py::class_<Cube>(m, "Cube").def(
    "set_limits", setLimits0, "Set the limits based on the molecule geometry");

  Index (Molecule::*atomCount0)() const = &Molecule::atomCount;
  Index (Molecule::*atomCount1)(unsigned char) const = &Molecule::atomCount;
  Bond (Molecule::*addBond1)(Index, Index, unsigned char) = &Molecule::addBond;
  Bond (Molecule::*addBond2)(const Atom&, const Atom&, unsigned char) =
    &Molecule::addBond;

  py::class_<Molecule>(m, "Molecule")
    .def(py::init<>())
    .def("add_atom",
         static_cast<Atom (Molecule::*)(unsigned char)>(&Molecule::addAtom),
         "Add an atom")
    .def("atom_count", atomCount0, "The number of atoms")
    .def("atom_count", atomCount1,
         "The number of atoms with the supplied atomic number")
    .def("add_bond", addBond1, "Add a new bond", py::arg("a1"), py::arg("a2"),
         py::arg("order") = 1)
    .def("add_bond", addBond2, "Add a new bond", py::arg("a1"), py::arg("a2"),
         py::arg("order") = 1)
    .def("bond_count", &Molecule::bondCount, "The number of bonds")
    .def("add_cube", &Molecule::addCube, py::return_value_policy::reference,
         "Add a new cube")
    .def("cube_count", &Molecule::cubeCount, "The number of cubes")
    .def("has_custom_elements", &Molecule::hasCustomElements,
         "Returns true if the molecule contains any custom elements")
    .def("formula", &Molecule::formula, "The chemical formula of the molecule",
         py::arg("delimiter") = "", py::arg("show_counts_over") = 1)
    .def("mass", &Molecule::mass, "The mass of the molecule");

  bool (GaussianSetTools::*calculateMolecularOrbital0)(Cube&, int) const =
    &GaussianSetTools::calculateMolecularOrbital;
  bool (GaussianSetTools::*calculateElectronDensity0)(Cube&) const =
    &GaussianSetTools::calculateElectronDensity;
  bool (GaussianSetTools::*calculateSpinDensity0)(Cube&) const =
    &GaussianSetTools::calculateSpinDensity;
  py::class_<GaussianSetTools>(m, "GaussianSetTools")
    .def(py::init<Molecule*>())
    .def("calculate_molecular_orbital", calculateMolecularOrbital0,
         "Calculate the molecular orbital and set values in the cube")
    .def("calculate_electron_density", calculateElectronDensity0,
         "Calculate the electron density and set values in the cube")
    .def("calculate_spin_density", calculateSpinDensity0,
         "Calculate the spin density and set values in the cube");
}
