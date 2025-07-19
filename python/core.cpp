#include <pybind11/eigen.h>
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include <avogadro/core/cube.h>
#include <avogadro/core/gaussiansettools.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/unitcell.h>

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
    .def_property("position", &Atom::position3d, &Atom::setPosition3d,
                  "The 3D position of the atom")
    .def_property("formal_charge", &Atom::formalCharge, &Atom::setFormalCharge,
                  "The formal charge of the atom")
    .def_property("is_selected", &Atom::selected, &Atom::setSelected,
                  "Whether the atom is selected")
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

  bool (Cube::*setLimits0)(const Molecule&, float, float) = &Cube::setLimits;
  py::class_<Cube>(m, "Cube").def(
    "set_limits", setLimits0, "Set the limits based on the molecule geometry");

  Index (Molecule::*atomCount0)() const = &Molecule::atomCount;
  Index (Molecule::*atomCount1)(unsigned char) const = &Molecule::atomCount;
  Bond (Molecule::*addBond1)(Index, Index, unsigned char) = &Molecule::addBond;
  Bond (Molecule::*addBond2)(const Atom&, const Atom&, unsigned char) =
    &Molecule::addBond;
  Bond (Molecule::*bond0)(Index) const = &Molecule::bond;
  Bond (Molecule::*bond1)(const Atom&, const Atom&) const = &Molecule::bond;
  Bond (Molecule::*bond2)(Index, Index) const = &Molecule::bond;
  Cube* (Molecule::*cube0)(Index) = &Molecule::cube;

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

  UnitCell* (Molecule::*unitCell0)() = &Molecule::unitCell;

  py::class_<Molecule>(m, "Molecule")
    .def(py::init<>())
    .def("add_atom",
         static_cast<Atom (Molecule::*)(unsigned char)>(&Molecule::addAtom),
         "Add an atom")
    .def("atom_count", atomCount0, "The number of atoms")
    .def("atom_count", atomCount1,
         "The number of atoms with the supplied atomic number")
    .def("atom", &Molecule::atom, "The atom at the specified index")
    .def("add_bond", addBond1, "Add a new bond", py::arg("a1"), py::arg("a2"),
         py::arg("order") = 1)
    .def("add_bond", addBond2, "Add a new bond", py::arg("a1"), py::arg("a2"),
         py::arg("order") = 1)
    .def("bond_count", &Molecule::bondCount, "The number of bonds")
    .def("bond", bond0, "The bond at the specified index")
    .def("bond", bond1, "The bond between the specified atoms")
    .def("bond", bond2, "The bond between the specified atoms")
    .def("add_cube", &Molecule::addCube, py::return_value_policy::reference,
         "Add a new cube")
    .def("cube_count", &Molecule::cubeCount, "The number of cubes")
    .def("cube", cube0, "The cube at the specified index")
    .def_property_readonly("radius", &Molecule::radius,
                           "The radius of the molecule")
    .def_property_readonly("center", &Molecule::centerOfGeometry,
                           "The center of geometry of the molecule")
    .def_property_readonly("mass_center", &Molecule::centerOfMass,
                           "The center of mass of the molecule")
    .def_property_readonly("unit_cell", unitCell0,
                           "The unit cell of the molecule, if defined")
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
