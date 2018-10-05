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
    .def_property("atomicNumber", &Atom::atomicNumber, &Atom::setAtomicNumber,
                  "The atomic number")
    .def("isValid", &Atom::isValid, "Check if the object is valid");

  using bondBase = BondTemplate<Molecule>;
  py::class_<bondBase>(m, "bondBase");
  py::class_<Bond, bondBase>(m, "Bond")
    .def_property_readonly("index", &Bond::index, "Index in the molecule")
    .def_property("order", &Bond::order, &Bond::setOrder,
                  "The order of the bond (single = 1, double = 2, etc")
    .def("isValid", &Bond::isValid, "Check if the object is valid")
    .def("atom1", &Bond::atom1, "The first atom")
    .def("atom2", &Bond::atom2, "The second atom");

  bool (Cube::*setLimits0)(const Molecule&, double, double) = &Cube::setLimits;
  py::class_<Cube>(m, "Cube").def(
    "setLimits", setLimits0, "Set the limits based on the molecule geometry");

  Index (Molecule::*atomCount0)() const = &Molecule::atomCount;
  Index (Molecule::*atomCount1)(unsigned char) const = &Molecule::atomCount;
  Bond (Molecule::*addBond1)(Index, Index, unsigned char) = &Molecule::addBond;
  Bond (Molecule::*addBond2)(const Atom&, const Atom&, unsigned char) =
    &Molecule::addBond;

  py::class_<Molecule>(m, "Molecule")
    .def(py::init<>())
    .def("addAtom", &Molecule::addAtom, "Add an atom")
    .def("atomCount", atomCount0, "The number of atoms")
    .def("atomCount", atomCount1,
         "The number of atoms with the supplied atomic number")
    .def("addBond", addBond1, "Add a new bond", py::arg("a1"), py::arg("a2"),
         py::arg("order") = 1)
    .def("addBond", addBond2, "Add a new bond", py::arg("a1"), py::arg("a2"),
         py::arg("order") = 1)
    .def("bondCount", &Molecule::bondCount, "The number of bonds")
    .def("addCube", &Molecule::addCube, py::return_value_policy::reference,
         "Add a new cube")
    .def("cubeCount", &Molecule::cubeCount, "The number of cubes")
    .def("hasCustomElements", &Molecule::hasCustomElements,
         "Returns true if the molecule contains any custom elements")
    .def("formula", &Molecule::formula, "The chemical formula of the molecule",
         py::arg("delimiter") = "", py::arg("show_counts_over") = 1)
    .def("mass", &Molecule::mass, "The mass of the molecule");

  bool (GaussianSetTools::*calculateMolecularOrbital0)(Cube&, int) const =
    &GaussianSetTools::calculateMolecularOrbital;
  py::class_<GaussianSetTools>(m, "GaussianSetTools")
    .def(py::init<Molecule*>())
    .def("calculateMolecularOrbital", calculateMolecularOrbital0,
         "Calculate the molecular orbital and set values in the cube");
}
