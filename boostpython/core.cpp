#include <boost/python.hpp>

#include <avogadro/core/molecule.h>

using namespace boost::python;
using namespace Avogadro;
using namespace Avogadro::Core;

void exportCore()
{
  class_<Atom>("Atom")
    .add_property("index",
                  &Atom::index,
                  "Index in the molecule")
    .add_property("atomicNumber",
                  &Atom::atomicNumber,
                  &Atom::setAtomicNumber,
                  "The atomic number")
    .def("isValid",
         &Atom::isValid,
         "Check if the object is valid")
    ;

  class_<Bond>("Bond")
    .add_property("index",
                  &Bond::index,
                  "Index in the molecule")
    .add_property("order",
                  &Bond::order,
                  &Bond::setOrder,
                  "The order of the bond (single = 1, double = 2, etc")
    .def("isValid",
         &Bond::isValid,
         "Check if the object is valid")
    .def("atom1",
         &Bond::atom1,
         "The first atom")
    .def("atom2",
         &Bond::atom2,
         "The second atom")
    ;

  Index (Molecule::*atomCount0)() const                   = &Molecule::atomCount;
  Index (Molecule::*atomCount1)(unsigned char) const      = &Molecule::atomCount;
  Bond (Molecule::*addBond1)(Index, Index, unsigned char) = &Molecule::addBond;
  Bond (Molecule::*addBond2)(const Atom&, const Atom&,
                             unsigned char)               = &Molecule::addBond;

  class_<Molecule>("Molecule")
    .def("addAtom",
         &Molecule::addAtom,
         "Add an atom")
    .def("atomCount",
         atomCount0,
         "The number of atoms")
    .def("atomCount",
         atomCount1,
         "The number of atoms with the supplied atomic number")
    .def("addBond",
         addBond1,
         "Add a new bond")
    .def("addBond",
         addBond2,
         "Add a new bond")
    .def("bondCount",
         &Molecule::bondCount,
         "The number of bonds")
    .def("hasCustomElements",
         &Molecule::hasCustomElements,
	 "Returns true if the molecule contains any custom elements")
    .def("formula",
         &Molecule::formula,
         "The chemical formula of the molecule")
    .def("mass",
         &Molecule::mass,
         "The mass of the molecule")
  ;
}
