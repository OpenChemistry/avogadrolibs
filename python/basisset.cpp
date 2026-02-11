#include "exporters.h"

#include <pybind11/eigen.h>
#include <pybind11/numpy.h>
#include <pybind11/stl.h>

#include <avogadro/core/basisset.h>
#include <avogadro/core/cube.h>
#include <avogadro/core/gaussianset.h>
#include <avogadro/core/gaussiansettools.h>
#include <avogadro/core/molecule.h>

namespace py = pybind11;

using namespace Avogadro;
using namespace Avogadro::Core;

void exportBasisSet(py::module_& m)
{
  // --- BasisSet ---

  auto basisSetClass = py::class_<BasisSet>(m, "BasisSet");

  py::enum_<BasisSet::ElectronType>(basisSetClass, "ElectronType")
    .value("Paired", BasisSet::Paired)
    .value("Alpha", BasisSet::Alpha)
    .value("Beta", BasisSet::Beta)
    .export_values();

  basisSetClass
    .def("electron_count", &BasisSet::electronCount,
         py::arg("type") = BasisSet::Paired, "The number of electrons")
    .def("molecular_orbital_count", &BasisSet::molecularOrbitalCount,
         py::arg("type") = BasisSet::Paired, "The number of molecular orbitals")
    .def("homo", &BasisSet::homo, py::arg("type") = BasisSet::Paired,
         "The HOMO orbital index")
    .def("lumo", &BasisSet::lumo, py::arg("type") = BasisSet::Paired,
         "The LUMO orbital index")
    .def("is_valid", &BasisSet::isValid, "Check if the basis set is valid")
    .def_property_readonly("name", &BasisSet::name, "The basis set name")
    .def_property_readonly("theory_name", &BasisSet::theoryName,
                           "The theory/method name")
    .def("symmetry_labels", &BasisSet::symmetryLabels,
         py::arg("type") = BasisSet::Paired, "Orbital symmetry labels")
    .def(
      "mo_energy",
      [](BasisSet& self, BasisSet::ElectronType type) -> py::array_t<double> {
        auto& energies = self.moEnergy(type);
        if (energies.empty())
          return py::array_t<double>(0);
        return py::array_t<double>({ static_cast<Py_ssize_t>(energies.size()) },
                                   { static_cast<Py_ssize_t>(sizeof(double)) },
                                   energies.data(), py::cast(self));
      },
      py::arg("type") = BasisSet::Paired,
      "MO energies as a numpy array (Hartrees)")
    .def(
      "mo_occupancy",
      [](BasisSet& self, BasisSet::ElectronType type) -> py::array_t<uint8_t> {
        auto& occ = self.moOccupancy(type);
        if (occ.empty())
          return py::array_t<uint8_t>(0);
        return py::array_t<uint8_t>(
          { static_cast<Py_ssize_t>(occ.size()) },
          { static_cast<Py_ssize_t>(sizeof(uint8_t)) }, occ.data(),
          py::cast(self));
      },
      py::arg("type") = BasisSet::Paired, "MO occupancies as a numpy array");

  // --- ScfType enum (namespace level) ---

  py::enum_<ScfType>(m, "ScfType")
    .value("Rhf", Rhf)
    .value("Uhf", Uhf)
    .value("Rohf", Rohf)
    .value("Unknown", Unknown)
    .export_values();

  // --- GaussianSet ---

  py::class_<GaussianSet, BasisSet>(m, "GaussianSet")
    .def_property_readonly("scf_type", &GaussianSet::scfType, "The SCF type")
    .def_property_readonly("functional_name", &GaussianSet::functionalName,
                           "DFT functional name (empty if none)")
    .def(
      "mo_matrix",
      [](GaussianSet& self, BasisSet::ElectronType type) -> MatrixX {
        return self.moMatrix(type);
      },
      py::arg("type") = BasisSet::Paired,
      "MO coefficient matrix as a numpy array")
    .def_property_readonly(
      "density_matrix",
      [](GaussianSet& self) -> MatrixX { return self.densityMatrix(); },
      "SCF density matrix as a numpy array")
    .def_property_readonly(
      "spin_density_matrix",
      [](GaussianSet& self) -> MatrixX { return self.spinDensityMatrix(); },
      "Spin density matrix as a numpy array")
    .def("molecular_orbital_count", &GaussianSet::molecularOrbitalCount,
         py::arg("type") = BasisSet::Paired)
    .def("is_valid", &GaussianSet::isValid);

  // --- GaussianSetTools ---

  // Cube-filling overloads
  bool (GaussianSetTools::*calcMO_cube)(Cube&, int) const =
    &GaussianSetTools::calculateMolecularOrbital;
  bool (GaussianSetTools::*calcED_cube)(Cube&) const =
    &GaussianSetTools::calculateElectronDensity;
  bool (GaussianSetTools::*calcSD_cube)(Cube&) const =
    &GaussianSetTools::calculateSpinDensity;

  // Point-evaluation overloads
  double (GaussianSetTools::*calcMO_point)(const Vector3&, int) const =
    &GaussianSetTools::calculateMolecularOrbital;
  double (GaussianSetTools::*calcED_point)(const Vector3&) const =
    &GaussianSetTools::calculateElectronDensity;
  double (GaussianSetTools::*calcSD_point)(const Vector3&) const =
    &GaussianSetTools::calculateSpinDensity;

  py::class_<GaussianSetTools>(m, "GaussianSetTools")
    .def(py::init<Molecule*>(), py::keep_alive<1, 2>(),
         "Create tools from a molecule with a Gaussian basis set")
    .def("set_electron_type", &GaussianSetTools::setElectronType,
         py::arg("type"), "Set the electron type (Alpha, Beta, or Paired)")
    .def("is_valid", &GaussianSetTools::isValid,
         "Check if the basis set is valid for calculations")
    // Cube-filling
    .def("calculate_molecular_orbital", calcMO_cube, py::arg("cube"),
         py::arg("mo_number"),
         "Calculate a molecular orbital and fill the cube")
    .def("calculate_electron_density", calcED_cube, py::arg("cube"),
         "Calculate the electron density and fill the cube")
    .def("calculate_spin_density", calcSD_cube, py::arg("cube"),
         "Calculate the spin density and fill the cube")
    // Point evaluation
    .def("calculate_molecular_orbital", calcMO_point, py::arg("position"),
         py::arg("mo_number"), "Calculate the MO value at a 3D position")
    .def("calculate_electron_density", calcED_point, py::arg("position"),
         "Calculate the electron density at a 3D position")
    .def("calculate_spin_density", calcSD_point, py::arg("position"),
         "Calculate the spin density at a 3D position");
}
