#include "exporters.h"

#include <pybind11/eigen.h>
#include <pybind11/numpy.h>
#include <pybind11/stl.h>

#include <avogadro/core/basisset.h>
#include <avogadro/core/cube.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/unitcell.h>

#include <cstring>
#include <utility>

namespace py = pybind11;

using namespace Avogadro;
using namespace Avogadro::Core;

// Ensure std::pair<Index,Index> has no padding for zero-copy numpy views.
static_assert(sizeof(std::pair<Index, Index>) == 2 * sizeof(Index),
              "std::pair<Index,Index> must be contiguous for numpy view");

void exportMolecule(py::module_& m)
{
  // Function pointer overloads
  Index (Molecule::*atomCount0)() const = &Molecule::atomCount;
  Index (Molecule::*atomCount1)(unsigned char) const = &Molecule::atomCount;
  Bond (Molecule::*addBond1)(Index, Index, unsigned char) = &Molecule::addBond;
  Bond (Molecule::*addBond2)(const Atom&, const Atom&, unsigned char) =
    &Molecule::addBond;
  Bond (Molecule::*bond0)(Index) const = &Molecule::bond;
  Bond (Molecule::*bond1)(const Atom&, const Atom&) const = &Molecule::bond;
  Bond (Molecule::*bond2)(Index, Index) const = &Molecule::bond;
  Cube* (Molecule::*cube0)(Index) = &Molecule::cube;
  UnitCell* (Molecule::*unitCell0)() = &Molecule::unitCell;

  py::class_<Molecule>(m, "Molecule")
    .def(py::init<>())
    // --- Per-atom/bond access ---
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
    // --- Geometry ---
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
    .def("mass", &Molecule::mass, "The mass of the molecule")

    // --- Bulk array properties (numpy, zero-copy read) ---
    .def_property(
      "positions",
      [](const Molecule& self) -> py::array_t<double> {
        const auto& pos = self.atomPositions3d();
        if (pos.empty())
          return py::array_t<double>(std::vector<Py_ssize_t>{ 0, 3 });
        return py::array_t<double>(
          std::vector<Py_ssize_t>{ static_cast<Py_ssize_t>(pos.size()), 3 },
          { static_cast<Py_ssize_t>(3 * sizeof(double)),
            static_cast<Py_ssize_t>(sizeof(double)) },
          reinterpret_cast<const double*>(pos.constData()), py::cast(self));
      },
      [](Molecule& self, py::array_t<double, py::array::c_style> arr) {
        auto buf = arr.request();
        if (buf.ndim != 2 || buf.shape[1] != 3)
          throw py::value_error("Expected shape (N, 3)");
        Core::Array<Vector3> positions(buf.shape[0]);
        std::memcpy(positions.data(), buf.ptr,
                    buf.shape[0] * 3 * sizeof(double));
        self.setAtomPositions3d(positions);
      },
      "Atomic positions as an (N, 3) numpy array")
    .def_property(
      "atomic_numbers",
      [](const Molecule& self) -> py::array_t<uint8_t> {
        const auto& nums = self.atomicNumbers();
        if (nums.empty())
          return py::array_t<uint8_t>(0);
        return py::array_t<uint8_t>(
          { static_cast<Py_ssize_t>(nums.size()) },
          { static_cast<Py_ssize_t>(sizeof(uint8_t)) },
          reinterpret_cast<const uint8_t*>(nums.constData()), py::cast(self));
      },
      [](Molecule& self, py::array_t<uint8_t, py::array::c_style> arr) {
        auto buf = arr.request();
        Core::Array<unsigned char> nums(buf.shape[0]);
        std::memcpy(nums.data(), buf.ptr, buf.shape[0]);
        self.setAtomicNumbers(nums);
      },
      "Atomic numbers as a uint8 numpy array")
    .def_property(
      "formal_charges",
      [](const Molecule& self) -> py::array_t<int8_t> {
        const auto& charges = self.formalCharges();
        if (charges.empty())
          return py::array_t<int8_t>(0);
        return py::array_t<int8_t>(
          { static_cast<Py_ssize_t>(charges.size()) },
          { static_cast<Py_ssize_t>(sizeof(int8_t)) },
          reinterpret_cast<const int8_t*>(charges.constData()), py::cast(self));
      },
      [](Molecule& self, py::array_t<int8_t, py::array::c_style> arr) {
        auto buf = arr.request();
        Core::Array<signed char> charges(buf.shape[0]);
        std::memcpy(charges.data(), buf.ptr, buf.shape[0]);
        self.setFormalCharges(charges);
      },
      "Formal charges as an int8 numpy array")
    .def_property_readonly(
      "bond_pairs",
      [](const Molecule& self) -> py::array_t<size_t> {
        const auto& pairs = self.bondPairs();
        if (pairs.empty())
          return py::array_t<size_t>(std::vector<Py_ssize_t>{ 0, 2 });
        return py::array_t<size_t>(
          std::vector<Py_ssize_t>{ static_cast<Py_ssize_t>(pairs.size()), 2 },
          { static_cast<Py_ssize_t>(2 * sizeof(size_t)),
            static_cast<Py_ssize_t>(sizeof(size_t)) },
          reinterpret_cast<const size_t*>(pairs.constData()), py::cast(self));
      },
      "Bond pairs as an (M, 2) numpy array of atom indices")
    .def_property_readonly(
      "bond_orders",
      [](const Molecule& self) -> py::array_t<uint8_t> {
        const auto& orders = self.bondOrders();
        if (orders.empty())
          return py::array_t<uint8_t>(0);
        return py::array_t<uint8_t>(
          { static_cast<Py_ssize_t>(orders.size()) },
          { static_cast<Py_ssize_t>(sizeof(uint8_t)) },
          reinterpret_cast<const uint8_t*>(orders.constData()), py::cast(self));
      },
      "Bond orders as a uint8 numpy array")

    // --- Partial charges ---
    .def("partial_charges", &Molecule::partialCharges, py::arg("type"),
         "Get partial charges by type name")
    .def("set_partial_charges", &Molecule::setPartialCharges, py::arg("type"),
         py::arg("value"), "Set partial charges by type name")
    .def(
      "partial_charge_types",
      [](const Molecule& self) {
        auto types = self.partialChargeTypes();
        return std::vector<std::string>(types.begin(), types.end());
      },
      "List of available partial charge types")

    // --- Charge and spin ---
    .def_property_readonly("total_charge", &Molecule::totalCharge,
                           "Total molecular charge")
    .def_property_readonly("total_spin_multiplicity",
                           &Molecule::totalSpinMultiplicity,
                           "Total spin multiplicity")

    // --- Bond perception ---
    .def("perceive_bonds_simple", &Molecule::perceiveBondsSimple,
         py::arg("tolerance") = 0.45, py::arg("min_distance") = 0.32,
         "Perceive bonds from distances")
    .def("perceive_bond_orders", &Molecule::perceiveBondOrders,
         "Perceive bond orders from geometry")

    // --- Basis set ---
    .def_property_readonly(
      "basis_set", [](Molecule& self) -> BasisSet* { return self.basisSet(); },
      py::return_value_policy::reference_internal,
      "The basis set, if available")

    // --- Cubes list ---
    .def_property_readonly(
      "cubes", [](Molecule& self) { return self.cubes(); },
      py::return_value_policy::reference_internal, "List of all cubes")

    // --- Force vectors ---
    .def_property_readonly(
      "force_vectors",
      [](const Molecule& self) -> py::array_t<double> {
        const auto& forces = self.forceVectors();
        if (forces.empty())
          return py::array_t<double>(std::vector<Py_ssize_t>{ 0, 3 });
        return py::array_t<double>(
          std::vector<Py_ssize_t>{ static_cast<Py_ssize_t>(forces.size()), 3 },
          { static_cast<Py_ssize_t>(3 * sizeof(double)),
            static_cast<Py_ssize_t>(sizeof(double)) },
          reinterpret_cast<const double*>(forces.constData()), py::cast(self));
      },
      "Force vectors as an (N, 3) numpy array")

    // --- Vibration data (returns by value, must copy) ---
    .def_property_readonly(
      "vibration_frequencies",
      [](const Molecule& self) -> py::array_t<double> {
        auto freq = self.vibrationFrequencies();
        if (freq.empty())
          return py::array_t<double>(0);
        py::array_t<double> result(freq.size());
        std::memcpy(result.mutable_data(), freq.constData(),
                    freq.size() * sizeof(double));
        return result;
      },
      "Vibrational frequencies as a numpy array (cm^-1)")
    .def_property_readonly(
      "vibration_ir_intensities",
      [](const Molecule& self) -> py::array_t<double> {
        auto ir = self.vibrationIRIntensities();
        if (ir.empty())
          return py::array_t<double>(0);
        py::array_t<double> result(ir.size());
        std::memcpy(result.mutable_data(), ir.constData(),
                    ir.size() * sizeof(double));
        return result;
      },
      "IR intensities as a numpy array")
    .def_property_readonly(
      "vibration_raman_intensities",
      [](const Molecule& self) -> py::array_t<double> {
        auto raman = self.vibrationRamanIntensities();
        if (raman.empty())
          return py::array_t<double>(0);
        py::array_t<double> result(raman.size());
        std::memcpy(result.mutable_data(), raman.constData(),
                    raman.size() * sizeof(double));
        return result;
      },
      "Raman intensities as a numpy array")
    .def(
      "vibration_lx",
      [](const Molecule& self, int mode) -> py::array_t<double> {
        auto lx = self.vibrationLx(mode);
        if (lx.empty())
          return py::array_t<double>(std::vector<Py_ssize_t>{ 0, 3 });
        py::array_t<double> result(
          std::vector<Py_ssize_t>{ static_cast<Py_ssize_t>(lx.size()), 3 });
        std::memcpy(result.mutable_data(),
                    reinterpret_cast<const double*>(lx.constData()),
                    lx.size() * 3 * sizeof(double));
        return result;
      },
      py::arg("mode"),
      "Displacement vectors for a vibration mode as an (N, 3) numpy array")

    // --- Spectra data ---
    .def("spectra", &Molecule::spectra, py::arg("name"),
         "Get spectra data by name")
    .def("set_spectra", &Molecule::setSpectra, py::arg("name"),
         py::arg("value"), "Set spectra data by name")
    .def(
      "spectra_types",
      [](const Molecule& self) {
        auto types = self.spectraTypes();
        return std::vector<std::string>(types.begin(), types.end());
      },
      "List of available spectra types");
}
