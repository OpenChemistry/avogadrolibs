#include "exporters.h"

#include <pybind11/eigen.h>
#include <pybind11/numpy.h>
#include <pybind11/stl.h>

#include <avogadro/core/basisset.h>
#include <avogadro/core/cube.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/unitcell.h>

#include <algorithm>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

namespace py = pybind11;

using namespace Avogadro;
using namespace Avogadro::Core;

namespace {

// The Atom/Bond proxies hold a raw pointer to their molecule; refuse proxies
// from another molecule rather than index this one with a foreign index.
void requireOwnedAtom(const Molecule& self, const Atom& atom)
{
  if (!atom.isValid() || atom.molecule() != &self)
    throw py::value_error("Atom does not belong to this molecule");
}

// The setters need one entry per atom; say what was expected.
std::string lengthMessage(const char* name, size_t expected, size_t got)
{
  return std::string(name) + " must have one entry per atom (expected " +
         std::to_string(expected) + ", got " + std::to_string(got) + ")";
}

// Copy count rows of width elements of type T into a new (count, width)
// numpy array, or a flat (count,) one when width is 0. The result owns its
// data: a view into Core::Array would dangle as soon as the molecule
// reallocates, and Core::Array is copy-on-write, so writes through a view of
// its const buffer could change other molecules sharing it.
template <typename T>
py::array_t<T> copyToArray(const void* source, size_t count, size_t width = 0)
{
  std::vector<Py_ssize_t> shape{ static_cast<Py_ssize_t>(count) };
  if (width > 0)
    shape.push_back(static_cast<Py_ssize_t>(width));
  py::array_t<T> result(shape);
  if (count > 0)
    std::memcpy(result.mutable_data(), source,
                count * std::max<size_t>(width, 1) * sizeof(T));
  return result;
}

} // namespace

// The bulk getters memcpy these types into plain numpy arrays.
static_assert(sizeof(std::pair<Index, Index>) == 2 * sizeof(Index),
              "std::pair<Index,Index> must be contiguous to copy into numpy");
static_assert(sizeof(Vector3) == 3 * sizeof(double),
              "Vector3 must be contiguous to copy into numpy");

void exportMolecule(py::module_& m)
{
  // Function pointer overloads
  Index (Molecule::*atomCount0)() const = &Molecule::atomCount;
  Index (Molecule::*atomCount1)(unsigned char) const = &Molecule::atomCount;
  Cube* (Molecule::*cube0)(Index) = &Molecule::cube;
  UnitCell* (Molecule::*unitCell0)() = &Molecule::unitCell;

  py::class_<Molecule>(m, "Molecule")
    .def(py::init<>())
    // --- Per-atom/bond access ---
    // Atom and Bond are proxies holding a raw Molecule pointer, so every one
    // returned must keep the molecule alive (see keepAlive).
    .def(
      "add_atom",
      [](Molecule& self, unsigned char atomicNumber) {
        return keepAlive(self, self.addAtom(atomicNumber));
      },
      "Add an atom")
    .def("atom_count", atomCount0, "The number of atoms")
    .def("atom_count", atomCount1,
         "The number of atoms with the supplied atomic number")
    .def(
      "atom",
      [](Molecule& self, Index index) {
        if (index >= self.atomCount())
          throw py::index_error("atom index out of range");
        return keepAlive(self, self.atom(index));
      },
      "The atom at the specified index")
    .def(
      "add_bond",
      [](Molecule& self, Index a1, Index a2, unsigned char order) {
        return keepAlive(self, self.addBond(a1, a2, order));
      },
      "Add a new bond", py::arg("a1"), py::arg("a2"), py::arg("order") = 1)
    .def(
      "add_bond",
      [](Molecule& self, const Atom& a1, const Atom& a2, unsigned char order) {
        requireOwnedAtom(self, a1);
        requireOwnedAtom(self, a2);
        return keepAlive(self, self.addBond(a1, a2, order));
      },
      "Add a new bond", py::arg("a1"), py::arg("a2"), py::arg("order") = 1)
    .def("bond_count", &Molecule::bondCount, "The number of bonds")
    .def(
      "bond",
      [](Molecule& self, Index index) {
        if (index >= self.bondCount())
          throw py::index_error("bond index out of range");
        return keepAlive(self, self.bond(index));
      },
      "The bond at the specified index")
    .def(
      "bond",
      [](Molecule& self, const Atom& a, const Atom& b) {
        requireOwnedAtom(self, a);
        requireOwnedAtom(self, b);
        return keepAlive(self, self.bond(a, b));
      },
      "The bond between the specified atoms (invalid if there is none)")
    .def(
      "bond",
      [](Molecule& self, Index a, Index b) {
        return keepAlive(self, self.bond(a, b));
      },
      "The bond between the atoms at the specified indices (invalid if "
      "there is none)")
    .def("add_cube", &Molecule::addCube,
         py::return_value_policy::reference_internal, "Add a new cube")
    .def("cube_count", &Molecule::cubeCount, "The number of cubes")
    .def("cube", cube0, py::return_value_policy::reference_internal,
         "The cube at the specified index")
    // --- Geometry ---
    .def_property_readonly("radius", &Molecule::radius,
                           "The radius of the molecule")
    .def_property_readonly("center", &Molecule::centerOfGeometry,
                           "The center of geometry of the molecule")
    .def_property_readonly("mass_center", &Molecule::centerOfMass,
                           "The center of mass of the molecule")
    .def_property_readonly("unit_cell", unitCell0,
                           py::return_value_policy::reference_internal,
                           "The unit cell of the molecule, if defined")
    .def("has_custom_elements", &Molecule::hasCustomElements,
         "Returns true if the molecule contains any custom elements")
    .def("formula", &Molecule::formula, "The chemical formula of the molecule",
         py::arg("delimiter") = "", py::arg("show_counts_over") = 1)
    .def("mass", &Molecule::mass, "The mass of the molecule")

    // --- Bulk array properties (numpy; getters return copies) ---
    .def_property(
      "positions",
      [](const Molecule& self) -> py::array_t<double> {
        const auto& pos = self.atomPositions3d();
        return copyToArray<double>(pos.constData(), pos.size(), 3);
      },
      [](Molecule& self, py::array_t<double, py::array::c_style> arr) {
        auto buf = arr.request();
        if (buf.ndim != 2 || buf.shape[1] != 3)
          throw py::value_error("Expected shape (N, 3)");
        Core::Array<Vector3> positions(buf.shape[0]);
        if (buf.shape[0] > 0)
          std::memcpy(positions.data(), buf.ptr,
                      buf.shape[0] * 3 * sizeof(double));
        if (!self.setAtomPositions3d(positions))
          throw py::value_error(
            lengthMessage("positions", self.atomCount(), positions.size()));
      },
      "Atomic positions as an (N, 3) numpy array (a copy; assign to the "
      "property to change them)")
    .def_property(
      "atomic_numbers",
      [](const Molecule& self) -> py::array_t<uint8_t> {
        const auto& nums = self.atomicNumbers();
        return copyToArray<uint8_t>(nums.constData(), nums.size());
      },
      [](Molecule& self, py::array_t<uint8_t, py::array::c_style> arr) {
        auto buf = arr.request();
        if (buf.ndim != 1)
          throw py::value_error("Expected a 1-D array of atomic numbers");
        Core::Array<unsigned char> nums(buf.shape[0]);
        if (buf.shape[0] > 0)
          std::memcpy(nums.data(), buf.ptr, buf.shape[0]);
        if (!self.setAtomicNumbers(nums))
          throw py::value_error(
            lengthMessage("atomic_numbers", self.atomCount(), nums.size()));
      },
      "Atomic numbers as a uint8 numpy array (a copy; assign to the property "
      "to change them)")
    .def_property(
      "formal_charges",
      [](const Molecule& self) -> py::array_t<int8_t> {
        const auto& charges = self.formalCharges();
        return copyToArray<int8_t>(charges.constData(), charges.size());
      },
      [](Molecule& self, py::array_t<int8_t, py::array::c_style> arr) {
        auto buf = arr.request();
        if (buf.ndim != 1)
          throw py::value_error("Expected a 1-D array of formal charges");
        Core::Array<signed char> charges(buf.shape[0]);
        if (buf.shape[0] > 0)
          std::memcpy(charges.data(), buf.ptr, buf.shape[0]);
        if (!self.setFormalCharges(charges))
          throw py::value_error(
            lengthMessage("formal_charges", self.atomCount(), charges.size()));
      },
      "Formal charges as an int8 numpy array (a copy; assign to the property "
      "to change them)")
    .def_property_readonly(
      "bond_pairs",
      [](const Molecule& self) -> py::array_t<size_t> {
        const auto& pairs = self.bondPairs();
        return copyToArray<size_t>(pairs.constData(), pairs.size(), 2);
      },
      "Bond pairs as an (M, 2) numpy array of atom indices (a copy)")
    .def_property_readonly(
      "bond_orders",
      [](const Molecule& self) -> py::array_t<uint8_t> {
        const auto& orders = self.bondOrders();
        return copyToArray<uint8_t>(orders.constData(), orders.size());
      },
      "Bond orders as a uint8 numpy array (a copy)")

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
    .def("perceive_bond_orders",
         static_cast<void (Molecule::*)()>(&Molecule::perceiveBondOrders),
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
        return copyToArray<double>(forces.constData(), forces.size(), 3);
      },
      "Force vectors as an (N, 3) numpy array (a copy)")

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
