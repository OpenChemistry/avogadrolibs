#include "exporters.h"

#include <pybind11/eigen.h>
#include <pybind11/numpy.h>
#include <pybind11/stl.h>

#include <avogadro/core/cube.h>
#include <avogadro/core/molecule.h>

namespace py = pybind11;

using namespace Avogadro;
using namespace Avogadro::Core;

void exportCube(py::module_& m)
{
  auto cubeClass = py::class_<Cube>(m, "Cube");

  py::enum_<Cube::Type>(cubeClass, "Type")
    .value("VdW", Cube::VdW)
    .value("SolventAccessible", Cube::SolventAccessible)
    .value("SolventExcluded", Cube::SolventExcluded)
    .value("ESP", Cube::ESP)
    .value("ElectronDensity", Cube::ElectronDensity)
    .value("SpinDensity", Cube::SpinDensity)
    .value("MO", Cube::MO)
    .value("FromFile", Cube::FromFile)
    .value("none", Cube::None)
    .export_values();

  // setLimits overloads
  bool (Cube::*setLimits_mmP)(const Vector3&, const Vector3&, const Vector3i&) =
    &Cube::setLimits;
  bool (Cube::*setLimits_mmS)(const Vector3&, const Vector3&, float) =
    &Cube::setLimits;
  bool (Cube::*setLimits_mDS)(const Vector3&, const Vector3i&, float) =
    &Cube::setLimits;
  bool (Cube::*setLimits_mDV)(const Vector3&, const Vector3i&, const Vector3&) =
    &Cube::setLimits;
  bool (Cube::*setLimits_C)(const Cube&) = &Cube::setLimits;
  bool (Cube::*setLimits_MSP)(const Molecule&, float, float) = &Cube::setLimits;

  // value overloads
  float (Cube::*value_ijk)(int, int, int) const = &Cube::value;
  float (Cube::*value_pos)(const Vector3&) const = &Cube::value;

  // setValue overloads
  bool (Cube::*setValue_ijk)(unsigned int, unsigned int, unsigned int, float) =
    &Cube::setValue;
  bool (Cube::*setValue_idx)(unsigned int, float) = &Cube::setValue;

  cubeClass
    // Data as 3D numpy array (zero-copy view)
    .def_property(
      "data",
      [](Cube& self) -> py::array_t<float> {
        auto* vec = self.data();
        if (vec->empty())
          return py::array_t<float>();
        return py::array_t<float>(
          { static_cast<Py_ssize_t>(self.nx()),
            static_cast<Py_ssize_t>(self.ny()),
            static_cast<Py_ssize_t>(self.nz()) },
          { static_cast<Py_ssize_t>(self.ny() * self.nz() * sizeof(float)),
            static_cast<Py_ssize_t>(self.nz() * sizeof(float)),
            static_cast<Py_ssize_t>(sizeof(float)) },
          vec->data(), py::cast(self));
      },
      [](Cube& self, py::array_t<float, py::array::c_style> arr) {
        auto buf = arr.request();
        auto* ptr = static_cast<float*>(buf.ptr);
        self.setData(std::vector<float>(ptr, ptr + buf.size));
      },
      "Cube data as a numpy array of shape (nx, ny, nz)")
    // Spatial properties
    .def_property_readonly("min", &Cube::min, "The minimum corner of the cube")
    .def_property_readonly("max", &Cube::max, "The maximum corner of the cube")
    .def_property_readonly("spacing", &Cube::spacing, "The grid spacing")
    .def_property_readonly("dimensions", &Cube::dimensions,
                           "The grid dimensions (nx, ny, nz)")
    .def_property_readonly("nx", &Cube::nx, "Number of points in x")
    .def_property_readonly("ny", &Cube::ny, "Number of points in y")
    .def_property_readonly("nz", &Cube::nz, "Number of points in z")
    // Value range
    .def_property_readonly("min_value", &Cube::minValue,
                           "The minimum data value")
    .def_property_readonly("max_value", &Cube::maxValue,
                           "The maximum data value")
    // Name and type
    .def_property("name", &Cube::name, &Cube::setName, "The cube name")
    .def_property("cube_type", &Cube::cubeType, &Cube::setCubeType,
                  "The cube type")
    // setLimits overloads
    .def("set_limits", setLimits_mmP, py::arg("min"), py::arg("max"),
         py::arg("points"),
         "Set limits from min/max corners and number of points")
    .def("set_limits", setLimits_mmS, py::arg("min"), py::arg("max"),
         py::arg("spacing"), "Set limits from min/max corners and spacing")
    .def("set_limits", setLimits_mDS, py::arg("min"), py::arg("dim"),
         py::arg("spacing"),
         "Set limits from min corner, dimensions and spacing")
    .def("set_limits", setLimits_mDV, py::arg("min"), py::arg("dim"),
         py::arg("spacing"),
         "Set limits from min corner, dimensions and spacing vector")
    .def("set_limits", setLimits_C, py::arg("cube"),
         "Copy limits from another cube")
    .def("set_limits", setLimits_MSP, py::arg("molecule"), py::arg("spacing"),
         py::arg("padding"), "Set limits based on molecule geometry")
    // Value access
    .def("value", value_ijk, py::arg("i"), py::arg("j"), py::arg("k"),
         "Get value at grid indices (i, j, k)")
    .def("value", value_pos, py::arg("pos"),
         "Get interpolated value at a 3D position")
    .def("set_value", setValue_ijk, py::arg("i"), py::arg("j"), py::arg("k"),
         py::arg("value"), "Set value at grid indices")
    .def("set_value", setValue_idx, py::arg("index"), py::arg("value"),
         "Set value at linear index")
    .def("fill", &Cube::fill, py::arg("value"),
         "Fill the entire cube with a value")
    // Index/position conversion
    .def("closest_index", &Cube::closestIndex, py::arg("pos"),
         "Get the linear index closest to a 3D position")
    .def("index_vector", &Cube::indexVector, py::arg("pos"),
         "Get the (i, j, k) index closest to a 3D position")
    .def("position", &Cube::position, py::arg("index"),
         "Get the 3D position of a linear index");
}
