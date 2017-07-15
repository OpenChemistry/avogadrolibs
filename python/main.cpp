#include <pybind11/pybind11.h>

namespace py = pybind11;

void exportCore(py::module &m);
void exportIo(py::module &m);

const char* hello()
{
  return "Ey up...";
}


PYBIND11_PLUGIN(avogadro2) {
  py::module m("avogadro2", "Avogadro Python binding");

  exportCore(m);
  exportIo(m);

  return m.ptr();
}
