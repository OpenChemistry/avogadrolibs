#ifndef AVOGADRO_PYTHON_EXPORTERS_H
#define AVOGADRO_PYTHON_EXPORTERS_H

#include <pybind11/pybind11.h>

#include <utility>

// Return value (an Atom or Bond proxy) as a Python object that keeps owner
// alive. py::keep_alive<0, 1> would be the usual tool, but pybind11 3.1 runs
// its post-call hook even when argument conversion failed, and then
// dereferences the "try next overload" sentinel as if it were the return
// value: m.atom(-1) or Bond.atom1(5) segfaults instead of raising TypeError.
// Doing it by hand only runs on a successful call.
template <typename Owner, typename T>
pybind11::object keepAlive(Owner& owner, T&& value)
{
  pybind11::object result = pybind11::cast(std::forward<T>(value));
  pybind11::object ownerObject =
    pybind11::cast(&owner, pybind11::return_value_policy::reference);
  pybind11::detail::keep_alive_impl(result, ownerObject);
  return result;
}

void exportCube(pybind11::module_& m);
void exportBasisSet(pybind11::module_& m);
void exportMolecule(pybind11::module_& m);

#endif
