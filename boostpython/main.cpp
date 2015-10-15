#include <Python.h>
#include <boost/python.hpp>

using namespace boost::python;

void exportCore();
void exportIo();

const char* hello()
{
  return "Ey up...";
}

BOOST_PYTHON_MODULE(avogadro2)
{
  exportCore();
  exportIo();
  def("hello", hello);
}
