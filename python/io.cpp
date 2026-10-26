#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include <avogadro/core/molecule.h>
#include <avogadro/io/fileformatmanager.h>

#include <avogadro/quantumio/gamessus.h>
#include <avogadro/quantumio/gaussiancube.h>
#include <avogadro/quantumio/gaussianfchk.h>
#include <avogadro/quantumio/molden.h>
#include <avogadro/quantumio/mopacaux.h>
#include <avogadro/quantumio/nwchemjson.h>
#include <avogadro/quantumio/nwchemlog.h>
#include <avogadro/quantumio/orca.h>

#include <stdexcept>
#include <string>

namespace py = pybind11;

using namespace Avogadro;
using namespace Avogadro::Core;
using namespace Avogadro::Io;
using namespace Avogadro::QuantumIO;

namespace {
// Add a proxy class for Python that exposes the file format manager singleton.
class ffm
{
public:
  ffm() : m_ffm(FileFormatManager::instance()) {}

  // Each operation starts by clearing the manager's (thread-local) error, so
  // error() describes only the call that just failed.
  [[noreturn]] void fail(const char* what) const
  {
    std::string message = m_ffm.error();
    while (!message.empty() &&
           (message.back() == '\n' || message.back() == '\r'))
      message.pop_back();
    if (message.empty())
      message = std::string(what) + " failed";
    throw std::runtime_error(message);
  }

  bool readFile(Core::Molecule& molecule, const std::string& fileName,
                const std::string& fileExtension = std::string(),
                const std::string& options = std::string()) const
  {
    if (!m_ffm.readFile(molecule, fileName, fileExtension, options))
      fail("Reading the file");
    return true;
  }

  bool writeFile(const Core::Molecule& molecule, const std::string& fileName,
                 const std::string& fileExtension = std::string(),
                 const std::string& options = std::string()) const
  {
    if (!m_ffm.writeFile(molecule, fileName, fileExtension, options))
      fail("Writing the file");
    return true;
  }

  bool readString(Core::Molecule& molecule, const std::string& string,
                  const std::string& fileExtension,
                  const std::string& options = std::string()) const
  {
    if (!m_ffm.readString(molecule, string, fileExtension, options))
      fail("Reading the string");
    return true;
  }

  std::string writeString(const Molecule& mol, const std::string& ext,
                          const std::string& options = std::string())
  {
    std::string fileStr;
    if (!m_ffm.writeString(mol, fileStr, ext, options))
      fail("Writing the string");
    return fileStr;
  }

private:
  FileFormatManager& m_ffm;
};
} // namespace

PYBIND11_MODULE(io, m)
{
  m.doc() = "AvogadroIo Python binding";

  /// Add the quantum IO formats, we should probably move them over soon, but
  /// get things working for now...
  Io::FileFormatManager::registerFormat(new GAMESSUSOutput);
  Io::FileFormatManager::registerFormat(new GaussianFchk);
  Io::FileFormatManager::registerFormat(new GaussianCube);
  Io::FileFormatManager::registerFormat(new MoldenFile);
  Io::FileFormatManager::registerFormat(new MopacAux);
  Io::FileFormatManager::registerFormat(new NWChemJson);
  Io::FileFormatManager::registerFormat(new NWChemLog);
  Io::FileFormatManager::registerFormat(new ORCAOutput);

  /// This class uses a singleton pattern, make it accessible through Python.
  py::class_<ffm>(m, "FileFormatManager")
    .def(py::init<>())
    .def(
      "read_file", &ffm::readFile,
      "Read in a molecule from the supplied file path. Returns True, or raises "
      "RuntimeError (with the reason) on failure",
      py::arg("molecule"), py::arg("file_name"),
      py::arg("file_extension") = std::string(),
      py::arg("options") = std::string())
    .def(
      "write_file", &ffm::writeFile,
      "Write the molecule to the supplied file path. Returns True, or raises "
      "RuntimeError (with the reason) on failure",
      py::arg("molecule"), py::arg("file_name"),
      py::arg("file_extension") = std::string(),
      py::arg("options") = std::string())
    .def("read_string", &ffm::readString,
         "Read in a molecule from the supplied string. Returns True, or raises "
         "RuntimeError (with the reason) on failure",
         py::arg("molecule"), py::arg("string"), py::arg("file_extension"),
         py::arg("options") = std::string())
    .def(
      "write_string", &ffm::writeString,
      "Write a molecule to a string and return it. Raises RuntimeError (with "
      "the reason) on failure",
      py::arg("mol"), py::arg("file_extension"),
      py::arg("options") = std::string());
}
