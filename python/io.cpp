#include <pybind11/pybind11.h>

#include <avogadro/core/molecule.h>
#include <avogadro/io/fileformatmanager.h>

#include <avogadro/quantumio/gamessus.h>
#include <avogadro/quantumio/gaussiancube.h>
#include <avogadro/quantumio/gaussianfchk.h>
#include <avogadro/quantumio/molden.h>
#include <avogadro/quantumio/mopacaux.h>
#include <avogadro/quantumio/nwchemjson.h>
#include <avogadro/quantumio/nwchemlog.h>

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

  bool readFile(Core::Molecule& molecule, const std::string& fileName,
                const std::string& fileExtension = std::string(),
                const std::string& options = std::string()) const
  {
    return m_ffm.readFile(molecule, fileName, fileExtension, options);
  }

  bool writeFile(const Core::Molecule& molecule, const std::string& fileName,
                 const std::string& fileExtension = std::string(),
                 const std::string& options = std::string()) const
  {
    return m_ffm.writeFile(molecule, fileName, fileExtension, options);
  }

  bool readString(Core::Molecule& molecule, const std::string& string,
                  const std::string& fileExtension,
                  const std::string& options = std::string()) const
  {
    return m_ffm.readString(molecule, string, fileExtension, options);
  }

  std::string writeString(const Molecule& mol, const std::string& ext,
                          const std::string& options = std::string())
  {
    std::string fileStr;
    bool ok = m_ffm.writeString(mol, fileStr, ext, options);
    if (!ok)
      fileStr = "Error: " + FileFormatManager::instance().error();
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
  Io::FileFormatManager::registerFormat(new GaussianFchk);
  Io::FileFormatManager::registerFormat(new GaussianCube);
  Io::FileFormatManager::registerFormat(new MoldenFile);
  Io::FileFormatManager::registerFormat(new MopacAux);
  Io::FileFormatManager::registerFormat(new NWChemJson);
  Io::FileFormatManager::registerFormat(new NWChemLog);

  /// This class uses a singleton pattern, make it accessible through Python.
  py::class_<ffm>(m, "FileFormatManager")
    .def(py::init<>())
    .def("readFile", &ffm::readFile,
         "Read in a molecule from the supplied file path", py::arg("molecule"),
         py::arg("fileName"), py::arg("fileExtension") = std::string(),
         py::arg("options") = std::string())
    .def("writeFile", &ffm::writeFile,
         "Write the molecule to the supplied file path", py::arg("molecule"),
         py::arg("fileName"), py::arg("fileExtension") = std::string(),
         py::arg("options") = std::string())
    .def("readString", &ffm::readString,
         "Read in a molecule from the supplied string", py::arg("molecule"),
         py::arg("string"), py::arg("fileExtension"),
         py::arg("options") = std::string())
    .def("writeString", &ffm::writeString,
         "Write a molecule to the supplied string", py::arg("mol"),
         py::arg("ext"), py::arg("options") = std::string());
}
