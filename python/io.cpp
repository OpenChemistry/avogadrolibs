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
                const std::string& fileExtension = std::string()) const
  {
    return m_ffm.readFile(molecule, fileName, fileExtension);
  }

  bool writeFile(const Core::Molecule& molecule, const std::string& fileName,
                 const std::string& fileExtension = std::string()) const
  {
    return m_ffm.writeFile(molecule, fileName, fileExtension);
  }

  bool readString(Core::Molecule& molecule, const std::string& string,
                  const std::string& fileExtension) const
  {
    return m_ffm.readString(molecule, string, fileExtension);
  }

  std::string writeString(const Molecule& mol, const std::string& ext)
  {
    std::string fileStr;
    bool ok = m_ffm.writeString(mol, fileStr, ext);
    if (!ok)
      fileStr = "Error: " + FileFormatManager::instance().error();
    return fileStr;
  }

private:
  FileFormatManager& m_ffm;
};
}

void exportIo(py::module& m)
{
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
         "Read in a molecule from the supplied file path")
    .def("writeFile", &ffm::writeFile,
         "Write the molecule to the supplied file path")
    .def("readString", &ffm::readString,
         "Read in a molecule from the supplied string")
    .def("writeString", &ffm::writeString,
         "Write a molecule to the supplied string");
}
