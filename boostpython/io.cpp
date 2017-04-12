#include <avogadro/core/molecule.h>
#include <avogadro/io/fileformatmanager.h>
#include <boost/python.hpp>

#include <avogadro/quantumio/gamessus.h>
#include <avogadro/quantumio/gaussiancube.h>
#include <avogadro/quantumio/gaussianfchk.h>
#include <avogadro/quantumio/molden.h>
#include <avogadro/quantumio/mopacaux.h>
#include <avogadro/quantumio/nwchemjson.h>
#include <avogadro/quantumio/nwchemlog.h>

using namespace boost::python;
using namespace Avogadro;
using namespace Avogadro::Core;
using namespace Avogadro::Io;
using namespace Avogadro::QuantumIO;

/// No operation deleter.
void noopDeleter(void*)
{
}

/// Helper function to get a shared_ptr that holds our singleton.
boost::shared_ptr<FileFormatManager> pyGetFFMSingleton()
{
  return boost::shared_ptr<FileFormatManager>(&FileFormatManager::instance(),
                                              &noopDeleter);
}

std::string ffmWriteString(FileFormatManager& ffm, const Molecule& mol,
                           const std::string& ext)
{
  std::string fileStr;
  bool ok = ffm.writeString(mol, fileStr, ext);
  if (!ok)
    fileStr = "Error: " + FileFormatManager::instance().error();
  return fileStr;
}

void exportIo()
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
  class_<FileFormatManager, boost::shared_ptr<FileFormatManager>,
         boost::noncopyable>("FileFormatManager", no_init)
    .def("__init__", make_constructor(&pyGetFFMSingleton))
    .def("readFile", &FileFormatManager::readFile,
         "Read in a molecule from the supplied file path")
    .def("writeFile", &FileFormatManager::writeFile,
         "Write the molecule to the supplied file path")
    .def("readString", &FileFormatManager::readString,
         "Read in a molecule from the supplied string")
    .def("writeString", &ffmWriteString,
         "Write a molecule to the supplied string");
}
