#include <boost/python.hpp>
#include <avogadro/core/molecule.h>
#include <avogadro/io/fileformatmanager.h>

using namespace boost::python;
using namespace Avogadro;
using namespace Avogadro::Core;
using namespace Avogadro::Io;

/// No operation deleter.
void noopDeleter(void*) {}

/// Helper function to get a shared_ptr that holds our singleton.
boost::shared_ptr<FileFormatManager> pyGetFFMSingleton()
{
  return boost::shared_ptr<FileFormatManager>(&FileFormatManager::instance(),
                                              &noopDeleter);
}

std::string ffmWriteString(FileFormatManager &ffm, const Molecule &mol,
                           const std::string &ext)
{
  std::string fileStr;
  bool ok = ffm.writeString(mol, fileStr, ext);
  if (!ok)
    fileStr = "Error: " + FileFormatManager::instance().error();
  return fileStr;
}

void exportIo()
{
  /// This class uses a singleton pattern, make it accessible through Python.
  class_<FileFormatManager, boost::shared_ptr<FileFormatManager>,
         boost::noncopyable> ("FileFormatManager", no_init)
    .def("__init__", make_constructor(&pyGetFFMSingleton))
    .def("readString",
         &FileFormatManager::readString,
         "Read in a molecule from the supplied string")
    .def("writeString",
         &ffmWriteString,
         "Write a molecule to the supplied string")
  ;
}
