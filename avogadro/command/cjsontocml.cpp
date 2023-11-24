/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/
#include "avogadro/core/molecule.h"
#include "avogadro/io/fileformatmanager.h"

#include <iostream>
#include <sstream>
#include <string>

using Avogadro::Io::FileFormatManager;
using Avogadro::Core::Molecule;
using std::cin;
using std::cout;
using std::string;
using std::ostringstream;

int main()
{

  FileFormatManager& mgr = FileFormatManager::instance();
  Molecule mol;

  ostringstream cjson;

  string line;
  while (getline(cin, line)) {
    cjson << line;
  }

  mgr.readString(mol, cjson.str(), "cjson");
  string cml;
  mgr.writeString(mol, cml, "cml");
  cout << cml;
}
