/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/
#include "avogadro/core/molecule.h"
#include "avogadro/io/fileformatmanager.h"

#include <iostream>
#include <sstream>
#include <string>

using Avogadro::Core::Molecule;
using Avogadro::Io::FileFormatManager;
using std::cin;
using std::cout;
using std::ostringstream;
using std::string;

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
