#include "avogadro/io/fileformatmanager.h"
#include "avogadro/core/molecule.h"

#include <iostream>
#include <sstream>
#include <string>

using namespace Avogadro::Io;
using namespace Avogadro::Core;
using namespace std;

int main() {

  FileFormatManager &mgr = FileFormatManager::instance();
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
