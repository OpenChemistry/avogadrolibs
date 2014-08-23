/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2014 Albert DeFusco University of Pittsburgh

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/
#include <avogadro/io/fileformatmanager.h>

#include <avogadro/core/molecule.h>
#include <avogadro/core/unitcell.h>
#include <avogadro/core/version.h>
#include <avogadro/core/matrix.h>
#include <avogadro/core/vector.h>
#include <avogadro/core/crystaltools.h>
#include <avogadro/core/avospglib.h>

#include <iostream>
#include <sstream>
#include <string>

using Avogadro::Io::FileFormatManager;
using Avogadro::Core::UnitCell;
using Avogadro::Core::Molecule;
using Avogadro::Core::AvoSpglib;
using Avogadro::Core::CrystalTools;
using std::cin;
using std::cout;
using std::endl;
using std::string;
using std::ostringstream;

void printHelp();

int main(int argc, char *argv[])
{
  // Register our quantum file format.
  FileFormatManager &mgr = FileFormatManager::instance();

  // Process the command line arguments, see what has been requested.
  string inFormat;
  int orbitalNumber=0;
  string inFile;
  bool density = false;
  for (int i = 1; i < argc; ++i) {
    string current(argv[i]);
    if (current == "--help" || current == "-h") {
      printHelp();
      return 0;
    }
    else if (current == "--version" || current == "-v") {
      cout << "Version: " << Avogadro::version() << endl;
      return 0;
    }
    else if (inFile.empty()) {
      inFile = argv[i];
    }
  }

  // Now read/write the molecule, if possible. Otherwise output errors.
  Molecule mol;
  if (!inFile.empty()) {
    if (!mgr.readFile(mol, inFile, inFormat)) {
      cout << "Failed to read " << inFile << " (" << inFormat << ")" << endl;
      return 1;
    }
  }
  else if (!inFormat.empty()) {
    ostringstream inFileString;
    string line;
    while (getline(cin, line))
      inFileString << line;
    if (!inFileString.str().empty()) {
      if (!mgr.readString(mol, inFileString.str(), inFormat)) {
        cout << "Failed to read input stream: " << inFileString.str() << endl;
        return 1;
      }
    }
  }
  else {
    cout << "Error, no input file or stream supplied with format." << endl;
  }
  if( !mol.unitCell() ) {
    cout << "Error, this molecule does not have a unit cell." << endl;
    return 1;
  }


  CrystalTools::fillUnitCell(mol);
  if(CrystalTools::getSpacegroup(mol))
    cout << "success" << endl;

  //CrystalTools::primitiveReduce(mol);

}

void printHelp()
{
  cout << "Usage: cell [-i <input-type>] <infilename> [-v / --version] \n"
       << endl;
}
