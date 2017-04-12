/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2013-2014 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

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
