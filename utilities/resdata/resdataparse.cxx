/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2018 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include <avogadro/core/utilities.h>

#include <algorithm>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

using std::cout;
using std::endl;
using std::ifstream;
using std::ofstream;
using std::pair;
using std::string;
using std::vector;

int main(int argc, char* argv[])
{
  /** This script helps in creating a residue data header file from a text file.
      Reference text file:
     https://github.com/openbabel/openbabel/blob/master/data/resdata.txt
  */
  if (argc != 3) {
    cout << "Incorrrect number of arguments specified. "
         << "2 arguments expected, path to input txt, and output file name."
         << endl;
    return 1;
  }

  // Now to write our source files.
  string outputFileName = string(argv[2]) + ".h";
  ofstream output(outputFileName.c_str());
  if (!output.is_open()) {
    cout << "Failed to open file " << outputFileName << endl;
    return 1;
  }

  output
    << "#ifndef AVOGADRO_CORE_RESIDUE_DATA\n"
    << "#define AVOGADRO_CORE_RESIDUE_DATA\n\n"
    << "#include <map>\n"
    << "#include <string>\n"
    << "#include <vector>\n"
    << "namespace Avogadro {\n"
    << "namespace Core {\n\n"
    << "class ResidueData\n"
    << "{\n"
    << "private:\n"
    << "  std::string m_residueName;\n"
    << "  std::vector<std::string> m_residueAtomNames;\n"
    << "  std::vector<std::pair<std::string, std::string>> "
       "m_residueSingleBonds;\n"
    << "  std::vector<std::pair<std::string, std::string>> "
       "m_residueDoubleBonds;\n\n"
    << "public:\n"
    << "  ResidueData() {}\n"
    << "  ResidueData(std::string name, std::vector<std::string> atomNames,\n"
    << "              std::vector<std::pair<std::string, std::string>> "
       "singleBonds,\n"
    << "              std::vector<std::pair<std::string, std::string>> "
       "doubleBonds)\n"
    << "  {\n"
    << "    m_residueName = name;\n"
    << "    m_residueAtomNames = atomNames;\n"
    << "    m_residueSingleBonds = singleBonds;\n"
    << "    m_residueDoubleBonds = doubleBonds;\n"
    << "  }\n\n"
    << "  ResidueData(const ResidueData& other)\n"
    << "  {\n"
    << "    m_residueName = other.m_residueName;\n"
    << "    m_residueAtomNames = other.m_residueAtomNames;\n"
    << "    m_residueSingleBonds = other.m_residueSingleBonds;\n"
    << "    m_residueDoubleBonds = other.m_residueDoubleBonds;\n"
    << "  }\n\n"
    << "  ResidueData& operator=(ResidueData other)\n"
    << "  {\n"
    << "    using std::swap;\n"
    << "    swap(*this, other);\n"
    << "    return *this;\n"
    << "  }\n\n"
    << "  std::vector<std::pair<std::string, std::string>> "
       "residueSingleBonds()\n"
    << "  {\n"
    << "    return m_residueSingleBonds;\n"
    << "  }\n\n"
    << "  std::vector<std::pair<std::string, std::string>> "
       "residueDoubleBonds()\n"
    << "  {\n"
    << "    return m_residueDoubleBonds;\n"
    << "  }\n"
    << "};\n\n";

  ifstream file(argv[1]);
  if (!file.is_open()) {
    cout << "Failed to open file " << argv[1] << endl;
    return 1;
  }

  string buffer, currResidue = "";
  vector<string> atoms, residueClassNames;
  vector<pair<string, string>> singleBonds, doubleBonds;
  while (getline(file, buffer)) {
    vector<string> params(Avogadro::Core::split(buffer, ' '));
    if (params.size() == 0) {

    } else {
      if (params[0] == "RES") {
        if (currResidue != "") {
          output << "ResidueData " << currResidue << "Data(\"" << currResidue
                 << "\",\n"
                 << "// Atoms\n{";
          int i = 0;
          for (i = 0; i < atoms.size(); ++i) {
            output << "\"" << atoms[i] << "\"";
            if (i != atoms.size() - 1)
              output << ", ";
          }
          output << "},\n";
          output << "// Single Bonds\n{";
          for (i = 0; i < singleBonds.size(); ++i) {
            output << "{\"" << singleBonds[i].first << "\", \""
                   << singleBonds[i].second << "\"}";
            if (i != singleBonds.size() - 1)
              output << ", ";
          }
          output << "},\n";
          output << "// Double Bonds\n{";
          for (i = 0; i < doubleBonds.size(); ++i) {
            output << "{\"" << doubleBonds[i].first << "\", \""
                   << doubleBonds[i].second << "\"}";
            if (i != doubleBonds.size() - 1)
              output << ", ";
          }
          output << "});\n\n";
          residueClassNames.push_back(currResidue);
        }

        currResidue = params[1];
        atoms.clear();
        singleBonds.clear();
        doubleBonds.clear();
      } else if (params[0] == "ATOM") {
        if (params[1][0] >= '0' && params[1][0] <= '9')
          std::rotate(params[1].begin(), params[1].begin() + 1,
                      params[1].end());
        atoms.push_back(params[1]);
      } else if (params[0] == "BOND") {
        if (params[1][0] >= '0' && params[1][0] <= '9')
          std::rotate(params[1].begin(), params[1].begin() + 1,
                      params[1].end());
        if (params[2][0] >= '0' && params[2][0] <= '9')
          std::rotate(params[2].begin(), params[2].begin() + 1,
                      params[2].end());

        if (params[3] == "1") {
          singleBonds.push_back(make_pair(params[1], params[2]));
        } else if (params[3] == "2") {
          doubleBonds.push_back(make_pair(params[1], params[2]));
        }
      }
    }
  }

  output << "std::map<std::string, ResidueData> residueDict = {\n";
  for (int j = 0; j < residueClassNames.size(); ++j) {
    output << "{\"" << residueClassNames[j] << "\", " << residueClassNames[j]
           << "Data}";
    if (j != residueClassNames.size() - 1)
      output << ", ";
  }
  output << "};\n\n}\n}\n\n#endif";

  file.close();

  output.close();

  return 0;
}
