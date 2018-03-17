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
#include <avogadro/quantumio/gamessus.h>
#include <avogadro/quantumio/gaussianfchk.h>
#include <avogadro/quantumio/molden.h>
#include <avogadro/quantumio/mopacaux.h>

#include <avogadro/core/cube.h>
#include <avogadro/core/gaussiansettools.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/version.h>

#include <iostream>
#include <sstream>
#include <string>

using Avogadro::Io::FileFormatManager;
using Avogadro::Core::Cube;
using Avogadro::Core::Molecule;
using Avogadro::Core::GaussianSetTools;
using std::cin;
using std::cout;
using std::endl;
using std::string;
using std::ostringstream;

using Eigen::Vector3d;
using Eigen::Vector3i;
static const double BOHR_TO_ANGSTROM = 0.529177249;
static const double ANGSTROM_TO_BOHR = 1.0 / BOHR_TO_ANGSTROM;

void printHelp();

int main(int argc, char* argv[])
{
  // Register our quantum file format.
  FileFormatManager& mgr = FileFormatManager::instance();
  mgr.registerFormat(new Avogadro::QuantumIO::GAMESSUSOutput);
  mgr.registerFormat(new Avogadro::QuantumIO::GaussianFchk);
  mgr.registerFormat(new Avogadro::QuantumIO::MoldenFile);
  mgr.registerFormat(new Avogadro::QuantumIO::MopacAux);

  // Process the command line arguments, see what has been requested.
  string inFormat;
  int orbitalNumber = 0;
  string inFile;
  bool density = false;
  for (int i = 1; i < argc; ++i) {
    string current(argv[i]);
    if (current == "--help" || current == "-h") {
      printHelp();
      return 0;
    } else if (current == "--version" || current == "-v") {
      cout << "Version: " << Avogadro::version() << endl;
      return 0;
    } else if (current == "-i" && i + 1 < argc) {
      inFormat = argv[++i];
      cout << "input format " << inFormat << endl;
    } else if (current == "-orb" && i + 1 < argc) {
      orbitalNumber = atoi(argv[++i]);
      // cout << "plot orbital " << orbitalNumber << endl;
    } else if (current == "-dens" && i < argc) {
      density = true;
    } else if (inFile.empty()) {
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
  } else if (!inFormat.empty()) {
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
  } else {
    cout << "Error, no input file or stream supplied with format." << endl;
  }
  if ((orbitalNumber > 0) && density) {
    cout << "Error, choose either density or a single orbital, not both."
         << endl;
    return 1;
  }

  // cube header
  cout << "Avogadro generated cube" << endl;
  if (orbitalNumber > 0)
    cout << "Orbital " << orbitalNumber << endl;
  else
    cout << "Electron Density" << endl;

  // set box dimensions in Bohr
  Vector3d min = Vector3d(-10.0, -10.0, -10.0);
  Vector3d max = Vector3d(10.0, 10.0, 10.0);
  Vector3i points = Vector3i(61, 61, 61);

  Cube* m_qube = new Cube;
  m_qube->setLimits(min * BOHR_TO_ANGSTROM, max * BOHR_TO_ANGSTROM, points);

  min = m_qube->position(0) * ANGSTROM_TO_BOHR;
  Vector3d spacing = m_qube->spacing() * ANGSTROM_TO_BOHR;
  int nat = mol.atomCount();
  printf("%4d %11.6f %11.6f %11.6f\n", nat, min.x(), min.y(), min.z());
  printf("%4d %11.6f %11.6f %11.6f\n", points.x(), spacing.x(), 0.0, 0.0);
  printf("%4d %11.6f %11.6f %11.6f\n", points.y(), 0.0, spacing.y(), .0);
  printf("%4d %11.6f %11.6f %11.6f\n", points.z(), 0.0, 0.0, spacing.z());

  // atoms
  for (int iatom = 0; iatom < nat; iatom++) {
    printf("%4d %11.6f %11.6f %11.6f %11.6f\n", mol.atomicNumber(iatom), 0.0,
           mol.atomPosition3d(iatom).x() * ANGSTROM_TO_BOHR,
           mol.atomPosition3d(iatom).y() * ANGSTROM_TO_BOHR,
           mol.atomPosition3d(iatom).z() * ANGSTROM_TO_BOHR);
  }
  if (orbitalNumber > 0)
    cout << "1  " << orbitalNumber << endl;

  GaussianSetTools* m_tools = new GaussianSetTools(&mol);

  // print the qube values
  int linecount = 0;
  for (unsigned int i = 0; i < m_qube->data()->size(); i++) {
    if (i % points.z() == 0 && i > 0) {
      linecount = 0;
      printf("\n");
    }
    double value =
      m_tools->calculateMolecularOrbital(m_qube->position(i), orbitalNumber);
    printf("%13.5E", value);
    // line wrapping
    linecount++;
    if (linecount % 6 == 0 && i > 0)
      printf("\n");
    else
      printf(" ");
  }
  printf("\n");

  return 0;
}

void printHelp()
{
  cout << "Usage: qube [-i <input-type>] <infilename> [-dens] [-orb <orbital "
          "number>] [-v / --version] \n"
       << endl;
}
