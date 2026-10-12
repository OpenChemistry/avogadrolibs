/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
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

using Avogadro::ANGSTROM_TO_BOHR_D;
using Avogadro::BOHR_TO_ANGSTROM_D;
using Avogadro::Core::Cube;
using Avogadro::Core::GaussianSetTools;
using Avogadro::Core::Molecule;
using Avogadro::Io::FileFormatManager;
using std::cin;
using std::cout;
using std::endl;
using std::ostringstream;
using std::string;

using Eigen::Vector3d;
using Eigen::Vector3i;

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
      cout << "Version: " << Avogadro::version() << '\n';
      return 0;
    } else if (current == "-i" && i + 1 < argc) {
      inFormat = argv[++i];
      cout << "input format " << inFormat << '\n';
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
      cout << "Failed to read " << inFile << " (" << inFormat << ")" << '\n';
      return 1;
    }
  } else if (!inFormat.empty()) {
    ostringstream inFileString;
    string line;
    while (getline(cin, line))
      inFileString << line;
    if (!inFileString.str().empty()) {
      if (!mgr.readString(mol, inFileString.str(), inFormat)) {
        cout << "Failed to read input stream: " << inFileString.str() << '\n';
        return 1;
      }
    }
  } else {
    cout << "Error, no input file or stream supplied with format." << '\n';
  }
  if ((orbitalNumber > 0) && density) {
    cout << "Error, choose either density or a single orbital, not both."
         << '\n';
    return 1;
  }

  // cube header
  cout << "Avogadro generated cube" << '\n';
  if (orbitalNumber > 0)
    cout << "Orbital " << orbitalNumber << '\n';
  else
    cout << "Electron Density" << '\n';

  // set box dimensions in Bohr
  Vector3d min = Vector3d(-10.0, -10.0, -10.0);
  Vector3d max = Vector3d(10.0, 10.0, 10.0);
  Vector3i points = Vector3i(61, 61, 61);

  Cube* m_qube = new Cube;
  m_qube->setLimits(min * BOHR_TO_ANGSTROM_D, max * BOHR_TO_ANGSTROM_D, points);

  min = m_qube->position(0) * ANGSTROM_TO_BOHR_D;
  Vector3d spacing = m_qube->spacing() * ANGSTROM_TO_BOHR_D;
  int nat = mol.atomCount();
  printf("%4d %11.6f %11.6f %11.6f\n", nat, min.x(), min.y(), min.z());
  printf("%4d %11.6f %11.6f %11.6f\n", points.x(), spacing.x(), 0.0, 0.0);
  printf("%4d %11.6f %11.6f %11.6f\n", points.y(), 0.0, spacing.y(), .0);
  printf("%4d %11.6f %11.6f %11.6f\n", points.z(), 0.0, 0.0, spacing.z());

  // atoms
  for (int iatom = 0; iatom < nat; iatom++) {
    printf("%4d %11.6f %11.6f %11.6f %11.6f\n", mol.atomicNumber(iatom), 0.0,
           mol.atomPosition3d(iatom).x() * ANGSTROM_TO_BOHR_D,
           mol.atomPosition3d(iatom).y() * ANGSTROM_TO_BOHR_D,
           mol.atomPosition3d(iatom).z() * ANGSTROM_TO_BOHR_D);
  }
  if (orbitalNumber > 0)
    cout << "1  " << orbitalNumber << '\n';

  auto* m_tools = new GaussianSetTools(&mol);

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
       << '\n';
}
