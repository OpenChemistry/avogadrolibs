/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/
#include <avogadro/core/molecule.h>
#include <avogadro/core/version.h>
#include <avogadro/io/fileformatmanager.h>

#include <iostream>
#include <sstream>
#include <string>

using Avogadro::Io::FileFormatManager;
using Avogadro::Core::Molecule;
using std::cin;
using std::cout;
using std::endl;
using std::string;
using std::ostringstream;

void printHelp();

int main(int argc, char* argv[])
{
  // Process the command line arguments, see what has been requested.
  string inFormat;
  string outFormat;
  string inFile;
  string outFile;
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
    } else if (current == "-o" && i + 1 < argc) {
      outFormat = argv[++i];
      cout << "output format " << outFormat << endl;
    } else if (inFile.empty()) {
      inFile = argv[i];
    } else if (outFile.empty()) {
      outFile = argv[i];
    }
  }

  // Now read/write the molecule, if possible. Otherwise output errors.
  FileFormatManager& mgr = FileFormatManager::instance();
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

  if (!outFile.empty()) {
    if (!mgr.writeFile(mol, outFile, outFormat)) {
      cout << "Failed to write " << outFile << " (" << outFormat << ")" << endl;
      return 1;
    }
  } else {
    if (outFormat.empty())
      outFormat = "cjson";
    string out;
    mgr.writeString(mol, out, outFormat);
    cout << out << endl;
  }

  return 0;
}

void printHelp()
{
  cout << "Usage: avobabel [-i <input-type>] <infilename> [-o <output-type>] "
          "<outfilename>\n"
       << endl;
}
