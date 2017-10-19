#include "pdbformat.h"

#include <avogadro/core/elements.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/utilities.h>
#include <avogadro/core/vector.h>

#include <istream>
#include <string>

using Avogadro::Core::Atom;
using Avogadro::Core::Bond;
using Avogadro::Core::Elements;
using Avogadro::Core::Molecule;
using Avogadro::Core::lexicalCast;
using Avogadro::Core::startsWith;
using Avogadro::Core::trimmed;

using std::string;
using std::istringstream;
using std::getline;
using std::vector;

namespace Avogadro {
namespace Io {

PdbFormat::PdbFormat()
{
}

PdbFormat::~PdbFormat()
{
}

bool PdbFormat::read(std::istream& in, Core::Molecule& mol)
{
  string buffer;
  int atomCount = 0;
  std::vector<int> terList;

  while (getline(in, buffer)) { // Read Each line one by one

    if (startsWith(buffer, "ENDMDL"))
    break;

    else if (startsWith(buffer, "ATOM") || startsWith(buffer, "HETATM")) {
      Vector3 pos; // Coordinates
      bool ok(false);
      pos.x() = lexicalCast<Real>(buffer.substr(30, 8), ok);
      if (!ok) {
        appendError("Failed to parse x coordinate: " + buffer.substr(30, 8));
        return false;
      }

      pos.y() = lexicalCast<Real>(buffer.substr(38, 8), ok);
      if (!ok) {
        appendError("Failed to parse y coordinate: " + buffer.substr(38, 8));
        return false;
      }

      pos.z() = lexicalCast<Real>(buffer.substr(46, 8), ok);
      if (!ok) {
        appendError("Failed to parse z coordinate: " + buffer.substr(46, 8));
        return false;
      }

      string element; // Element symbol, right justififed
      element = buffer.substr(76, 2);
      element = trimmed(element);
      if(element == "SE")  //For Sulphur
        element = 'S';

      unsigned char atomicNum = Elements::atomicNumberFromSymbol(element);
      if(atomicNum == 255)
      appendError("Invalid element");

      Atom newAtom = mol.addAtom(atomicNum);
      newAtom.setPosition3d(pos);

      atomCount++;
    }

    else if(startsWith(buffer, "TER"))
    { //  This is very important, each TER record also counts in the serial.
      // Need to account for that when comparing with CONECT
      bool ok(false);
      terList.push_back(lexicalCast<int>(buffer.substr(6, 5), ok));

      if(!ok)
      {
        appendError ("Failed to parse TER serial");
        return false;
      }
    }

    else if(startsWith(buffer, "CONECT"))
    {
      bool ok(false);
      int a = lexicalCast<int>(buffer.substr(6, 5), ok);
      if (!ok)
      {
        appendError ("Failed to parse coordinate a " + buffer.substr(6, 5));
        return false;
      }
      --a;
      int terCount;
      for (terCount = 0; terCount < terList.size() && a > terList[terCount]; ++terCount); // semicolon is intentional
        a = a - terCount;

      int b1 = lexicalCast<int>(buffer.substr(11, 5), ok);
      if (!ok)
      {
        appendError ("Failed to parse coordinate b1 " + buffer.substr(11, 5));
        return false;
      }
      --b1;
      for (terCount = 0; terCount < terList.size() && b1 > terList[terCount]; ++terCount);  // semicolon is intentional
      b1 = b1 - terCount;

      if(a < b1){
        mol.Avogadro::Core::Molecule::addBond(a, b1, 1);
      }

      if(trimmed(buffer.substr(16, 5)) != "") // Futher bonds may be absent
      {
        int b2 = lexicalCast<int>(buffer.substr(16, 5), ok);
        if(!ok)
        {
          appendError ("Failed to parse coordinate b2" + buffer.substr(16, 5));
          return false;
        }
        --b2;
        for (terCount = 0; terCount < terList.size() && b2 > terList[terCount]; ++terCount);  // semicolon is intentional
        b2 = b2 - terCount;

        if(a < b2){
          mol.Avogadro::Core::Molecule::addBond(a, b2, 1);
        }
      }

      if(trimmed(buffer.substr(21, 5)) != "") // Futher bonds may be absent
      {
        int b3 = lexicalCast<int>(buffer.substr(21, 5), ok);
        if(!ok)
        {
          appendError ("Failed to parse coordinate b3" + buffer.substr(21, 5));
          return false;
        }
        --b3;
        for (terCount = 0; terCount < terList.size() && b3 > terList[terCount]; ++terCount);  // semicolon is intentional
        b3 = b3 - terCount;

        if(a < b3){
          mol.Avogadro::Core::Molecule::addBond(a, b3, 1);
        }
      }

      if(trimmed(buffer.substr(26, 5)) != "") // Futher bonds may be absent
      {
        int b4 = lexicalCast<int>(buffer.substr(26, 5), ok);
        if(!ok)
        {
          appendError ("Failed to parse coordinate b4" + buffer.substr(26, 5));
          return false;
        }
        --b4;
        for (terCount = 0; terCount < terList.size() && b4 > terList[terCount]; ++terCount);  // semicolon is intentional
        b4 = b4 - terCount;

        if(a < b4){
          mol.Avogadro::Core::Molecule::addBond(a, b4, 1);
        }
      }
    }
  } // End while loop
  return true;
} // End read

std::vector<std::string> PdbFormat::fileExtensions() const
{
  std::vector<std::string> ext;
  ext.push_back("pdb");
  return ext;
}

std::vector<std::string> PdbFormat::mimeTypes() const
{
  std::vector<std::string> mime;
  mime.push_back("chemical/x-pdb");
  return mime;
}

} // end Io namespace
} // end Avogadro namespace