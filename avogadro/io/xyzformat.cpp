/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2013 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "xyzformat.h"

#include <avogadro/core/elements.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/vector.h>

#include <iomanip>
#include <istream>
#include <ostream>
#include <string>
#include <sstream>

using Avogadro::Core::Atom;
using Avogadro::Core::Elements;
using Avogadro::Core::Molecule;

namespace Avogadro {
namespace Io {

#ifndef _WIN32
using std::isalpha;
#endif

XyzFormat::XyzFormat()
{
  setSupportedOperations(ReadWrite | File | Stream | String);
}

XyzFormat::~XyzFormat()
{
}

bool XyzFormat::read(std::istream &inStream, Core::Molecule &mol)
{
  size_t numAtoms = 0;
  if (!(inStream >> numAtoms)) {
    appendError("Error parsing number of atoms.");
    return false;
  }

  // Throw away the title
  std::string buffer;
  std::getline(inStream, buffer); // Finish the first line
  std::getline(inStream, buffer); // Discard the example

  // Parse atoms
  unsigned char atomicNum;
  Vector3 pos;
  for (size_t i = 0; i < numAtoms; ++i) {
    if (inStream >> buffer &&
        inStream >> pos.x() &&
        inStream >> pos.y() &&
        inStream >> pos.z()) {
      if (!buffer.empty()) {
        if (isalpha(buffer[0])) {
          atomicNum = Elements::atomicNumberFromSymbol(buffer);
        }
        else {
          short int atomicNumInt = 0;
          std::istringstream(buffer) >> atomicNumInt;
          atomicNum = static_cast<unsigned char>(atomicNumInt);
        }
        Atom newAtom = mol.addAtom(atomicNum);
        newAtom.setPosition3d(pos);
        continue;
      }
    }
    break;
  }

  // Check that all atoms were handled.
  if (mol.atomCount() != numAtoms) {
    std::ostringstream errorStream;
    errorStream << "Error parsing atom at index " << mol.atomCount()
                << " (line " << 3 + mol.atomCount() << ").";
    appendError(errorStream.str());
    return false;
  }

  return true;
}

bool XyzFormat::write(std::ostream &outStream, const Core::Molecule &mol)
{
  size_t numAtoms = mol.atomCount();

  outStream << numAtoms << std::endl
            << "XYZ file generated by Avogadro." << std::endl;

  for (size_t i = 0; i < numAtoms; ++i) {
    Atom atom = mol.atom(i);
    if (!atom.isValid()) {
      appendError("Internal error: Atom invalid.");
      return false;
    }

    outStream << std::setw(3) << std::left
              << Elements::symbol(atom.atomicNumber()) << " "
              << std::setw(10) << std::right << std::fixed
              << std::setprecision(5)
              << atom.position3d().x() << " "
              << std::setw(10) << std::right << std::fixed
              << std::setprecision(5)
              << atom.position3d().y() << " "
              << std::setw(10) << std::right << std::fixed
              << std::setprecision(5)
              << atom.position3d().z() << "\n";
  }

  return true;
}

std::vector<std::string> XyzFormat::fileExtensions() const
{
  std::vector<std::string> ext;
  ext.push_back("xyz");
  return ext;
}

std::vector<std::string> XyzFormat::mimeTypes() const
{
  std::vector<std::string> mime;
  mime.push_back("chemical/x-xyz");
  return mime;
}

} // end Io namespace
} // end Avogadro namespace
