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

#include "dcdformat.h"
#include "struct.h"

#include <avogadro/core/elements.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/unitcell.h>
#include <avogadro/core/utilities.h>
#include <avogadro/core/vector.h>

#include <cmath>
#include <iomanip>
#include <istream>
#include <ostream>
#include <sstream>
#include <string>

using std::endl;
using std::getline;
using std::map;
using std::pair;
using std::string;
using std::to_string;
using std::vector;

namespace Avogadro {
namespace Io {

using Core::Array;
using Core::Atom;
using Core::Elements;
using Core::lexicalCast;
using Core::Molecule;
using Core::split;
using Core::trimmed;
using Core::UnitCell;

#ifndef _WIN32
using std::isalpha;
#endif

#define DCD_EOF -1
#define DCD_MAGIC 84
#define DCD_IS_CHARMM 0x01
#define DCD_HAS_4DIMS 0x02
#define DCD_HAS_EXTRA_BLOCK 0x04

int swap_integer(int inp)
{
  return (((inp << 24) & 0xff000000) | ((inp << 8) & 0x00ff0000) |
          ((inp >> 8) & 0x0000ff00) | ((inp >> 24) & 0x000000ff));
}

char swap_endian(char endian)
{
  if (endian == '>')
    return '<';
  else
    return '>';
}

DcdFormat::DcdFormat() {}

DcdFormat::~DcdFormat() {}

bool DcdFormat::read(std::istream& inStream, Core::Molecule& mol)
{
  /** Endian type, Buffer and Format char containers for unpacking and storing
   * data using struct library */
  char endian = '>';
  char buff[BUFSIZ];
  char fmt[BUFSIZ];

  /** Variables to store various components from the binary data unpacked using
   * the struct library */
  char raw[84];
  char* remarks;
  double DELTA;
  int magic;
  int charmm;
  int NAMNF;
  int NTITLE;
  int lenRemarks;
  int NATOMS;
  int blockSize;

  // Determining size of file
  inStream.seekg(0, inStream.end);
  int fileLen = inStream.tellg();
  inStream.seekg(0, inStream.beg);

  // Reading magic number
  snprintf(fmt, sizeof(fmt), "%c1i", endian);
  inStream.read(buff, struct_calcsize(fmt));
  struct_unpack(buff, fmt, &magic);
  if (magic != DCD_MAGIC) {
    magic = swap_integer(magic);
    endian = swap_endian(endian);
    if (magic != DCD_MAGIC) {
      appendError("File does not start with magic number 84.");
      return false;
    }
  }

  // CORD
  snprintf(fmt, sizeof(fmt), "%c%ds", endian, magic);
  inStream.read(buff, struct_calcsize(fmt));
  struct_unpack(buff, fmt, raw);
  if (raw[0] != 'C' || raw[1] != 'O' || raw[2] != 'R' || raw[3] != 'D') {
    appendError("Keyword CORD not found.");
    return false;
  }

  // Determining whether the trajectory file is from CHARMM or not
  if (*(reinterpret_cast<int*>(raw + 80)) != 0) {
    charmm = DCD_IS_CHARMM;
    if (*(reinterpret_cast<int*>(raw + 44)) != 0)
      charmm |= DCD_HAS_EXTRA_BLOCK;

    if (*(reinterpret_cast<int*>(raw + 48)) == 1)
      charmm |= DCD_HAS_4DIMS;
  } else {
    charmm = 0;
  }

  // number of fixed atoms
  NAMNF = *(reinterpret_cast<int*>(raw + 36));

  // DELTA (timestep) is stored as a double with X-PLOR but as a float with
  // CHARMM
  if (charmm & DCD_IS_CHARMM) {
    float ftmp;
    ftmp = *(reinterpret_cast<float*>(raw + 40));

    DELTA = static_cast<double>(ftmp);
  } else {
    (DELTA) = *(reinterpret_cast<double*>(raw + 40));
  }

  snprintf(fmt, sizeof(fmt), "%c1i", endian);
  inStream.read(buff, struct_calcsize(fmt));
  struct_unpack(buff, fmt, &magic);

  snprintf(fmt, sizeof(fmt), "%c1i", endian);
  inStream.read(buff, struct_calcsize(fmt));
  struct_unpack(buff, fmt, &blockSize);

  if (((blockSize - 4) % 80) == 0) {
    // Read NTITLE, the number of 80 character title strings
    snprintf(fmt, sizeof(fmt), "%c1i", endian);
    inStream.read(buff, struct_calcsize(fmt));
    struct_unpack(buff, fmt, &NTITLE);
    lenRemarks = NTITLE * 80;
    remarks = reinterpret_cast<char*>(malloc(lenRemarks));
    snprintf(fmt, sizeof(fmt), "%c%ds", endian, lenRemarks);
    inStream.read(buff, struct_calcsize(fmt));
    struct_unpack(buff, fmt, remarks);

    snprintf(fmt, sizeof(fmt), "%c1i", endian);
    inStream.read(buff, struct_calcsize(fmt));
    int endSize;
    struct_unpack(buff, fmt, &endSize);
  } else {
    appendError("Block size must be 4 plus a multiple of 80.");
    return false;
  }

  snprintf(fmt, sizeof(fmt), "%c1i", endian);
  inStream.read(buff, struct_calcsize(fmt));
  int fourInput;
  struct_unpack(buff, fmt, &fourInput);
  if (fourInput != 4) {
    // Error
  }

  snprintf(fmt, sizeof(fmt), "%c1i", endian);
  inStream.read(buff, struct_calcsize(fmt));
  struct_unpack(buff, fmt, &NATOMS);

  snprintf(fmt, sizeof(fmt), "%c1i", endian);
  inStream.read(buff, struct_calcsize(fmt));
  struct_unpack(buff, fmt, &fourInput);
  if (fourInput != 4) {
    appendError("Expected token 4. Read token " + to_string(fourInput));
    return false;
  }

  if (NAMNF != 0) {
    int** FREEINDEXES =
      reinterpret_cast<int**>(calloc((NATOMS - NAMNF), sizeof(int)));
    if (*FREEINDEXES == nullptr) {
      appendError("MALLOC failed.");
      return false;
    }

    /* Read in index array size */
    snprintf(fmt, sizeof(fmt), "%c1i", endian);
    inStream.read(buff, struct_calcsize(fmt));
    int arrSize;
    struct_unpack(buff, fmt, &arrSize);

    if (arrSize != (NATOMS - NAMNF) * 4) {
      appendError("DCD file contains bad format.");
      return false;
    }

    snprintf(fmt, sizeof(fmt), "%c%di", endian, (NATOMS - NAMNF));
    inStream.read(buff, struct_calcsize(fmt));
    struct_unpack(buff, fmt, *FREEINDEXES);

    snprintf(fmt, sizeof(fmt), "%c1i", endian);
    inStream.read(buff, struct_calcsize(fmt));
    struct_unpack(buff, fmt, &arrSize);

    if (arrSize != (NATOMS - NAMNF) * 4) {
      appendError("DCD file contains bad format.");
      return false;
    }
  }

  // CHARMM trajectories have an extra block to be read, that contains
  // information about the unit cell
  if ((charmm & DCD_IS_CHARMM) && (charmm & DCD_HAS_EXTRA_BLOCK)) {
    snprintf(fmt, sizeof(fmt), "%c1i", endian);
    inStream.read(buff, struct_calcsize(fmt));
    int leadingNum;
    struct_unpack(buff, fmt, &leadingNum);

    if (leadingNum == 48) {
      double unitcell[6];
      for (int aa = 0; aa < 6; ++aa) {
        snprintf(fmt, sizeof(fmt), "%c%dd", endian, 1);
        inStream.read(buff, struct_calcsize(fmt));
        struct_unpack(buff, fmt, &unitcell[aa]);
      }
      if (unitcell[1] >= -1.0 && unitcell[1] <= 1.0 && unitcell[3] >= -1.0 &&
          unitcell[3] <= 1.0 && unitcell[4] >= -1.0 && unitcell[4] <= 1.0) {
        // CHARMM and certain NAMD files have the cosines instead of angles
        // This formulation improves rounding behavior for orthogonal cells
        // so that the angles end up at precisely 90 degrees, unlike acos()
        unitcell[4] = M_PI_2 - asin(unitcell[4]); /* cosBC */
        unitcell[3] = M_PI_2 - asin(unitcell[3]); /* cosAC */
        unitcell[1] = M_PI_2 - asin(unitcell[1]); /* cosAB */
      }

      mol.setUnitCell(new UnitCell(unitcell[0], unitcell[2], unitcell[5],
                                   unitcell[4], unitcell[3], unitcell[1]));
    } else {
      inStream.read(buff, leadingNum);
    }
    inStream.read(buff, sizeof(int));
  }

  // Reading the atom coordinates
  int formatint[6];
  Array<float> cx, cy, cz;
  cx.reserve(NATOMS);
  cy.reserve(NATOMS);
  cz.reserve(NATOMS);

  snprintf(fmt, sizeof(fmt), "%c1i", endian);
  inStream.read(buff, struct_calcsize(fmt));
  struct_unpack(buff, fmt, &formatint[0]);

  for (int i = 0; i < NATOMS; ++i) {
    // X coordinates
    snprintf(fmt, sizeof(fmt), "%c%df", endian, 1);
    inStream.read(buff, struct_calcsize(fmt));
    struct_unpack(buff, fmt, &cx[i]);
    /* code */
  }

  snprintf(fmt, sizeof(fmt), "%c2i", endian);
  inStream.read(buff, struct_calcsize(fmt));
  struct_unpack(buff, fmt, &formatint[1], &formatint[2]);

  for (int i = 0; i < NATOMS; ++i) {
    // Y coordinates
    snprintf(fmt, sizeof(fmt), "%c%df", endian, 1);
    inStream.read(buff, struct_calcsize(fmt));
    struct_unpack(buff, fmt, &cy[i]);
  }

  snprintf(fmt, sizeof(fmt), "%c2i", endian);
  inStream.read(buff, struct_calcsize(fmt));
  struct_unpack(buff, fmt, &formatint[3], &formatint[4]);

  for (int i = 0; i < NATOMS; ++i) {
    // Z coordinates
    snprintf(fmt, sizeof(fmt), "%c%df", endian, 1);
    inStream.read(buff, struct_calcsize(fmt));
    struct_unpack(buff, fmt, &cz[i]);
  }

  snprintf(fmt, sizeof(fmt), "%c1i", endian);
  inStream.read(buff, struct_calcsize(fmt));
  struct_unpack(buff, fmt, &formatint[5]);

  typedef map<string, unsigned char> AtomTypeMap;
  AtomTypeMap atomTypes;
  unsigned char customElementCounter = CustomElementMin;

  for (int i = 0; i < NATOMS; ++i) {
    Vector3 pos(cx[i], cy[i], cz[i]);

    AtomTypeMap::const_iterator it;
    atomTypes.insert(std::make_pair(to_string(i), customElementCounter++));
    it = atomTypes.find(to_string(i));
    // if (customElementCounter > CustomElementMax) {
    //   appendError("Custom element type limit exceeded.");
    //   return false;
    // }
    Atom newAtom = mol.addAtom(it->second);
    newAtom.setPosition3d(pos);
  }

  mol.setTimeStep(0, 0);

  // Skipping fourth dimension block
  if ((charmm & DCD_IS_CHARMM) && (charmm & DCD_HAS_EXTRA_BLOCK)) {
    snprintf(fmt, sizeof(fmt), "%c1i", endian);
    inStream.read(buff, struct_calcsize(fmt));
    int sizeToRead;
    struct_unpack(buff, fmt, &sizeToRead);

    inStream.read(buff, sizeToRead);

    inStream.read(buff, sizeof(int));
  }

  // Set the custom element map if needed
  if (!atomTypes.empty()) {
    Molecule::CustomElementMap elementMap;
    for (AtomTypeMap::const_iterator it = atomTypes.begin(),
                                     itEnd = atomTypes.end();
         it != itEnd; ++it) {
      elementMap.insert(std::make_pair(it->second, "Atom " + it->first));
    }
    mol.setCustomElementMap(elementMap);
  }

  mol.setCoordinate3d(mol.atomPositions3d(), 0);

  // Do we have an animation?
  int coordSet = 1;
  while ((static_cast<int>(inStream.tellg()) != fileLen) &&
         (static_cast<int>(inStream.tellg()) != DCD_EOF)) {
    // Reading the atom coordinates
    Array<Vector3> positions;
    positions.reserve(NATOMS);

    snprintf(fmt, sizeof(fmt), "%c1i", endian);
    inStream.read(buff, struct_calcsize(fmt));
    struct_unpack(buff, fmt, &formatint[0]);

    for (int i = 0; i < NATOMS; ++i) {
      // X coordinates
      snprintf(fmt, sizeof(fmt), "%c%df", endian, 1);
      inStream.read(buff, struct_calcsize(fmt));
      struct_unpack(buff, fmt, &cx[i]);
    }

    snprintf(fmt, sizeof(fmt), "%c2i", endian);
    inStream.read(buff, struct_calcsize(fmt));
    struct_unpack(buff, fmt, &formatint[1], &formatint[2]);

    for (int i = 0; i < NATOMS; ++i) {
      // Y coordinates
      snprintf(fmt, sizeof(fmt), "%c%df", endian, 1);
      inStream.read(buff, struct_calcsize(fmt));
      struct_unpack(buff, fmt, &cy[i]);
    }

    snprintf(fmt, sizeof(fmt), "%c2i", endian);
    inStream.read(buff, struct_calcsize(fmt));
    struct_unpack(buff, fmt, &formatint[3], &formatint[4]);

    for (int i = 0; i < NATOMS; ++i) {
      // Z coordinates
      snprintf(fmt, sizeof(fmt), "%c%df", endian, 1);
      inStream.read(buff, struct_calcsize(fmt));
      struct_unpack(buff, fmt, &cz[i]);
    }

    snprintf(fmt, sizeof(fmt), "%c1i", endian);
    inStream.read(buff, struct_calcsize(fmt));
    struct_unpack(buff, fmt, &formatint[5]);

    for (int i = 0; i < NATOMS; ++i) {
      Vector3 pos(cx[i], cy[i], cz[i]);
      positions.push_back(pos);
    }

    mol.setTimeStep(DELTA * coordSet, coordSet);

    // Skipping fourth dimension block
    if ((charmm & DCD_IS_CHARMM) && (charmm & DCD_HAS_EXTRA_BLOCK)) {
      snprintf(fmt, sizeof(fmt), "%c1i", endian);
      inStream.read(buff, struct_calcsize(fmt));
      int sizeToRead;
      struct_unpack(buff, fmt, &sizeToRead);

      inStream.read(buff, sizeToRead);

      inStream.read(buff, sizeof(int));
    }

    mol.setCoordinate3d(positions, coordSet++);
  }

  return true;
}

bool DcdFormat::write(std::ostream& outStream, const Core::Molecule& mol)
{
  return false;
}

std::vector<std::string> DcdFormat::fileExtensions() const
{
  std::vector<std::string> ext;
  ext.push_back("dcd");
  return ext;
}

std::vector<std::string> DcdFormat::mimeTypes() const
{
  std::vector<std::string> mime;
  mime.push_back("application/octet-stream");
  return mime;
}

} // end Io namespace
} // end Avogadro namespace
