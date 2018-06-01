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
  char endian = '>', buff[BUFSIZ], fmt[BUFSIZ], raw[84];
  char* remarks;
  double DELTA;
  int magic, charmm, NSET, ISTART, NSAVC, NAMNF, NTITLE, len_remarks, NATOMS,
    block_size;

  // Determining size of file
  inStream.seekg(0, inStream.end);
  int file_len = inStream.tellg();
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
  if (*((int*)(raw + 80)) != 0) {
    charmm = DCD_IS_CHARMM;
    if (*((int*)(raw + 44)) != 0)
      charmm |= DCD_HAS_EXTRA_BLOCK;

    if (*((int*)(raw + 48)) == 1)
      charmm |= DCD_HAS_4DIMS;
  } else {
    charmm = 0;
  }

  // number of fixed atoms
  NAMNF = *((int*)(raw + 36));

  // DELTA (timestep) is stored as a double with X-PLOR but as a float with
  // CHARMM
  if ((charmm)&DCD_IS_CHARMM) {
    float ftmp;
    ftmp = *((float*)(raw + 40));

    DELTA = (double)ftmp;
  } else {
    (DELTA) = *((double*)(raw + 40));
  }

  snprintf(fmt, sizeof(fmt), "%c1i", endian);
  inStream.read(buff, struct_calcsize(fmt));
  struct_unpack(buff, fmt, &magic);

  snprintf(fmt, sizeof(fmt), "%c1i", endian);
  inStream.read(buff, struct_calcsize(fmt));
  struct_unpack(buff, fmt, &block_size);

  if (((block_size - 4) % 80) == 0) {
    // Read NTITLE, the number of 80 character title strings
    snprintf(fmt, sizeof(fmt), "%c1i", endian);
    inStream.read(buff, struct_calcsize(fmt));
    struct_unpack(buff, fmt, &NTITLE);
    len_remarks = NTITLE * 80;
    remarks = (char*)malloc(len_remarks);
    snprintf(fmt, sizeof(fmt), "%c%ds", endian, len_remarks);
    inStream.read(buff, struct_calcsize(fmt));
    struct_unpack(buff, fmt, remarks);

    snprintf(fmt, sizeof(fmt), "%c1i", endian);
    inStream.read(buff, struct_calcsize(fmt));
    int end_size;
    struct_unpack(buff, fmt, &end_size);
  } else {
    appendError("Block size must be 4 plus a multiple of 80.");
    return false;
  }

  snprintf(fmt, sizeof(fmt), "%c1i", endian);
  inStream.read(buff, struct_calcsize(fmt));
  int four_input;
  struct_unpack(buff, fmt, &four_input);
  if (four_input != 4) {
    // Error
  }

  snprintf(fmt, sizeof(fmt), "%c1i", endian);
  inStream.read(buff, struct_calcsize(fmt));
  struct_unpack(buff, fmt, &NATOMS);

  snprintf(fmt, sizeof(fmt), "%c1i", endian);
  inStream.read(buff, struct_calcsize(fmt));
  struct_unpack(buff, fmt, &four_input);
  if (four_input != 4) {
    appendError("Expected token 4. Read token " + to_string(four_input));
    return false;
  }

  if (NAMNF != 0) {
    int** FREEINDEXES = (int**)calloc((NATOMS - NAMNF), sizeof(int));
    if (*FREEINDEXES == NULL) {
      appendError("MALLOC failed.");
      return false;
    }

    /* Read in index array size */
    snprintf(fmt, sizeof(fmt), "%c1i", endian);
    inStream.read(buff, struct_calcsize(fmt));
    int arr_size;
    struct_unpack(buff, fmt, &arr_size);

    if (arr_size != (NATOMS - NAMNF) * 4) {
      appendError("DCD file contains bad format.");
      return false;
    }

    snprintf(fmt, sizeof(fmt), "%c%di", endian, (NATOMS - NAMNF));
    inStream.read(buff, struct_calcsize(fmt));
    struct_unpack(buff, fmt, *FREEINDEXES);

    snprintf(fmt, sizeof(fmt), "%c1i", endian);
    inStream.read(buff, struct_calcsize(fmt));
    struct_unpack(buff, fmt, &arr_size);

    if (arr_size != (NATOMS - NAMNF) * 4) {
      appendError("DCD file contains bad format.");
      return false;
    }
  }

  // CHARMM trajectories have an extra block to be read, that contains
  // information about the unit cell
  if ((charmm & DCD_IS_CHARMM) && (charmm & DCD_HAS_EXTRA_BLOCK)) {
    snprintf(fmt, sizeof(fmt), "%c1i", endian);
    inStream.read(buff, struct_calcsize(fmt));
    int leading_num;
    struct_unpack(buff, fmt, &leading_num);

    if (leading_num == 48) {
      double unitcell[6];
      for (int aa = 0; aa < 6; aa++) {
        snprintf(fmt, sizeof(fmt), "%c%dd", endian, 1);
        inStream.read(buff, struct_calcsize(fmt));
        struct_unpack(buff, fmt, &unitcell[aa]);
      }
      mol.setUnitCell(new UnitCell(unitcell[0], unitcell[1], unitcell[2],
                                   acos(unitcell[3]), acos(unitcell[4]),
                                   acos(unitcell[5])));
    } else {
      inStream.read(buff, leading_num);
    }
    inStream.read(buff, sizeof(int));
  }

  // Reading the atom coordinates
  int formatint[6];
  float cx[NATOMS], cy[NATOMS], cz[NATOMS];

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

  // Skipping fourth dimension block
  if ((charmm & DCD_IS_CHARMM) && (charmm & DCD_HAS_EXTRA_BLOCK)) {
    snprintf(fmt, sizeof(fmt), "%c1i", endian);
    inStream.read(buff, struct_calcsize(fmt));
    int size_to_read;
    struct_unpack(buff, fmt, &size_to_read);

    inStream.read(buff, size_to_read);

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
  while (inStream.tellg() != file_len) {
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

    // Skipping fourth dimension block
    if ((charmm & DCD_IS_CHARMM) && (charmm & DCD_HAS_EXTRA_BLOCK)) {
      snprintf(fmt, sizeof(fmt), "%c1i", endian);
      inStream.read(buff, struct_calcsize(fmt));
      int size_to_read;
      struct_unpack(buff, fmt, &size_to_read);

      inStream.read(buff, size_to_read);

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
