/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "dcdformat.h"
#include "binaryblock_p.h"
#include "struct.h"

#include <avogadro/core/elements.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/unitcell.h>
#include <avogadro/core/utilities.h>
#include <avogadro/core/vector.h>

#include <algorithm>
#include <cmath>
#include <istream>
#include <ostream>
#include <string>
#include <vector>

using std::map;
using std::string;
using std::to_string;
using std::vector;

namespace Avogadro::Io {

using Core::Array;
using Core::Atom;
using Core::Molecule;
using Core::UnitCell;

#ifndef _WIN32
#endif

#define DCD_EOF (-1)
constexpr int DCD_MAGIC = 84;
constexpr int DCD_IS_CHARMM = 0x01;
constexpr int DCD_HAS_4DIMS = 0x02;
constexpr int DCD_HAS_EXTRA_BLOCK = 0x04;

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

bool DcdFormat::read(std::istream& inStream, Core::Molecule& mol)
{
  /** Endian type, Buffer and Format char containers for unpacking and storing
   * data using struct library */
  char endian = '>';
  std::vector<char> buff(BUFSIZ);
  char fmt[BUFSIZ];

  /** Variables to store various components from the binary data unpacked using
   * the struct library */
  char raw[84] = {};
  double DELTA = 0.0;
  int magic = 0;
  int charmm = 0;
  int NAMNF = 0;
  int NTITLE = 0;
  int lenRemarks = 0;
  int NATOMS = 0;
  int blockSize = 0;

  // Determining size of file
  inStream.seekg(0, inStream.end);
  int fileLen = inStream.tellg();
  inStream.seekg(0, inStream.beg);

  // Reading magic number
  snprintf(fmt, sizeof(fmt), "%c1i", endian);
  if (!readBlock(inStream, buff, struct_calcsize(fmt), fileLen)) {
    appendError("Unexpected end of DCD file.");
    return false;
  }
  struct_unpack(buff.data(), fmt, &magic);
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
  if (!readBlock(inStream, buff, struct_calcsize(fmt), fileLen)) {
    appendError("Unexpected end of DCD file.");
    return false;
  }
  struct_unpack(buff.data(), fmt, raw);
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
  if (!readBlock(inStream, buff, struct_calcsize(fmt), fileLen)) {
    appendError("Unexpected end of DCD file.");
    return false;
  }
  struct_unpack(buff.data(), fmt, &magic);

  snprintf(fmt, sizeof(fmt), "%c1i", endian);
  if (!readBlock(inStream, buff, struct_calcsize(fmt), fileLen)) {
    appendError("Unexpected end of DCD file.");
    return false;
  }
  struct_unpack(buff.data(), fmt, &blockSize);

  if (((blockSize - 4) % 80) == 0) {
    // Read NTITLE, the number of 80 character title strings
    snprintf(fmt, sizeof(fmt), "%c1i", endian);
    if (!readBlock(inStream, buff, struct_calcsize(fmt), fileLen)) {
      appendError("Unexpected end of DCD file.");
      return false;
    }
    struct_unpack(buff.data(), fmt, &NTITLE);
    // NTITLE comes from the file, so check the product rather than trusting
    // it: 80 * NTITLE overflows int for NTITLE > ~26.8M, and the result was
    // handed straight to malloc.
    if (NTITLE < 0 || NTITLE > fileLen / 80) {
      appendError("DCD file declares an implausible title count.");
      return false;
    }
    lenRemarks = NTITLE * 80;
    std::vector<char> remarks(static_cast<size_t>(lenRemarks));
    snprintf(fmt, sizeof(fmt), "%c%ds", endian, lenRemarks);
    if (!readBlock(inStream, buff, struct_calcsize(fmt), fileLen)) {
      appendError("Unexpected end of DCD file.");
      return false;
    }
    struct_unpack(buff.data(), fmt, remarks.data());

    snprintf(fmt, sizeof(fmt), "%c1i", endian);
    if (!readBlock(inStream, buff, struct_calcsize(fmt), fileLen)) {
      appendError("Unexpected end of DCD file.");
      return false;
    }
    int endSize;
    struct_unpack(buff.data(), fmt, &endSize);
  } else {
    appendError("Block size must be 4 plus a multiple of 80.");
    return false;
  }

  snprintf(fmt, sizeof(fmt), "%c1i", endian);
  if (!readBlock(inStream, buff, struct_calcsize(fmt), fileLen)) {
    appendError("Unexpected end of DCD file.");
    return false;
  }
  int fourInput;
  struct_unpack(buff.data(), fmt, &fourInput);
  if (fourInput != 4) {
    // Error
  }

  snprintf(fmt, sizeof(fmt), "%c1i", endian);
  if (!readBlock(inStream, buff, struct_calcsize(fmt), fileLen)) {
    appendError("Unexpected end of DCD file.");
    return false;
  }
  struct_unpack(buff.data(), fmt, &NATOMS);

  snprintf(fmt, sizeof(fmt), "%c1i", endian);
  if (!readBlock(inStream, buff, struct_calcsize(fmt), fileLen)) {
    appendError("Unexpected end of DCD file.");
    return false;
  }
  struct_unpack(buff.data(), fmt, &fourInput);
  if (fourInput != 4) {
    appendError("Expected token 4. Read token " + to_string(fourInput));
    return false;
  }

  if (NAMNF != 0) {
    // This was calloc((NATOMS - NAMNF), sizeof(int)) cast to int**, with the
    // null check written as *FREEINDEXES rather than FREEINDEXES -- so on the
    // zeroed block it read back as a null pointer and this branch always
    // failed, meaning a DCD with fixed atoms never loaded at all.
    if (NAMNF < 0 || NAMNF > NATOMS) {
      appendError("DCD file declares an implausible fixed atom count.");
      return false;
    }
    std::vector<int> freeIndexes(static_cast<size_t>(NATOMS - NAMNF));

    /* Read in index array size */
    snprintf(fmt, sizeof(fmt), "%c1i", endian);
    if (!readBlock(inStream, buff, struct_calcsize(fmt), fileLen)) {
      appendError("Unexpected end of DCD file.");
      return false;
    }
    int arrSize = 0;
    struct_unpack(buff.data(), fmt, &arrSize);

    if (arrSize != (NATOMS - NAMNF) * 4) {
      appendError("DCD file contains bad format.");
      return false;
    }

    snprintf(fmt, sizeof(fmt), "%c%di", endian, (NATOMS - NAMNF));
    if (!readBlock(inStream, buff, struct_calcsize(fmt), fileLen)) {
      appendError("Unexpected end of DCD file.");
      return false;
    }
    struct_unpack(buff.data(), fmt, freeIndexes.data());

    snprintf(fmt, sizeof(fmt), "%c1i", endian);
    if (!readBlock(inStream, buff, struct_calcsize(fmt), fileLen)) {
      appendError("Unexpected end of DCD file.");
      return false;
    }
    struct_unpack(buff.data(), fmt, &arrSize);

    if (arrSize != (NATOMS - NAMNF) * 4) {
      appendError("DCD file contains bad format.");
      return false;
    }
  }

  // CHARMM trajectories have an extra block to be read, that contains
  // information about the unit cell
  if ((charmm & DCD_IS_CHARMM) && (charmm & DCD_HAS_EXTRA_BLOCK)) {
    snprintf(fmt, sizeof(fmt), "%c1i", endian);
    if (!readBlock(inStream, buff, struct_calcsize(fmt), fileLen)) {
      appendError("Unexpected end of DCD file.");
      return false;
    }
    int leadingNum;
    struct_unpack(buff.data(), fmt, &leadingNum);

    if (leadingNum == 48) {
      double unitcell[6];
      for (double& aa : unitcell) {
        snprintf(fmt, sizeof(fmt), "%c%dd", endian, 1);
        if (!readBlock(inStream, buff, struct_calcsize(fmt), fileLen)) {
          appendError("Unexpected end of DCD file.");
          return false;
        }
        struct_unpack(buff.data(), fmt, &aa);
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

      auto* cell = new UnitCell(unitcell[0], unitcell[2], unitcell[5],
                                unitcell[4], unitcell[3], unitcell[1]);
      if (!cell->isRegular()) {
        appendError("cell matrix is singular");
        delete cell;
        return false;
      }
      mol.setUnitCell(cell);
    } else {
      if (!readBlock(inStream, buff, leadingNum, fileLen)) {
        appendError("Unexpected end of DCD file.");
        return false;
      }
    }
    if (!readBlock(inStream, buff, sizeof(int), fileLen)) {
      appendError("Unexpected end of DCD file.");
      return false;
    }
  }

  // NATOMS is file-derived and sizes three arrays below. Each atom needs at
  // least a float per axis, so a count larger than the file cannot be real.
  if (NATOMS < 0 || NATOMS > fileLen) {
    appendError("DCD file declares an implausible atom count.");
    return false;
  }

  // Reading the atom coordinates
  int formatint[6] = {};
  Array<float> cx, cy, cz;
  cx.resize(NATOMS);
  cy.resize(NATOMS);
  cz.resize(NATOMS);

  snprintf(fmt, sizeof(fmt), "%c1i", endian);
  if (!readBlock(inStream, buff, struct_calcsize(fmt), fileLen)) {
    appendError("Unexpected end of DCD file.");
    return false;
  }
  struct_unpack(buff.data(), fmt, &formatint[0]);

  for (int i = 0; i < NATOMS; ++i) {
    // X coordinates
    snprintf(fmt, sizeof(fmt), "%c%df", endian, 1);
    if (!readBlock(inStream, buff, struct_calcsize(fmt), fileLen)) {
      appendError("Unexpected end of DCD file.");
      return false;
    }
    struct_unpack(buff.data(), fmt, &cx[i]);
    /* code */
  }

  snprintf(fmt, sizeof(fmt), "%c2i", endian);
  if (!readBlock(inStream, buff, struct_calcsize(fmt), fileLen)) {
    appendError("Unexpected end of DCD file.");
    return false;
  }
  struct_unpack(buff.data(), fmt, &formatint[1], &formatint[2]);

  for (int i = 0; i < NATOMS; ++i) {
    // Y coordinates
    snprintf(fmt, sizeof(fmt), "%c%df", endian, 1);
    if (!readBlock(inStream, buff, struct_calcsize(fmt), fileLen)) {
      appendError("Unexpected end of DCD file.");
      return false;
    }
    struct_unpack(buff.data(), fmt, &cy[i]);
  }

  snprintf(fmt, sizeof(fmt), "%c2i", endian);
  if (!readBlock(inStream, buff, struct_calcsize(fmt), fileLen)) {
    appendError("Unexpected end of DCD file.");
    return false;
  }
  struct_unpack(buff.data(), fmt, &formatint[3], &formatint[4]);

  for (int i = 0; i < NATOMS; ++i) {
    // Z coordinates
    snprintf(fmt, sizeof(fmt), "%c%df", endian, 1);
    if (!readBlock(inStream, buff, struct_calcsize(fmt), fileLen)) {
      appendError("Unexpected end of DCD file.");
      return false;
    }
    struct_unpack(buff.data(), fmt, &cz[i]);
  }

  snprintf(fmt, sizeof(fmt), "%c1i", endian);
  if (!readBlock(inStream, buff, struct_calcsize(fmt), fileLen)) {
    appendError("Unexpected end of DCD file.");
    return false;
  }
  struct_unpack(buff.data(), fmt, &formatint[5]);

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
    if (!readBlock(inStream, buff, struct_calcsize(fmt), fileLen)) {
      appendError("Unexpected end of DCD file.");
      return false;
    }
    int sizeToRead;
    struct_unpack(buff.data(), fmt, &sizeToRead);

    if (!readBlock(inStream, buff, sizeToRead, fileLen)) {
      appendError("Unexpected end of DCD file.");
      return false;
    }

    if (!readBlock(inStream, buff, sizeof(int), fileLen)) {
      appendError("Unexpected end of DCD file.");
      return false;
    }
  }

  // Set the custom element map if needed
  if (!atomTypes.empty()) {
    Molecule::CustomElementMap elementMap;
    for (const auto& atomType : atomTypes) {
      elementMap.insert(
        std::make_pair(atomType.second, "Atom " + atomType.first));
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
    positions.resize(NATOMS);

    snprintf(fmt, sizeof(fmt), "%c1i", endian);
    readBlock(inStream, buff, struct_calcsize(fmt), fileLen);
    struct_unpack(buff.data(), fmt, &formatint[0]);

    for (int i = 0; i < NATOMS; ++i) {
      // X coordinates
      snprintf(fmt, sizeof(fmt), "%c%df", endian, 1);
      readBlock(inStream, buff, struct_calcsize(fmt), fileLen);
      struct_unpack(buff.data(), fmt, &cx[i]);
    }

    snprintf(fmt, sizeof(fmt), "%c2i", endian);
    readBlock(inStream, buff, struct_calcsize(fmt), fileLen);
    struct_unpack(buff.data(), fmt, &formatint[1], &formatint[2]);

    for (int i = 0; i < NATOMS; ++i) {
      // Y coordinates
      snprintf(fmt, sizeof(fmt), "%c%df", endian, 1);
      readBlock(inStream, buff, struct_calcsize(fmt), fileLen);
      struct_unpack(buff.data(), fmt, &cy[i]);
    }

    snprintf(fmt, sizeof(fmt), "%c2i", endian);
    readBlock(inStream, buff, struct_calcsize(fmt), fileLen);
    struct_unpack(buff.data(), fmt, &formatint[3], &formatint[4]);

    for (int i = 0; i < NATOMS; ++i) {
      // Z coordinates
      snprintf(fmt, sizeof(fmt), "%c%df", endian, 1);
      readBlock(inStream, buff, struct_calcsize(fmt), fileLen);
      struct_unpack(buff.data(), fmt, &cz[i]);
    }

    snprintf(fmt, sizeof(fmt), "%c1i", endian);
    readBlock(inStream, buff, struct_calcsize(fmt), fileLen);
    struct_unpack(buff.data(), fmt, &formatint[5]);

    for (int i = 0; i < NATOMS; ++i) {
      Vector3 pos(cx[i], cy[i], cz[i]);
      positions.push_back(pos);
    }

    mol.setTimeStep(DELTA * coordSet, coordSet);

    // Skipping fourth dimension block
    if ((charmm & DCD_IS_CHARMM) && (charmm & DCD_HAS_EXTRA_BLOCK)) {
      snprintf(fmt, sizeof(fmt), "%c1i", endian);
      readBlock(inStream, buff, struct_calcsize(fmt), fileLen);
      int sizeToRead;
      struct_unpack(buff.data(), fmt, &sizeToRead);

      readBlock(inStream, buff, sizeToRead, fileLen);

      readBlock(inStream, buff, sizeof(int), fileLen);
    }

    mol.setCoordinate3d(positions, coordSet++);
  }

  return true;
}

bool DcdFormat::write(std::ostream&, const Core::Molecule&)
{
  return false;
}

std::vector<std::string> DcdFormat::fileExtensions() const
{
  std::vector<std::string> ext;
  ext.emplace_back("dcd");
  return ext;
}

std::vector<std::string> DcdFormat::mimeTypes() const
{
  std::vector<std::string> mime;
  mime.emplace_back("application/octet-stream");
  return mime;
}

} // namespace Avogadro::Io
