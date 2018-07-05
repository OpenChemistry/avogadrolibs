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

#include "trrformat.h"
#include "struct.h"

#include <avogadro/core/elements.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/unitcell.h>
#include <avogadro/core/utilities.h>
#include <avogadro/core/vector.h>

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
using Core::Molecule;
using Core::split;
using Core::trimmed;
using Core::UnitCell;

#ifndef _WIN32
using std::isalpha;
#endif

#define GROMACS_MAGIC 1993
#define DIM 3
#define NM_TO_ANGSTROM 10.0
string TRRVERSION = "GMX_trn_file";
string HEADITEMS[] = { "ir_size",   "e_size",   "box_size", "vir_size",
                       "pres_size", "top_size", "sym_size", "x_size",
                       "v_size",    "f_size",   "natoms",   "step",
                       "nre",       "time",     "lambda" };

int swapInteger(int inp)
{
  return (((inp << 24) & 0xff000000) | ((inp << 8) & 0x00ff0000) |
          ((inp >> 8) & 0x0000ff00) | ((inp >> 24) & 0x000000ff));
}

char swapEndian(char endian)
{
  if (endian == '>')
    return '<';
  else
    return '>';
}

/* Checks whether the data stored in the binary file is of float or double type
 */
int isDouble(map<string, int>& header)
{
  int SIZE_DOUBLE = struct_calcsize("d");
  int size = 0;
  string headerKeys[] = { "box_size", "x_size", "v_size", "f_size" };

  for (int i = 0; i < (int)(sizeof(headerKeys) / sizeof(*headerKeys)); i++) {
    if (header[headerKeys[i]] != 0) {
      if (headerKeys[i] == "box_size") {
        size = (int)(header[headerKeys[i]] / DIM * DIM);
        break;
      } else {
        size = (int)(header[headerKeys[i]] / (header["natoms"] * DIM));
        break;
      }
    }
  }
  return size == SIZE_DOUBLE;
}

TrrFormat::TrrFormat() {}

TrrFormat::~TrrFormat() {}

bool TrrFormat::read(std::istream& inStream, Core::Molecule& mol)
{
  bool doubleStatus;
  char endian = '>', buff[BUFSIZ], fmt[BUFSIZ], raw[1000];
  int magic, natoms, slen0, slen1, headval[13];
  string subs, keyCheck[] = { "box_size", "vir_size", "pres_size" },
               keyCheck2[] = { "x_size", "v_size", "f_size" };
  map<string, int> header;

  // Determining size of file
  inStream.seekg(0, inStream.end);
  int fileLen = inStream.tellg();
  inStream.seekg(0, inStream.beg);

  // Binary file must start with 1993
  snprintf(fmt, sizeof(fmt), "%c1i", endian);
  inStream.read(buff, struct_calcsize(fmt));
  struct_unpack(buff, fmt, &magic);
  if (magic != GROMACS_MAGIC) {
    // Endian conversion
    magic = swapInteger(magic);
    endian = swapEndian(endian);
    if (magic != GROMACS_MAGIC) {
      appendError("Frame does not start with magic number 1993.");
      return false;
    }
  }

  snprintf(fmt, sizeof(fmt), "%c2i", endian);
  inStream.read(buff, struct_calcsize(fmt));
  struct_unpack(buff, fmt, &slen0, &slen1);

  // Reading trajectory version string
  snprintf(fmt, sizeof(fmt), "%c%ds", endian, slen0 - 1);
  inStream.read(buff, struct_calcsize(fmt));
  struct_unpack(buff, fmt, raw);
  subs = string(raw).substr(0, 12);
  if (subs != TRRVERSION) {
    appendError("Gromacs version string mismatch.");
    return false;
  }

  // "ir_size", "e_size", "box_size", "vir_size", "pres_size",
  // "top_size", "sym_size", "x_size", "v_size", "f_size",
  // "natoms", "step", "nre"
  snprintf(fmt, sizeof(fmt), "%c13i", endian);
  inStream.read(buff, struct_calcsize(fmt));
  struct_unpack(buff, fmt, &headval[0], &headval[1], &headval[2], &headval[3],
                &headval[4], &headval[5], &headval[6], &headval[7], &headval[8],
                &headval[9], &headval[10], &headval[11], &headval[12]);
  for (int i = 0; i < 13; ++i) {
    header.insert(pair<string, int>(HEADITEMS[i], headval[i]));
  }

  // Reading timestep and lambda
  doubleStatus = isDouble(header);
  if (doubleStatus) {
    double header0, header1;
    snprintf(fmt, sizeof(fmt), "%c2d", endian);
    inStream.read(buff, struct_calcsize(fmt));
    struct_unpack(buff, fmt, &header0, &header1);
    header.insert(pair<string, int>("time", header0));
    header.insert(pair<string, int>("lambda", header1));
  } else {
    float header0, header1;
    snprintf(fmt, sizeof(fmt), "%c2f", endian);
    inStream.read(buff, struct_calcsize(fmt));
    struct_unpack(buff, fmt, &header0, &header1);
    header.insert(pair<string, int>("time", header0));
    header.insert(pair<string, int>("lambda", header1));
  }

  // Reading matrices corresponding to "box_size", "vir_size", "pres_size"
  for (int _kid = 0; _kid < 3; ++_kid) {
    if (header[keyCheck[_kid]] != 0) {
      if (doubleStatus) {
        snprintf(fmt, sizeof(fmt), "%c%dd", endian, DIM * DIM);
        double mat[DIM][DIM];
        inStream.read(buff, struct_calcsize(fmt));
        struct_unpack(buff, fmt, &mat[0][0], &mat[0][1], &mat[0][2], &mat[1][0],
                      &mat[1][1], &mat[1][2], &mat[2][0], &mat[2][1],
                      &mat[2][2]);
        if (keyCheck[_kid] == "box_size") {
          mol.setUnitCell(new UnitCell(
            Vector3(mat[0][0] * NM_TO_ANGSTROM, mat[0][1] * NM_TO_ANGSTROM,
                    mat[0][2] * NM_TO_ANGSTROM),
            Vector3(mat[1][0] * NM_TO_ANGSTROM, mat[1][1] * NM_TO_ANGSTROM,
                    mat[1][2] * NM_TO_ANGSTROM),
            Vector3(mat[2][0] * NM_TO_ANGSTROM, mat[2][1] * NM_TO_ANGSTROM,
                    mat[2][2] * NM_TO_ANGSTROM)));
        }
      } else {
        snprintf(fmt, sizeof(fmt), "%c%df", endian, DIM * DIM);
        float mat[DIM][DIM];
        inStream.read(buff, struct_calcsize(fmt));
        struct_unpack(buff, fmt, &mat[0][0], &mat[0][1], &mat[0][2], &mat[1][0],
                      &mat[1][1], &mat[1][2], &mat[2][0], &mat[2][1],
                      &mat[2][2]);
        if (keyCheck[_kid] == "box_size") {
          mol.setUnitCell(new UnitCell(
            Vector3(mat[0][0] * NM_TO_ANGSTROM, mat[0][1] * NM_TO_ANGSTROM,
                    mat[0][2] * NM_TO_ANGSTROM),
            Vector3(mat[1][0] * NM_TO_ANGSTROM, mat[1][1] * NM_TO_ANGSTROM,
                    mat[1][2] * NM_TO_ANGSTROM),
            Vector3(mat[2][0] * NM_TO_ANGSTROM, mat[2][1] * NM_TO_ANGSTROM,
                    mat[2][2] * NM_TO_ANGSTROM)));
        }
      }
    }
  }

  typedef map<string, unsigned char> AtomTypeMap;
  AtomTypeMap atomTypes;
  unsigned char customElementCounter = CustomElementMin;

  // Reading the coordinates of positions, velocities and forces
  for (int _kid = 0; _kid < 3; ++_kid) {
    natoms = header["natoms"];
    double coordsDouble[DIM];
    float coordsFloat[DIM];
    for (int i = 0; i < natoms; ++i) {
      if (header[keyCheck2[_kid]] != 0) {
        memset(coordsDouble, 0, sizeof(coordsDouble));
        memset(coordsFloat, 0, sizeof(coordsFloat));
        if (doubleStatus) {
          snprintf(fmt, sizeof(fmt), "%c%dd", endian, DIM);
          inStream.read(buff, struct_calcsize(fmt));
          struct_unpack(buff, fmt, &coordsDouble[0], &coordsDouble[1],
                        &coordsDouble[2]);
        } else {
          snprintf(fmt, sizeof(fmt), "%c%df", endian, DIM);
          inStream.read(buff, struct_calcsize(fmt));
          struct_unpack(buff, fmt, &coordsFloat[0], &coordsFloat[1],
                        &coordsFloat[2]);
        }

        if (keyCheck2[_kid] == "x_size") {
          // If parsed coordinates are fractional, the corresponding unscaling
          // is done. Else the positions are assigned as parsed.
          Vector3 pos(
            coordsDouble[0] * NM_TO_ANGSTROM + coordsFloat[0] * NM_TO_ANGSTROM,
            coordsDouble[1] * NM_TO_ANGSTROM + coordsFloat[1] * NM_TO_ANGSTROM,
            coordsDouble[2] * NM_TO_ANGSTROM + coordsFloat[2] * NM_TO_ANGSTROM);

          AtomTypeMap::const_iterator it;
          // if (it == atomTypes.end()) {
          atomTypes.insert(
            std::make_pair(to_string(i), customElementCounter++));
          it = atomTypes.find(to_string(i));
          // if (customElementCounter > CustomElementMax) {
          //   appendError("Custom element type limit exceeded.");
          //   return false;
          // }
          Atom newAtom = mol.addAtom(it->second);
          newAtom.setPosition3d(pos);
        }
      }
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
  }
  mol.setCoordinate3d(mol.atomPositions3d(), 0);

  // Do we have an animation?
  // EOF check
  int coordSet = 1;
  while (static_cast<int>(inStream.tellg()) != fileLen) {
    // Binary header must start with 1993
    snprintf(fmt, sizeof(fmt), "%c1i", endian);
    inStream.read(buff, struct_calcsize(fmt));
    struct_unpack(buff, fmt, &magic);
    if (magic != GROMACS_MAGIC) {
      // Endian conversion
      magic = swapInteger(magic);
      endian = swapEndian(endian);
      if (magic != GROMACS_MAGIC) {
        appendError("Frame does not start with magic number 1993.");
        return false;
      }
    }

    snprintf(fmt, sizeof(fmt), "%c2i", endian);
    inStream.read(buff, struct_calcsize(fmt));
    struct_unpack(buff, fmt, &slen0, &slen1);

    // Reading trajectory version string
    snprintf(fmt, sizeof(fmt), "%c%ds", endian, slen0 - 1);
    inStream.read(buff, struct_calcsize(fmt));
    struct_unpack(buff, fmt, raw);
    subs = string(raw).substr(0, 12);
    if (subs != TRRVERSION) {
      appendError("Gromacs version string mismatch.");
      return false;
    }

    // "ir_size", "e_size", "box_size", "vir_size", "pres_size",
    // "top_size", "sym_size", "x_size", "v_size", "f_size",
    // "natoms", "step", "nre"
    snprintf(fmt, sizeof(fmt), "%c13i", endian);
    inStream.read(buff, struct_calcsize(fmt));
    struct_unpack(buff, fmt, &headval[0], &headval[1], &headval[2], &headval[3],
                  &headval[4], &headval[5], &headval[6], &headval[7],
                  &headval[8], &headval[9], &headval[10], &headval[11],
                  &headval[12]);
    for (int i = 0; i < 13; ++i) {
      header.insert(pair<string, int>(HEADITEMS[i], headval[i]));
    }

    // Reading timestep and lambda
    doubleStatus = isDouble(header);
    if (doubleStatus) {
      double header0, header1;
      snprintf(fmt, sizeof(fmt), "%c2d", endian);
      inStream.read(buff, struct_calcsize(fmt));
      struct_unpack(buff, fmt, &header0, &header1);
      header.insert(pair<string, int>("time", header0));
      header.insert(pair<string, int>("lambda", header1));
    } else {
      float header0, header1;
      snprintf(fmt, sizeof(fmt), "%c2f", endian);
      inStream.read(buff, struct_calcsize(fmt));
      struct_unpack(buff, fmt, &header0, &header1);
      header.insert(pair<string, int>("time", header0));
      header.insert(pair<string, int>("lambda", header1));
    }

    // Reading matrices corresponding to "box_size", "vir_size", "pres_size"
    for (int _kid = 0; _kid < 3; ++_kid) {
      if (header[keyCheck[_kid]] != 0) {
        natoms = header["natoms"];
        if (doubleStatus) {
          snprintf(fmt, sizeof(fmt), "%c%dd", endian, DIM * DIM);
          double mat[DIM][DIM];
          inStream.read(buff, struct_calcsize(fmt));
          struct_unpack(buff, fmt, &mat[0][0], &mat[0][1], &mat[0][2],
                        &mat[1][0], &mat[1][1], &mat[1][2], &mat[2][0],
                        &mat[2][1], &mat[2][2]);
          if (keyCheck[_kid] == "box_size") {
            mol.setUnitCell(new UnitCell(
              Vector3(mat[0][0] * NM_TO_ANGSTROM, mat[0][1] * NM_TO_ANGSTROM,
                      mat[0][2] * NM_TO_ANGSTROM),
              Vector3(mat[1][0] * NM_TO_ANGSTROM, mat[1][1] * NM_TO_ANGSTROM,
                      mat[1][2] * NM_TO_ANGSTROM),
              Vector3(mat[2][0] * NM_TO_ANGSTROM, mat[2][1] * NM_TO_ANGSTROM,
                      mat[2][2] * NM_TO_ANGSTROM)));
          }
        } else {
          snprintf(fmt, sizeof(fmt), "%c%df", endian, DIM * DIM);
          float mat[DIM][DIM];
          inStream.read(buff, struct_calcsize(fmt));
          struct_unpack(buff, fmt, &mat[0][0], &mat[0][1], &mat[0][2],
                        &mat[1][0], &mat[1][1], &mat[1][2], &mat[2][0],
                        &mat[2][1], &mat[2][2]);
          if (keyCheck[_kid] == "box_size") {
            mol.setUnitCell(new UnitCell(
              Vector3(mat[0][0] * NM_TO_ANGSTROM, mat[0][1] * NM_TO_ANGSTROM,
                      mat[0][2] * NM_TO_ANGSTROM),
              Vector3(mat[1][0] * NM_TO_ANGSTROM, mat[1][1] * NM_TO_ANGSTROM,
                      mat[1][2] * NM_TO_ANGSTROM),
              Vector3(mat[2][0] * NM_TO_ANGSTROM, mat[2][1] * NM_TO_ANGSTROM,
                      mat[2][2] * NM_TO_ANGSTROM)));
          }
        }
      }
    }

    natoms = header["natoms"];
    Array<Vector3> positions;
    positions.reserve(natoms);

    // Reading the coordinates of positions, velocities and forces
    for (int _kid = 0; _kid < 3; ++_kid) {
      double coordsDouble[DIM];
      float coordsFloat[DIM];
      for (int i = 0; i < natoms; ++i) {
        if (header[keyCheck2[_kid]] != 0) {
          memset(coordsDouble, 0, sizeof(coordsDouble));
          memset(coordsFloat, 0, sizeof(coordsFloat));
          if (doubleStatus) {
            snprintf(fmt, sizeof(fmt), "%c%dd", endian, DIM);
            inStream.read(buff, struct_calcsize(fmt));
            struct_unpack(buff, fmt, &coordsDouble[0], &coordsDouble[1],
                          &coordsDouble[2]);
          } else {
            snprintf(fmt, sizeof(fmt), "%c%df", endian, DIM);
            inStream.read(buff, struct_calcsize(fmt));
            struct_unpack(buff, fmt, &coordsFloat[0], &coordsFloat[1],
                          &coordsFloat[2]);
          }

          if (keyCheck2[_kid] == "x_size") {
            // If parsed coordinates are fractional, the corresponding unscaling
            // is done. Else the positions are assigned as parsed.
            Vector3 pos(coordsDouble[0] * NM_TO_ANGSTROM +
                          coordsFloat[0] * NM_TO_ANGSTROM,
                        coordsDouble[1] * NM_TO_ANGSTROM +
                          coordsFloat[1] * NM_TO_ANGSTROM,
                        coordsDouble[2] * NM_TO_ANGSTROM +
                          coordsFloat[2] * NM_TO_ANGSTROM);
            positions.push_back(pos);
          }
        }
      }
    }
    mol.setCoordinate3d(positions, coordSet++);
    positions.clear();
  }
  return true;
}

bool TrrFormat::write(std::ostream& outStream, const Core::Molecule& mol)
{
  return false;
}

std::vector<std::string> TrrFormat::fileExtensions() const
{
  std::vector<std::string> ext;
  ext.push_back("trr");
  return ext;
}

std::vector<std::string> TrrFormat::mimeTypes() const
{
  std::vector<std::string> mime;
  mime.push_back("application/octet-stream");
  return mime;
}

} // end Io namespace
} // end Avogadro namespace
