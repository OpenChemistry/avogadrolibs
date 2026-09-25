/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "trrformat.h"
#include "binaryblock_p.h"
#include "struct.h"

#include <avogadro/core/elements.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/unitcell.h>
#include <avogadro/core/utilities.h>
#include <avogadro/core/vector.h>

#include <istream>
#include <ostream>
#include <string>
#include <vector>

using std::map;
using std::pair;
using std::string;
using std::to_string;

namespace Avogadro::Io {

using Core::Array;
using Core::Atom;
using Core::Molecule;
using Core::UnitCell;

constexpr int GROMACS_MAGIC = 1993;
constexpr int DIM = 3;
constexpr float NM_TO_ANGSTROM = 10.0;
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

  for (auto& headerKey : headerKeys) {
    if (header[headerKey] != 0) {
      if (headerKey == "box_size") {
        size = (int)(header[headerKey] / DIM * DIM);
        break;
      } else {
        // natoms is read from the file, and this is integer division: a
        // declared count of zero used to raise SIGFPE right here.
        if (header["natoms"] <= 0)
          return 0;
        size = (int)(header[headerKey] / (header["natoms"] * DIM));
        break;
      }
    }
  }
  return size == SIZE_DOUBLE;
}

bool TrrFormat::read(std::istream& inStream, Core::Molecule& mol)
{
  bool doubleStatus;
  char endian = '>', fmt[BUFSIZ], raw[1000] = {};
  std::vector<char> buff(BUFSIZ);
  int magic = 0, natoms = 0, slen0 = 0, slen1 = 0, headval[13] = {};
  string subs, keyCheck[] = { "box_size", "vir_size", "pres_size" },
               keyCheck2[] = { "x_size", "v_size", "f_size" };
  map<string, int> header;

  // Determining size of file
  inStream.seekg(0, inStream.end);
  int fileLen = inStream.tellg();
  inStream.seekg(0, inStream.beg);

  // Binary file must start with 1993
  snprintf(fmt, sizeof(fmt), "%c1i", endian);
  readBlock(inStream, buff, struct_calcsize(fmt), fileLen);
  struct_unpack(buff.data(), fmt, &magic);
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
  readBlock(inStream, buff, struct_calcsize(fmt), fileLen);
  struct_unpack(buff.data(), fmt, &slen0, &slen1);

  // Reading trajectory version string. slen0 comes from the file and was fed
  // straight to a "%ds" unpack into raw[1000], overflowing it above 1001 as
  // well as overflowing the read buffer. raw is zero filled and one byte is
  // held back, so what lands in it stays NUL terminated for string(raw).
  if (slen0 < 1 || slen0 > static_cast<int>(sizeof(raw))) {
    appendError("TRR file declares an implausible version string length.");
    return false;
  }
  snprintf(fmt, sizeof(fmt), "%c%ds", endian, slen0 - 1);
  readBlock(inStream, buff, struct_calcsize(fmt), fileLen);
  struct_unpack(buff.data(), fmt, raw);
  subs = string(raw).substr(0, 12);
  if (subs != TRRVERSION) {
    appendError("Gromacs version string mismatch.");
    return false;
  }

  // "ir_size", "e_size", "box_size", "vir_size", "pres_size",
  // "top_size", "sym_size", "x_size", "v_size", "f_size",
  // "natoms", "step", "nre"
  snprintf(fmt, sizeof(fmt), "%c13i", endian);
  readBlock(inStream, buff, struct_calcsize(fmt), fileLen);
  struct_unpack(buff.data(), fmt, &headval[0], &headval[1], &headval[2],
                &headval[3], &headval[4], &headval[5], &headval[6], &headval[7],
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
    readBlock(inStream, buff, struct_calcsize(fmt), fileLen);
    struct_unpack(buff.data(), fmt, &header0, &header1);
    header.insert(pair<string, int>("time", header0));
    header.insert(pair<string, int>("lambda", header1));
  } else {
    float header0, header1;
    snprintf(fmt, sizeof(fmt), "%c2f", endian);
    readBlock(inStream, buff, struct_calcsize(fmt), fileLen);
    struct_unpack(buff.data(), fmt, &header0, &header1);
    header.insert(pair<string, int>("time", header0));
    header.insert(pair<string, int>("lambda", header1));
  }

  // Reading matrices corresponding to "box_size", "vir_size", "pres_size"
  for (auto& _kid : keyCheck) {
    if (header[_kid] != 0) {
      if (doubleStatus) {
        snprintf(fmt, sizeof(fmt), "%c%dd", endian, DIM * DIM);
        double mat[DIM][DIM];
        readBlock(inStream, buff, struct_calcsize(fmt), fileLen);
        struct_unpack(buff.data(), fmt, &mat[0][0], &mat[0][1], &mat[0][2],
                      &mat[1][0], &mat[1][1], &mat[1][2], &mat[2][0],
                      &mat[2][1], &mat[2][2]);
        if (_kid == "box_size") {
          auto* uc = new UnitCell(
            Vector3(mat[0][0] * NM_TO_ANGSTROM, mat[0][1] * NM_TO_ANGSTROM,
                    mat[0][2] * NM_TO_ANGSTROM),
            Vector3(mat[1][0] * NM_TO_ANGSTROM, mat[1][1] * NM_TO_ANGSTROM,
                    mat[1][2] * NM_TO_ANGSTROM),
            Vector3(mat[2][0] * NM_TO_ANGSTROM, mat[2][1] * NM_TO_ANGSTROM,
                    mat[2][2] * NM_TO_ANGSTROM));
          if (!uc->isRegular()) {
            appendError("lattice vectors are not linear independent");
            delete uc;
            return false;
          }
          mol.setUnitCell(uc);
        }
      } else {
        snprintf(fmt, sizeof(fmt), "%c%df", endian, DIM * DIM);
        float mat[DIM][DIM];
        readBlock(inStream, buff, struct_calcsize(fmt), fileLen);
        struct_unpack(buff.data(), fmt, &mat[0][0], &mat[0][1], &mat[0][2],
                      &mat[1][0], &mat[1][1], &mat[1][2], &mat[2][0],
                      &mat[2][1], &mat[2][2]);
        if (_kid == "box_size") {
          auto* uc = new UnitCell(
            Vector3(mat[0][0] * NM_TO_ANGSTROM, mat[0][1] * NM_TO_ANGSTROM,
                    mat[0][2] * NM_TO_ANGSTROM),
            Vector3(mat[1][0] * NM_TO_ANGSTROM, mat[1][1] * NM_TO_ANGSTROM,
                    mat[1][2] * NM_TO_ANGSTROM),
            Vector3(mat[2][0] * NM_TO_ANGSTROM, mat[2][1] * NM_TO_ANGSTROM,
                    mat[2][2] * NM_TO_ANGSTROM));
          if (!uc->isRegular()) {
            appendError("lattice vectors are not linear independent");
            return false;
          }
          mol.setUnitCell(uc);
        }
      }
    }
  }

  using AtomTypeMap = map<string, unsigned char>;
  AtomTypeMap atomTypes;
  unsigned char customElementCounter = CustomElementMin;

  // Each atom costs at least DIM floats, so a count larger than the file
  // itself cannot be real.
  if (header["natoms"] < 0 || header["natoms"] > fileLen) {
    appendError("TRR file declares an implausible atom count.");
    return false;
  }

  // Reading the coordinates of positions, velocities and forces
  for (auto& _kid : keyCheck2) {
    natoms = header["natoms"];
    double coordsDouble[DIM];
    float coordsFloat[DIM];
    for (int i = 0; i < natoms; ++i) {
      if (header[_kid] != 0) {
        memset(coordsDouble, 0, sizeof(coordsDouble));
        memset(coordsFloat, 0, sizeof(coordsFloat));
        if (doubleStatus) {
          snprintf(fmt, sizeof(fmt), "%c%dd", endian, DIM);
          readBlock(inStream, buff, struct_calcsize(fmt), fileLen);
          struct_unpack(buff.data(), fmt, &coordsDouble[0], &coordsDouble[1],
                        &coordsDouble[2]);
        } else {
          snprintf(fmt, sizeof(fmt), "%c%df", endian, DIM);
          readBlock(inStream, buff, struct_calcsize(fmt), fileLen);
          struct_unpack(buff.data(), fmt, &coordsFloat[0], &coordsFloat[1],
                        &coordsFloat[2]);
        }

        if (_kid == "x_size") {
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
      for (const auto& atomType : atomTypes) {
        elementMap.insert(
          std::make_pair(atomType.second, "Atom " + atomType.first));
      }
      mol.setCustomElementMap(elementMap);
    }
  }
  mol.setCoordinate3d(mol.atomPositions3d(), 0);

  // Do we have an animation?
  // tellg() returns -1 once the stream is exhausted, which never equals
  // fileLen -- so testing only for fileLen span forever on a truncated file.
  int coordSet = 1;
  while (static_cast<int>(inStream.tellg()) != fileLen &&
         static_cast<int>(inStream.tellg()) != -1) {
    // Binary header must start with 1993
    snprintf(fmt, sizeof(fmt), "%c1i", endian);
    readBlock(inStream, buff, struct_calcsize(fmt), fileLen);
    struct_unpack(buff.data(), fmt, &magic);
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
    readBlock(inStream, buff, struct_calcsize(fmt), fileLen);
    struct_unpack(buff.data(), fmt, &slen0, &slen1);

    // Reading trajectory version string
    snprintf(fmt, sizeof(fmt), "%c%ds", endian, slen0 - 1);
    readBlock(inStream, buff, struct_calcsize(fmt), fileLen);
    struct_unpack(buff.data(), fmt, raw);
    subs = string(raw).substr(0, 12);
    if (subs != TRRVERSION) {
      appendError("Gromacs version string mismatch.");
      return false;
    }

    // "ir_size", "e_size", "box_size", "vir_size", "pres_size",
    // "top_size", "sym_size", "x_size", "v_size", "f_size",
    // "natoms", "step", "nre"
    snprintf(fmt, sizeof(fmt), "%c13i", endian);
    readBlock(inStream, buff, struct_calcsize(fmt), fileLen);
    struct_unpack(buff.data(), fmt, &headval[0], &headval[1], &headval[2],
                  &headval[3], &headval[4], &headval[5], &headval[6],
                  &headval[7], &headval[8], &headval[9], &headval[10],
                  &headval[11], &headval[12]);
    for (int i = 0; i < 13; ++i) {
      header.insert(pair<string, int>(HEADITEMS[i], headval[i]));
    }

    // Reading timestep and lambda
    doubleStatus = isDouble(header);
    if (doubleStatus) {
      double header0, header1;
      snprintf(fmt, sizeof(fmt), "%c2d", endian);
      readBlock(inStream, buff, struct_calcsize(fmt), fileLen);
      struct_unpack(buff.data(), fmt, &header0, &header1);
      header.insert(pair<string, int>("time", header0));
      header.insert(pair<string, int>("lambda", header1));
    } else {
      float header0, header1;
      snprintf(fmt, sizeof(fmt), "%c2f", endian);
      readBlock(inStream, buff, struct_calcsize(fmt), fileLen);
      struct_unpack(buff.data(), fmt, &header0, &header1);
      header.insert(pair<string, int>("time", header0));
      header.insert(pair<string, int>("lambda", header1));
    }

    // Reading matrices corresponding to "box_size", "vir_size", "pres_size"
    for (auto& _kid : keyCheck) {
      if (header[_kid] != 0) {
        natoms = header["natoms"];
        if (doubleStatus) {
          snprintf(fmt, sizeof(fmt), "%c%dd", endian, DIM * DIM);
          double mat[DIM][DIM];
          readBlock(inStream, buff, struct_calcsize(fmt), fileLen);
          struct_unpack(buff.data(), fmt, &mat[0][0], &mat[0][1], &mat[0][2],
                        &mat[1][0], &mat[1][1], &mat[1][2], &mat[2][0],
                        &mat[2][1], &mat[2][2]);
          if (_kid == "box_size") {
            auto* uc = new UnitCell(
              Vector3(mat[0][0] * NM_TO_ANGSTROM, mat[0][1] * NM_TO_ANGSTROM,
                      mat[0][2] * NM_TO_ANGSTROM),
              Vector3(mat[1][0] * NM_TO_ANGSTROM, mat[1][1] * NM_TO_ANGSTROM,
                      mat[1][2] * NM_TO_ANGSTROM),
              Vector3(mat[2][0] * NM_TO_ANGSTROM, mat[2][1] * NM_TO_ANGSTROM,
                      mat[2][2] * NM_TO_ANGSTROM));
            if (!uc->isRegular()) {
              appendError("lattice vectors are not linear independent");
              return false;
            }
            mol.setUnitCell(uc);
          }
        } else {
          snprintf(fmt, sizeof(fmt), "%c%df", endian, DIM * DIM);
          float mat[DIM][DIM];
          readBlock(inStream, buff, struct_calcsize(fmt), fileLen);
          struct_unpack(buff.data(), fmt, &mat[0][0], &mat[0][1], &mat[0][2],
                        &mat[1][0], &mat[1][1], &mat[1][2], &mat[2][0],
                        &mat[2][1], &mat[2][2]);
          if (_kid == "box_size") {
            auto* uc = new UnitCell(
              Vector3(mat[0][0] * NM_TO_ANGSTROM, mat[0][1] * NM_TO_ANGSTROM,
                      mat[0][2] * NM_TO_ANGSTROM),
              Vector3(mat[1][0] * NM_TO_ANGSTROM, mat[1][1] * NM_TO_ANGSTROM,
                      mat[1][2] * NM_TO_ANGSTROM),
              Vector3(mat[2][0] * NM_TO_ANGSTROM, mat[2][1] * NM_TO_ANGSTROM,
                      mat[2][2] * NM_TO_ANGSTROM));
            if (!uc->isRegular()) {
              appendError("lattice vectors are not linear independent");
              return false;
            }
            mol.setUnitCell(uc);
          }
        }
      }
    }

    natoms = header["natoms"];
    Array<Vector3> positions;
    positions.reserve(natoms);

    // Reading the coordinates of positions, velocities and forces
    for (auto& _kid : keyCheck2) {
      double coordsDouble[DIM];
      float coordsFloat[DIM];
      for (int i = 0; i < natoms; ++i) {
        if (header[_kid] != 0) {
          memset(coordsDouble, 0, sizeof(coordsDouble));
          memset(coordsFloat, 0, sizeof(coordsFloat));
          if (doubleStatus) {
            snprintf(fmt, sizeof(fmt), "%c%dd", endian, DIM);
            readBlock(inStream, buff, struct_calcsize(fmt), fileLen);
            struct_unpack(buff.data(), fmt, &coordsDouble[0], &coordsDouble[1],
                          &coordsDouble[2]);
          } else {
            snprintf(fmt, sizeof(fmt), "%c%df", endian, DIM);
            readBlock(inStream, buff, struct_calcsize(fmt), fileLen);
            struct_unpack(buff.data(), fmt, &coordsFloat[0], &coordsFloat[1],
                          &coordsFloat[2]);
          }

          if (_kid == "x_size") {
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

bool TrrFormat::write(std::ostream&, const Core::Molecule&)
{
  return false;
}

std::vector<std::string> TrrFormat::fileExtensions() const
{
  std::vector<std::string> ext;
  ext.emplace_back("trr");
  return ext;
}

std::vector<std::string> TrrFormat::mimeTypes() const
{
  std::vector<std::string> mime;
  mime.emplace_back("application/octet-stream");
  return mime;
}

} // namespace Avogadro::Io
