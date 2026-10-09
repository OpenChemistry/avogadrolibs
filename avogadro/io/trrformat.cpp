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

#include <cstddef>
#include <cstdint>
#include <istream>
#include <memory>
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
  // Swap as unsigned: shifting a negative int left is undefined, and the
  // magic number read in the wrong byte order is often negative.
  const auto u = static_cast<uint32_t>(inp);
  return static_cast<int>(((u << 24) & 0xff000000U) | ((u << 8) & 0x00ff0000U) |
                          ((u >> 8) & 0x0000ff00U) | ((u >> 24) & 0x000000ffU));
}

// The ByteOrder for the '>'/'<' char used in struct format strings.
Core::ByteOrder byteOrderOf(char endian)
{
  return endian == '>' ? Core::ByteOrder::BigEndian
                       : Core::ByteOrder::LittleEndian;
}

char swapEndian(char endian)
{
  if (endian == '>')
    return '<';
  else
    return '>';
}

/**
 * Read @a count floats or doubles (the file's precision) in the file's byte
 * order and multiply each by NM_TO_ANGSTROM. A failed read leaves the buffer
 * zeroed, so @a out then holds zeros. Decoding goes through the Core
 * utilities, which keep -0.0, denormals, inf and NaN exact.
 */
void readScaled(std::istream& in, std::vector<char>& buff,
                std::streamsize fileLen, char endian, bool isDoubleData,
                int count, double* out)
{
  const std::size_t size = isDoubleData ? sizeof(double) : sizeof(float);
  readBlock(in, buff, static_cast<std::streamsize>(size * count), fileLen);
  for (int k = 0; k < count; ++k) {
    const char* data = buff.data() + k * size;
    if (isDoubleData)
      out[k] = Core::unpackDouble(data, byteOrderOf(endian)) * NM_TO_ANGSTROM;
    else
      out[k] = static_cast<double>(
        Core::unpackFloat(data, byteOrderOf(endian)) * NM_TO_ANGSTROM);
  }
}

/**
 * Read the box, virial or pressure matrix (DIM x DIM, scaled to Angstrom).
 * For a box, set the unit cell; returns false if the cell is singular.
 */
bool readMatrix(std::istream& in, std::vector<char>& buff,
                std::streamsize fileLen, char endian, bool isDoubleData,
                bool isBox, Molecule& mol)
{
  double mat[DIM * DIM];
  readScaled(in, buff, fileLen, endian, isDoubleData, DIM * DIM, mat);
  if (isBox) {
    auto uc = std::make_unique<UnitCell>(Vector3(mat[0], mat[1], mat[2]),
                                         Vector3(mat[3], mat[4], mat[5]),
                                         Vector3(mat[6], mat[7], mat[8]));
    if (!uc->isRegular())
      return false;
    mol.setUnitCell(uc.release());
  }
  return true;
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
        size = (int)(header[headerKey] / (DIM * DIM));
        break;
      } else {
        // natoms is read from the file, and this is integer division: a
        // declared count of zero used to raise SIGFPE right here.
        if (header["natoms"] <= 0)
          return 0;
        // 64-bit, since natoms * DIM overflows int for a huge declared count
        size = static_cast<int>(header[headerKey] /
                                (static_cast<int64_t>(header["natoms"]) * DIM));
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
    header[HEADITEMS[i]] = headval[i];
  }

  // Skip the timestep and lambda. Nothing uses them, and converting a
  // NaN or out-of-range value from the file to int is undefined.
  doubleStatus = isDouble(header);
  snprintf(fmt, sizeof(fmt), "%c2%c", endian, doubleStatus ? 'd' : 'f');
  readBlock(inStream, buff, struct_calcsize(fmt), fileLen);

  // Reading matrices corresponding to "box_size", "vir_size", "pres_size"
  for (auto& _kid : keyCheck) {
    if (header[_kid] != 0) {
      if (!readMatrix(inStream, buff, fileLen, endian, doubleStatus,
                      _kid == "box_size", mol)) {
        appendError("lattice vectors are not linear independent");
        return false;
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
    double coords[DIM];
    for (int i = 0; i < natoms; ++i) {
      if (header[_kid] != 0) {
        readScaled(inStream, buff, fileLen, endian, doubleStatus, DIM, coords);

        if (_kid == "x_size") {
          Vector3 pos(coords[0], coords[1], coords[2]);

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
  const int firstFrameAtoms = header["natoms"];

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

    // Reading trajectory version string, bounded as for the first frame.
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
                  &headval[3], &headval[4], &headval[5], &headval[6],
                  &headval[7], &headval[8], &headval[9], &headval[10],
                  &headval[11], &headval[12]);
    for (int i = 0; i < 13; ++i) {
      header[HEADITEMS[i]] = headval[i];
    }

    // Skip the timestep and lambda. Nothing uses them, and converting a
    // NaN or out-of-range value from the file to int is undefined.
    doubleStatus = isDouble(header);
    snprintf(fmt, sizeof(fmt), "%c2%c", endian, doubleStatus ? 'd' : 'f');
    readBlock(inStream, buff, struct_calcsize(fmt), fileLen);

    // Reading matrices corresponding to "box_size", "vir_size", "pres_size"
    for (auto& _kid : keyCheck) {
      if (header[_kid] != 0) {
        natoms = header["natoms"];
        if (!readMatrix(inStream, buff, fileLen, endian, doubleStatus,
                        _kid == "box_size", mol)) {
          appendError("lattice vectors are not linear independent");
          return false;
        }
      }
    }

    // Every frame describes the atoms of the first one.
    if (header["natoms"] != firstFrameAtoms) {
      appendError("TRR frame atom count differs from the first frame.");
      return false;
    }
    natoms = header["natoms"];
    Array<Vector3> positions;
    positions.reserve(natoms);

    // Reading the coordinates of positions, velocities and forces
    for (auto& _kid : keyCheck2) {
      double coords[DIM];
      for (int i = 0; i < natoms; ++i) {
        if (header[_kid] != 0) {
          readScaled(inStream, buff, fileLen, endian, doubleStatus, DIM,
                     coords);

          if (_kid == "x_size") {
            Vector3 pos(coords[0], coords[1], coords[2]);
            positions.push_back(pos);
          }
        }
      }
    }
    // Frames may carry only velocities or forces (nstvout, nstfout), and
    // those are no coordinate set.
    if (header["x_size"] != 0)
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
