/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "dcdformat.h"
#include "binaryblock_p.h"

#include <avogadro/core/avogadrocore.h>
#include <avogadro/core/elements.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/unitcell.h>
#include <avogadro/core/utilities.h>
#include <avogadro/core/vector.h>

#include <cmath>
#include <cstdint>
#include <cstring>
#include <istream>
#include <memory>
#include <ostream>
#include <string>
#include <type_traits>
#include <vector>

using std::string;
using std::to_string;
using std::vector;

namespace Avogadro::Io {

using Core::Array;
using Core::Atom;
using Core::Molecule;
using Core::UnitCell;

namespace {

constexpr int DCD_MAGIC = 84;
// CHARMM -- and NAMD, which writes the CHARMM flavour -- records DELTA in AKMA
// time units, where one unit is 48.88821 fs (CHARMM's TIMFAC). X-PLOR records
// it in picoseconds already, which is why the two are read at different
// widths below.
constexpr double AkmaToPicoseconds = 0.04888821;

enum class RecordStatus
{
  Ok,
  Truncated, // the file ended inside the record
  BadMarker  // the leading and trailing length markers are inconsistent
};

// Everything the per-frame reader needs to know about the file.
struct DcdLayout
{
  char endian = '>';
  bool hasCell = false;     // CHARMM unit-cell record before the coordinates
  bool hasFourDims = false; // CHARMM fourth-dimension record after them
  int numAtoms = 0;
  // Zero-based indices of the atoms that move after the first frame. Only
  // meaningful when hasFixedAtoms (which can leave it empty if every atom is
  // fixed).
  bool hasFixedAtoms = false;
  std::vector<int> freeIndexes;
};

// Every length marker is a 4-byte int32.
constexpr std::streamsize MarkerBytes = 4;

// Decode a T (int32_t, float or double) stored in the file's byte order,
// '>' for big-endian and '<' for little-endian, independent of the host's.
// Going through the integer bits keeps -0.0, denormals, inf and NaN exact.
template <typename T>
T unpack(const char* data, char endian)
{
  using Bits = std::conditional_t<sizeof(T) == 4, uint32_t, uint64_t>;
  Bits bits = 0;
  for (std::size_t i = 0; i < sizeof(Bits); ++i) {
    const std::size_t shift = endian == '>' ? sizeof(Bits) - 1 - i : i;
    bits |= static_cast<Bits>(static_cast<unsigned char>(data[i]))
            << (8 * shift);
  }
  T value;
  std::memcpy(&value, &bits, sizeof(T));
  return value;
}

int unpackInt(const char* data, char endian)
{
  return unpack<int32_t>(data, endian);
}

/**
 * Read one Fortran-style record: a 4-byte length marker, the payload, and the
 * same marker again. The payload is left in @a payload. If @a expectedBytes is
 * not negative, the marker must equal it.
 */
RecordStatus readRecord(std::istream& in, char endian, std::streamoff fileLen,
                        std::vector<char>& payload, int expectedBytes,
                        int* length = nullptr)
{
  std::vector<char> marker(MarkerBytes);
  if (!readBlock(in, marker, MarkerBytes, fileLen))
    return RecordStatus::Truncated;
  const int bytes = unpackInt(marker.data(), endian);
  if (bytes < 0 || (expectedBytes >= 0 && bytes != expectedBytes))
    return RecordStatus::BadMarker;

  if (!readBlock(in, payload, bytes, fileLen))
    return RecordStatus::Truncated;
  if (!readBlock(in, marker, MarkerBytes, fileLen))
    return RecordStatus::Truncated;
  if (unpackInt(marker.data(), endian) != bytes)
    return RecordStatus::BadMarker;

  if (length != nullptr)
    *length = bytes;
  return RecordStatus::Ok;
}

// Read one record of @a count float32 values into axis @a axis of
// @a positions, where value i goes to atom indexes[i] (or i if there is no
// index list).
RecordStatus readAxis(std::istream& in, char endian, std::streamoff fileLen,
                      std::vector<char>& payload, std::size_t count, int axis,
                      const std::vector<int>* indexes,
                      Array<Vector3>& positions)
{
  // Record markers are int32, so no valid record exceeds INT32_MAX bytes;
  // checking before the multiply keeps count * 4 from wrapping.
  if (count > static_cast<std::size_t>(INT32_MAX / 4))
    return RecordStatus::BadMarker;
  const RecordStatus status =
    readRecord(in, endian, fileLen, payload, static_cast<int>(count * 4));
  if (status != RecordStatus::Ok)
    return status;
  for (std::size_t i = 0; i < count; ++i) {
    const std::size_t atom =
      indexes != nullptr ? static_cast<std::size_t>((*indexes)[i]) : i;
    positions[atom][axis] = unpack<float>(payload.data() + 4 * i, endian);
  }
  return RecordStatus::Ok;
}

/**
 * Convert the six doubles of a CHARMM unit-cell record (A, gamma, B, beta,
 * alpha, C) into a cell. The angles are cosines in CHARMM and many NAMD files
 * and degrees otherwise; UnitCell wants radians.
 */
std::unique_ptr<UnitCell> cellFromRecord(double uc[6])
{
  if (uc[1] >= -1.0 && uc[1] <= 1.0 && uc[3] >= -1.0 && uc[3] <= 1.0 &&
      uc[4] >= -1.0 && uc[4] <= 1.0) {
    // This formulation improves rounding behavior for orthogonal cells
    // so that the angles end up at precisely 90 degrees, unlike acos()
    uc[4] = M_PI_2 - asin(uc[4]); /* cosBC */
    uc[3] = M_PI_2 - asin(uc[3]); /* cosAC */
    uc[1] = M_PI_2 - asin(uc[1]); /* cosAB */
  } else {
    uc[4] *= DEG_TO_RAD_D;
    uc[3] *= DEG_TO_RAD_D;
    uc[1] *= DEG_TO_RAD_D;
  }
  return std::make_unique<UnitCell>(uc[0], uc[2], uc[5], uc[4], uc[3], uc[1]);
}

/**
 * Read one frame: [unit cell], X, Y, Z, [fourth dimension].
 *
 * @param first True for frame 0, which holds every atom even when some are
 * fixed and is the only one whose unit cell is decoded (Molecule holds a
 * single cell). Later frames hold only the free atoms.
 * @param positions On entry, empty or the positions to start from (the first
 * frame's, so fixed atoms stay put); on success the frame's positions.
 * @param cell Receives the unit cell record of the first frame, if any.
 */
RecordStatus readFrame(std::istream& in, const DcdLayout& layout,
                       std::streamoff fileLen, std::vector<char>& payload,
                       bool first, Array<Vector3>& positions,
                       std::unique_ptr<UnitCell>& cell)
{
  RecordStatus status;
  if (layout.hasCell) {
    status = readRecord(in, layout.endian, fileLen, payload, 48);
    if (status != RecordStatus::Ok)
      return status;
    if (first) {
      double uc[6];
      for (int i = 0; i < 6; ++i)
        uc[i] = unpack<double>(payload.data() + 8 * i, layout.endian);
      // All three lengths zero means the file has no cell (VMD does the
      // same); that is checked on the lengths, before any angle conversion.
      if (uc[0] != 0.0 || uc[2] != 0.0 || uc[5] != 0.0)
        cell = cellFromRecord(uc);
    }
  }

  const bool freeOnly = !first && layout.hasFixedAtoms;
  const std::size_t count = freeOnly
                              ? layout.freeIndexes.size()
                              : static_cast<std::size_t>(layout.numAtoms);
  positions.resize(static_cast<std::size_t>(layout.numAtoms), Vector3::Zero());
  for (int axis = 0; axis < 3; ++axis) {
    status = readAxis(in, layout.endian, fileLen, payload, count, axis,
                      freeOnly ? &layout.freeIndexes : nullptr, positions);
    if (status != RecordStatus::Ok)
      return status;
  }

  if (layout.hasFourDims)
    return readRecord(in, layout.endian, fileLen, payload, -1);
  return RecordStatus::Ok;
}

std::string recordError(RecordStatus status, const std::string& what)
{
  if (status == RecordStatus::BadMarker)
    return "DCD " + what + " has inconsistent record length markers.";
  return "Unexpected end of DCD file.";
}

} // namespace

bool DcdFormat::read(std::istream& inStream, Core::Molecule& mol)
{
  std::vector<char> buff(BUFSIZ);
  DcdLayout layout;

  // Determining size of file. A failed tellg() is -1, which is not a length.
  inStream.seekg(0, inStream.end);
  const std::streamoff fileLen = inStream.tellg();
  inStream.seekg(0, inStream.beg);
  if (fileLen < 0 || !inStream.good()) {
    appendError("Unable to determine the size of the DCD file.");
    return false;
  }

  // Reading magic number: the byte order is whichever one makes it 84.
  if (!readBlock(inStream, buff, MarkerBytes, fileLen)) {
    appendError("Unexpected end of DCD file.");
    return false;
  }
  if (unpackInt(buff.data(), '>') == DCD_MAGIC) {
    layout.endian = '>';
  } else if (unpackInt(buff.data(), '<') == DCD_MAGIC) {
    layout.endian = '<';
  } else {
    appendError("File does not start with magic number 84.");
    return false;
  }
  const char endian = layout.endian;

  // CORD plus the rest of the 84 byte header, and its trailing marker. The
  // payload stays raw bytes in the file's byte order, so every field is
  // decoded through the endian-aware path below, never by a pointer cast.
  if (!readBlock(inStream, buff, DCD_MAGIC, fileLen)) {
    appendError("Unexpected end of DCD file.");
    return false;
  }
  const char* raw = buff.data();
  if (raw[0] != 'C' || raw[1] != 'O' || raw[2] != 'R' || raw[3] != 'D') {
    appendError("Keyword CORD not found.");
    return false;
  }
  // (The trailing marker is checked after the fields are decoded, since
  // reading it reuses the buffer.)

  // Determining whether the trajectory file is from CHARMM or not: a nonzero
  // version number in the last header word. Only CHARMM files can carry the
  // unit-cell and fourth-dimension records.
  const bool charmm = unpackInt(raw + 80, endian) != 0;
  if (charmm) {
    layout.hasCell = unpackInt(raw + 44, endian) != 0;
    layout.hasFourDims = unpackInt(raw + 48, endian) == 1;
  }

  // First integration step written, and how many steps apart the frames are.
  const int ISTART = unpackInt(raw + 8, endian);
  const int NSAVC = unpackInt(raw + 12, endian);

  // number of fixed atoms
  const int numFixed = unpackInt(raw + 36, endian);

  // DELTA (timestep) is stored as a double, in picoseconds, with X-PLOR, but
  // as a float in AKMA time units with CHARMM. Both end up in picoseconds.
  double DELTA = 0.0;
  if (charmm)
    DELTA =
      static_cast<double>(unpack<float>(raw + 40, endian)) * AkmaToPicoseconds;
  else
    DELTA = unpack<double>(raw + 40, endian);

  // DELTA is the integration timestep, but only every NSAVC-th step was
  // written, so that -- not DELTA -- is how far apart the frames in this file
  // are. A file that claims no saving frequency gets one step, which at least
  // keeps successive frames at distinct times.
  const double frameInterval = DELTA * (NSAVC > 0 ? NSAVC : 1);
  const double startTime = DELTA * (ISTART > 0 ? ISTART : 0);

  std::vector<char> marker(MarkerBytes);
  if (!readBlock(inStream, marker, MarkerBytes, fileLen)) {
    appendError("Unexpected end of DCD file.");
    return false;
  }
  if (unpackInt(marker.data(), endian) != DCD_MAGIC) {
    appendError("DCD header has inconsistent record length markers.");
    return false;
  }

  // Title record: NTITLE, then NTITLE 80-character strings.
  int titleBytes = 0;
  RecordStatus status =
    readRecord(inStream, endian, fileLen, buff, -1, &titleBytes);
  if (status != RecordStatus::Ok) {
    appendError(recordError(status, "title block"));
    return false;
  }
  if (titleBytes < 4 || ((titleBytes - 4) % 80) != 0) {
    appendError("Block size must be 4 plus a multiple of 80.");
    return false;
  }
  // NTITLE comes from the file, so check it against the block that holds the
  // strings rather than trusting it.
  const int NTITLE = unpackInt(buff.data(), endian);
  if (NTITLE < 0 || NTITLE > (titleBytes - 4) / 80) {
    appendError("DCD file declares an implausible title count.");
    return false;
  }

  // NATOMS record
  status = readRecord(inStream, endian, fileLen, buff, 4);
  if (status != RecordStatus::Ok) {
    appendError(recordError(status, "atom count"));
    return false;
  }
  layout.numAtoms = unpackInt(buff.data(), endian);

  // NATOMS is file-derived and sizes arrays below. Each atom needs at least a
  // float per axis, so a count larger than the file cannot be real.
  // (Three floats, 12 bytes, in the first frame alone.)
  if (layout.numAtoms < 0 || layout.numAtoms > fileLen / 12) {
    appendError("DCD file declares an implausible atom count.");
    return false;
  }

  if (numFixed != 0) {
    if (numFixed < 0 || numFixed > layout.numAtoms) {
      appendError("DCD file declares an implausible fixed atom count.");
      return false;
    }
    // One-based indices of the atoms that move in every frame after the first.
    const int numFree = layout.numAtoms - numFixed;
    layout.hasFixedAtoms = true;
    if (numFree > INT32_MAX / 4) {
      appendError("DCD file declares an implausible free atom count.");
      return false;
    }
    status = readRecord(inStream, endian, fileLen, buff, numFree * 4);
    if (status != RecordStatus::Ok) {
      appendError(recordError(status, "free atom index block"));
      return false;
    }
    layout.freeIndexes.resize(static_cast<std::size_t>(numFree));
    for (int i = 0; i < numFree; ++i) {
      const int index = unpackInt(buff.data() + 4 * i, endian);
      if (index < 1 || index > layout.numAtoms) {
        appendError("DCD file has a free atom index out of range.");
        return false;
      }
      layout.freeIndexes[static_cast<std::size_t>(i)] = index - 1;
    }
  }

  // The first frame. A cell is stored per frame in the file, but Molecule
  // holds one, so only the first frame's is kept.
  Array<Vector3> positions;
  std::unique_ptr<UnitCell> cell;
  status = readFrame(inStream, layout, fileLen, buff, true, positions, cell);
  if (status != RecordStatus::Ok) {
    appendError(recordError(status, "frame"));
    return false;
  }
  if (cell != nullptr) {
    if (!cell->isRegular()) {
      appendError("cell matrix is singular");
      return false;
    }
    mol.setUnitCell(cell.release());
  }

  // Every atom is its own custom element ("Atom <index>"). The element value
  // wraps around if there are more atoms than custom slots.
  Molecule::CustomElementMap elementMap;
  for (int i = 0; i < layout.numAtoms; ++i) {
    const auto element = static_cast<unsigned char>(CustomElementMin + i);
    Atom newAtom = mol.addAtom(element);
    newAtom.setPosition3d(positions[static_cast<std::size_t>(i)]);
    elementMap.emplace(element, "Atom " + to_string(i));
  }
  if (layout.numAtoms > 0)
    mol.setCustomElementMap(elementMap);

  mol.setTimeStep(startTime, 0);
  mol.setCoordinate3d(mol.atomPositions3d(), 0);

  // Do we have an animation? Frames run to the end of the file. Fixed atoms
  // keep the first frame's positions, so only then does a later frame start
  // from them; otherwise every position is overwritten.
  int coordSet = 1;
  while (true) {
    const std::streampos here = inStream.tellg();
    if (here == std::streampos(-1) ||
        static_cast<std::streamoff>(here) >= fileLen)
      break;

    Array<Vector3> framePositions;
    if (layout.hasFixedAtoms)
      framePositions = positions;
    status =
      readFrame(inStream, layout, fileLen, buff, false, framePositions, cell);
    if (status == RecordStatus::Truncated) {
      // Keep the complete frames; a partly written last frame is common when
      // a simulation is still running or was killed.
      appendError("DCD file ends in the middle of frame " +
                  to_string(coordSet) + "; the incomplete frame was ignored.");
      break;
    }
    if (status == RecordStatus::BadMarker) {
      appendError("DCD frame " + to_string(coordSet) +
                  " has inconsistent record length markers; it and any later "
                  "frames were ignored.");
      break;
    }

    mol.setTimeStep(startTime + frameInterval * coordSet, coordSet);
    mol.setCoordinate3d(framePositions, coordSet++);
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
