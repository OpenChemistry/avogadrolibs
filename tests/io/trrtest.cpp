/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "iotests.h"

#include <gtest/gtest.h>

#include <avogadro/core/molecule.h>
#include <avogadro/core/unitcell.h>
#include <avogadro/core/vector.h>
#include <avogadro/io/trrformat.h>

#include <cmath>
#include <cstdint>
#include <fstream>
#include <iterator>
#include <limits>
#include <string>
#include <vector>

using Avogadro::Core::Molecule;
using Avogadro::Io::TrrFormat;

namespace {

const char* trrPath()
{
  static const std::string path =
    std::string(AVOGADRO_DATA) + "/data/trr/lysozyme_nvt.trr";
  return path.c_str();
}

void appendBE32(std::string& out, int32_t value)
{
  auto v = static_cast<uint32_t>(value);
  out.push_back(static_cast<char>((v >> 24) & 0xff));
  out.push_back(static_cast<char>((v >> 16) & 0xff));
  out.push_back(static_cast<char>((v >> 8) & 0xff));
  out.push_back(static_cast<char>(v & 0xff));
}

void appendBEFloat(std::string& out, uint32_t bits)
{
  appendBE32(out, static_cast<int32_t>(bits));
}

/**
 * A big-endian single precision TRR with no box, @a bits holding the raw
 * IEEE 754 bit patterns of the coordinates (3 per atom, in nm).
 */
std::string singlePrecisionTrr(const std::vector<uint32_t>& bits)
{
  const int32_t natoms = static_cast<int32_t>(bits.size() / 3);
  std::string data;
  appendBE32(data, 1993); // GROMACS magic
  appendBE32(data, 13);
  appendBE32(data, 12);
  data += "GMX_trn_file";
  // The 13 header ints: ten block sizes (only x is set), natoms, step, nre
  for (int32_t v : { 0, 0, 0, 0, 0, 0, 0, 3 * 4 * natoms, 0, 0, natoms, 0, 0 })
    appendBE32(data, v);
  appendBEFloat(data, 0); // time (0.0f)
  appendBEFloat(data, 0); // lambda (0.0f)
  for (uint32_t b : bits)
    appendBEFloat(data, b);
  return data;
}

/**
 * A TRR prefix declaring a version string of @a slen0 bytes.
 *
 * The reader passes slen0 - 1 to a "%ds" unpack whose destination is a fixed
 * char[1000], so this is the field that used to drive a stack write.
 */
std::string headerWithStringLength(int32_t slen0)
{
  std::string data;
  appendBE32(data, 1993); // GROMACS magic
  appendBE32(data, slen0);
  appendBE32(data, slen0);
  return data;
}

} // namespace

TEST(TrrTest, readTrajectory)
{
  TrrFormat trr;
  Molecule molecule;
  ASSERT_TRUE(trr.readFile(trrPath(), molecule)) << trr.error();

  EXPECT_GT(molecule.atomCount(), static_cast<size_t>(0));
  EXPECT_GT(molecule.coordinate3dCount(), static_cast<size_t>(0));
}

TEST(TrrTest, readEmpty)
{
  TrrFormat trr;
  Molecule molecule;
  EXPECT_FALSE(trr.readString("", molecule));
  EXPECT_EQ(molecule.atomCount(), static_cast<size_t>(0));
}

TEST(TrrTest, readNotTrr)
{
  TrrFormat trr;
  Molecule molecule;
  EXPECT_FALSE(trr.readString("nowhere near a GROMACS trajectory", molecule));
  EXPECT_EQ(molecule.atomCount(), static_cast<size_t>(0));
}

// slen0 is read from the file and used as an unpack length into char[1000].
TEST(TrrTest, rejectsOversizedVersionString)
{
  for (int32_t slen0 : { 1001, 5000, 100000, 2147483647 }) {
    TrrFormat trr;
    Molecule molecule;
    EXPECT_FALSE(trr.readString(headerWithStringLength(slen0), molecule))
      << "slen0 " << slen0;
    EXPECT_EQ(molecule.atomCount(), static_cast<size_t>(0))
      << "slen0 " << slen0;
  }
}

TEST(TrrTest, rejectsNonPositiveVersionString)
{
  for (int32_t slen0 : { 0, -1, -2147483647 }) {
    TrrFormat trr;
    Molecule molecule;
    EXPECT_FALSE(trr.readString(headerWithStringLength(slen0), molecule))
      << "slen0 " << slen0;
  }
}

// A truncated header must fail rather than act on whatever the buffer held,
// and must terminate: the frame loop compares tellg() against the file length,
// and an exhausted stream reports -1, which never matches.
TEST(TrrTest, readTruncatedHeader)
{
  const std::string full = headerWithStringLength(13);
  for (size_t len = 0; len < full.size(); ++len) {
    TrrFormat trr;
    Molecule molecule;
    EXPECT_FALSE(trr.readString(full.substr(0, len), molecule))
      << "truncated to " << len << " bytes";
  }
}

TEST(TrrTest, readTruncatedTrajectory)
{
  TrrFormat reference;
  Molecule full;
  ASSERT_TRUE(reference.readFile(trrPath(), full));

  std::string contents;
  {
    std::ifstream in(trrPath(), std::ios::binary);
    ASSERT_TRUE(in.good());
    contents.assign((std::istreambuf_iterator<char>(in)),
                    std::istreambuf_iterator<char>());
  }
  ASSERT_FALSE(contents.empty());

  for (size_t denom : { 2, 3, 4, 8, 16, 64, 256 }) {
    TrrFormat trr;
    Molecule molecule;
    // The return value is not the point -- a prefix may hold a whole frame.
    // This must not crash, hang, or produce more atoms than the whole file.
    trr.readString(contents.substr(0, contents.size() / denom), molecule);
    EXPECT_LE(molecule.atomCount(), full.atomCount()) << "1/" << denom;
  }
}

// Small hand-built trajectories: a water molecule in a 1.5 nm box, with atom
// 0 moved 0.01 nm along x per step. isDouble() used to compute
// box_size / DIM * DIM, which is 72 rather than 8, so every double-precision
// file with a box was read as single precision.
TEST(TrrTest, readWaterVariants)
{
  struct Case
  {
    const char* file;
    size_t frames;
    double lastX; // Angstrom, atom 0 in the last coordinate set
  };
  for (const Case& c : { Case{ "water-float-xv.trr", 2, 0.1 },
                         Case{ "water-float-velocity-only-frame.trr", 2, 0.2 },
                         Case{ "water-double-xvf.trr", 2, 0.1 },
                         Case{ "water-float-little-endian.trr", 1, 0.0 },
                         Case{ "water-float-virial.trr", 1, 0.0 } }) {
    TrrFormat trr;
    Molecule molecule;
    ASSERT_TRUE(trr.readFile(std::string(AVOGADRO_DATA) + "/data/trr/" + c.file,
                             molecule))
      << c.file << ": " << trr.error();

    EXPECT_EQ(molecule.atomCount(), static_cast<size_t>(3)) << c.file;
    EXPECT_EQ(molecule.coordinate3dCount(), c.frames) << c.file;
    ASSERT_NE(molecule.unitCell(), nullptr) << c.file;
    EXPECT_NEAR(molecule.unitCell()->a(), 15.0, 1e-5) << c.file;
    EXPECT_NEAR(molecule.unitCell()->c(), 15.0, 1e-5) << c.file;

    // nm --> Angstrom
    const auto first = molecule.coordinate3d(0);
    EXPECT_NEAR(first[1].x(), 0.957, 1e-5) << c.file;
    EXPECT_NEAR(first[2].y(), 0.927, 1e-5) << c.file;
    // A frame with only velocities is no coordinate set, so the second set
    // of water-float-velocity-only-frame.trr is step 2.
    EXPECT_NEAR(molecule.coordinate3d(c.frames - 1)[0].x(), c.lastX, 1e-5)
      << c.file;
  }
}

namespace {

std::string readWaterFile(const char* name)
{
  std::ifstream in(std::string(AVOGADRO_DATA) + "/data/trr/" + name,
                   std::ios::binary);
  return std::string((std::istreambuf_iterator<char>(in)),
                     std::istreambuf_iterator<char>());
}

void setBE32(std::string& data, size_t offset, int32_t value)
{
  std::string bytes;
  appendBE32(bytes, value);
  data.replace(offset, 4, bytes);
}

// water-float-xv.trr holds two frames of this many bytes each
const size_t waterFrameSize = 192;

} // namespace

// Found by fuzzing: the version string length was bounds-checked only in the
// first frame, so a later frame could overflow the stack buffer it unpacks to.
TEST(TrrTest, rejectsOversizedVersionStringInLaterFrame)
{
  std::string data = readWaterFile("water-float-xv.trr");
  ASSERT_EQ(data.size(), 2 * waterFrameSize);
  for (int32_t slen0 : { 1001, 5000, 0, -1 }) {
    std::string bad = data;
    setBE32(bad, waterFrameSize + 4, slen0);
    TrrFormat trr;
    Molecule molecule;
    EXPECT_FALSE(trr.readString(bad, molecule)) << "slen0 " << slen0;
  }
}

// Later frames used to keep the first frame's header, because std::map::insert
// does not replace an existing key, so a changed atom count went unnoticed.
TEST(TrrTest, rejectsChangedAtomCountInLaterFrame)
{
  std::string data = readWaterFile("water-float-xv.trr");
  ASSERT_EQ(data.size(), 2 * waterFrameSize);
  // natoms is the 11th of the 13 header ints, which start at byte 24
  setBE32(data, waterFrameSize + 24 + 10 * 4, 2);
  TrrFormat trr;
  Molecule molecule;
  EXPECT_FALSE(trr.readString(data, molecule));
}

// Coordinates are decoded bit for bit: -0.0 keeps its sign and a denormal
// survives. The old struct-based decoder gave about -5.9e-39 for -0.0 and
// mangled denormals.
TEST(TrrTest, exactSinglePrecisionCoordinates)
{
  const std::vector<uint32_t> bits = {
    0x80000000u, // -0.0f
    0x3f800000u, // 1.0f
    0x00000001u, // smallest denormal
    0x00800000u, // FLT_MIN
    0xbf800000u, // -1.0f
    0x80000001u  // -smallest denormal
  };
  TrrFormat trr;
  Molecule molecule;
  ASSERT_TRUE(trr.readString(singlePrecisionTrr(bits), molecule))
    << trr.error();
  ASSERT_EQ(molecule.atomCount(), static_cast<size_t>(2));

  constexpr float tiny = std::numeric_limits<float>::denorm_min();
  const Avogadro::Vector3 a = molecule.atomPosition3d(0);
  const Avogadro::Vector3 b = molecule.atomPosition3d(1);
  EXPECT_EQ(a.x(), 0.0);
  EXPECT_TRUE(std::signbit(a.x()));
  EXPECT_EQ(a.y(), 10.0);
  // nm to Angstrom is a multiplication by 10 in single precision
  EXPECT_EQ(a.z(), static_cast<double>(tiny * 10.0f));
  EXPECT_GT(a.z(), 0.0);
  EXPECT_EQ(b.x(),
            static_cast<double>(std::numeric_limits<float>::min() * 10.0f));
  EXPECT_EQ(b.y(), -10.0);
  EXPECT_EQ(b.z(), static_cast<double>(-tiny * 10.0f));
}
