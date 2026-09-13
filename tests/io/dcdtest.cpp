/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "iotests.h"

#include <gtest/gtest.h>

#include <avogadro/core/molecule.h>
#include <avogadro/core/vector.h>
#include <avogadro/io/dcdformat.h>

#include <cstdint>
#include <cstring>
#include <fstream>
#include <iterator>
#include <string>

using Avogadro::Core::Molecule;
using Avogadro::Io::DcdFormat;

namespace {

// DCD stores big-endian integers when written on a big-endian host; the reader
// detects the order from the magic number. Build big-endian here, which is the
// order the reader tries first.
void appendBE32(std::string& out, int32_t value)
{
  auto v = static_cast<uint32_t>(value);
  out.push_back(static_cast<char>((v >> 24) & 0xff));
  out.push_back(static_cast<char>((v >> 16) & 0xff));
  out.push_back(static_cast<char>((v >> 8) & 0xff));
  out.push_back(static_cast<char>(v & 0xff));
}

/**
 * A minimal DCD header up to and including NTITLE.
 *
 * @param ntitle The declared number of 80-character title records. The reader
 * multiplies this by 80 to size the remarks block, so it is the field that
 * used to drive a write past a fixed 8KB stack buffer.
 */
std::string headerWithNtitle(int32_t ntitle)
{
  std::string data;
  appendBE32(data, 84); // magic

  char raw[84] = {};
  std::memcpy(raw, "CORD", 4);
  // raw+36 is NAMNF (fixed atoms) and raw+80 marks a CHARMM file; leaving both
  // zero takes the plain X-PLOR path.
  data.append(raw, sizeof(raw));

  appendBE32(data, 84); // trailing magic
  appendBE32(data, 84); // block size, must be 4 plus a multiple of 80
  appendBE32(data, ntitle);
  return data;
}

} // namespace

TEST(DcdTest, readTrajectory)
{
  DcdFormat dcd;
  Molecule molecule;
  ASSERT_TRUE(dcd.readFile(
    std::string(AVOGADRO_DATA) + "/data/dcd/villin_N68H.dcd", molecule))
    << dcd.error();

  EXPECT_EQ(molecule.atomCount(), static_cast<size_t>(8867));
  // A trajectory, so every frame should have been picked up.
  EXPECT_EQ(molecule.coordinate3dCount(), static_cast<size_t>(10));

  // Spot check the first atom of the first frame.
  ASSERT_GE(molecule.atomPositions3d().size(), static_cast<size_t>(1));
  const auto first = molecule.atomPositions3d()[0];
  EXPECT_NEAR(first.x(), 24.8987, 1e-3);
  EXPECT_NEAR(first.y(), 13.5501, 1e-3);
  EXPECT_NEAR(first.z(), 20.0539, 1e-3);
}

TEST(DcdTest, readEmpty)
{
  DcdFormat dcd;
  Molecule molecule;
  EXPECT_FALSE(dcd.readString("", molecule));
  EXPECT_EQ(molecule.atomCount(), static_cast<size_t>(0));
}

TEST(DcdTest, readNotDcd)
{
  DcdFormat dcd;
  Molecule molecule;
  EXPECT_FALSE(dcd.readString("this is plainly not a trajectory", molecule));
  EXPECT_EQ(molecule.atomCount(), static_cast<size_t>(0));
}

// NTITLE is read from the file and multiplied by 80 to size the remarks block.
// That length was passed to istream::read() against a fixed char[BUFSIZ], so
// any NTITLE above 102 wrote past it and down the stack. These must be
// rejected, not merely survived.
TEST(DcdTest, rejectsOversizedTitleBlock)
{
  for (int32_t ntitle : { 200, 1000, 1000000, 26843546, 2147483647 }) {
    DcdFormat dcd;
    Molecule molecule;
    EXPECT_FALSE(dcd.readString(headerWithNtitle(ntitle), molecule))
      << "NTITLE " << ntitle;
    EXPECT_EQ(molecule.atomCount(), static_cast<size_t>(0))
      << "NTITLE " << ntitle;
  }
}

TEST(DcdTest, rejectsNegativeTitleCount)
{
  for (int32_t ntitle : { -1, -80, -2147483647 }) {
    DcdFormat dcd;
    Molecule molecule;
    EXPECT_FALSE(dcd.readString(headerWithNtitle(ntitle), molecule))
      << "NTITLE " << ntitle;
  }
}

// Every field a DCD reader acts on comes from the file, so a header that stops
// partway must fail rather than carry on with whatever the buffer held.
TEST(DcdTest, readTruncatedHeader)
{
  const std::string full = headerWithNtitle(1);
  for (size_t len = 0; len < full.size(); ++len) {
    DcdFormat dcd;
    Molecule molecule;
    EXPECT_FALSE(dcd.readString(full.substr(0, len), molecule))
      << "truncated to " << len << " bytes";
    EXPECT_EQ(molecule.atomCount(), static_cast<size_t>(0))
      << "truncated to " << len << " bytes";
  }
}

// The same, against the real file: cutting a valid trajectory at any point
// must fail cleanly rather than read past the end of a block.
TEST(DcdTest, readTruncatedTrajectory)
{
  DcdFormat reference;
  Molecule full;
  ASSERT_TRUE(reference.readFile(
    std::string(AVOGADRO_DATA) + "/data/dcd/villin_N68H.dcd", full));

  std::string contents;
  {
    std::ifstream in(std::string(AVOGADRO_DATA) + "/data/dcd/villin_N68H.dcd",
                     std::ios::binary);
    ASSERT_TRUE(in.good());
    contents.assign((std::istreambuf_iterator<char>(in)),
                    std::istreambuf_iterator<char>());
  }
  ASSERT_FALSE(contents.empty());

  // A spread of cut points rather than every offset, to keep the test quick.
  for (size_t denom : { 2, 3, 4, 8, 16, 64, 256 }) {
    DcdFormat dcd;
    Molecule molecule;
    // No expectation on the return value -- a prefix may hold a whole frame.
    // The point is that it must not crash or invent atoms out of nothing.
    dcd.readString(contents.substr(0, contents.size() / denom), molecule);
    EXPECT_LE(molecule.atomCount(), full.atomCount()) << "1/" << denom;
  }
}
