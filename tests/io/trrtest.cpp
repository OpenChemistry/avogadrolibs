/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "iotests.h"

#include <gtest/gtest.h>

#include <avogadro/core/molecule.h>
#include <avogadro/core/vector.h>
#include <avogadro/io/trrformat.h>

#include <cstdint>
#include <fstream>
#include <iterator>
#include <string>

using Avogadro::Core::Molecule;
using Avogadro::Io::TrrFormat;

namespace {

const char* trrPath()
{
  static const std::string path =
    std::string(AVOGADRO_DATA) + "/data/lysozyme_nvt.trr";
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
