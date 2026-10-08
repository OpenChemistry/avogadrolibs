/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "iotests.h"

#include <gtest/gtest.h>

#include <avogadro/core/molecule.h>
#include <avogadro/core/unitcell.h>
#include <avogadro/core/vector.h>
#include <avogadro/io/dcdformat.h>

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

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

using Frame = std::vector<std::array<float, 3>>;

// Builds a DCD file in memory, in either byte order and either flavour, so the
// reader can be tested against layouts we have no real files for.
struct DcdBuilder
{
  bool bigEndian = false;
  bool charmm = true;      // CHARMM: float DELTA in AKMA; X-PLOR: double in ps
  bool extraBlock = false; // CHARMM unit-cell record before each frame
  bool fourDims = false;   // CHARMM fourth-dimension record after each frame
  double delta = 0.5;
  int istart = 0;
  int nsavc = 1;
  int natoms = 0;
  // 1-based indices of the atoms that move; empty means no fixed atoms.
  std::vector<int> freeIndexes;
  // Unit cell record contents: A, gamma, B, beta, alpha, C.
  std::array<double, 6> cell = { 10.0, 0.0, 10.0, 0.0, 0.0, 10.0 };
  // Frame 0 holds every atom; with fixed atoms, later frames hold only the
  // free ones.
  std::vector<Frame> frames;
  // If >= 0, add this to the trailing marker of frame 0's X record.
  int corruptXTrailer = -1;

  std::string out;

  void put32(int32_t value)
  {
    auto v = static_cast<uint32_t>(value);
    char b[4] = { static_cast<char>(v & 0xff),
                  static_cast<char>((v >> 8) & 0xff),
                  static_cast<char>((v >> 16) & 0xff),
                  static_cast<char>((v >> 24) & 0xff) };
    for (int i = 0; i < 4; ++i)
      out.push_back(b[bigEndian ? 3 - i : i]);
  }
  void putFloat(float value)
  {
    uint32_t v;
    std::memcpy(&v, &value, 4);
    put32(static_cast<int32_t>(v));
  }
  void putDouble(double value)
  {
    uint64_t v;
    std::memcpy(&v, &value, 8);
    for (int i = 0; i < 8; ++i) {
      int shift = bigEndian ? 8 * (7 - i) : 8 * i;
      out.push_back(static_cast<char>((v >> shift) & 0xff));
    }
  }

  void writeAxis(int axis, const Frame& frame, int trailerDelta)
  {
    put32(static_cast<int32_t>(frame.size() * 4));
    for (const auto& atom : frame)
      putFloat(atom[axis]);
    put32(static_cast<int32_t>(frame.size() * 4) + trailerDelta);
  }

  std::string build()
  {
    out.clear();
    put32(84);
    size_t start = out.size();
    out.append("CORD");
    put32(static_cast<int32_t>(frames.size())); // NSET
    put32(istart);
    put32(nsavc);
    for (int i = 0; i < 5; ++i)
      put32(0);
    put32(freeIndexes.empty()
            ? 0
            : natoms - static_cast<int32_t>(freeIndexes.size())); // NAMNF
    if (charmm)
      putFloat(static_cast<float>(delta));
    else
      putDouble(delta);
    // Bytes 44-47 are the extra-block flag, which an X-PLOR DELTA overlaps.
    if (charmm) {
      put32(extraBlock ? 1 : 0);
      put32(fourDims ? 1 : 0);
    } else {
      put32(0); // second half of the double is already written above
      out.resize(out.size() - 4);
      put32(0);
    }
    while (out.size() - start < 80)
      put32(0);
    put32(charmm ? 24 : 0); // CHARMM version
    put32(84);

    put32(84); // title: NTITLE = 1
    put32(1);
    out.append(std::string(80, ' '));
    put32(84);

    put32(4);
    put32(natoms);
    put32(4);

    if (!freeIndexes.empty()) {
      put32(static_cast<int32_t>(freeIndexes.size() * 4));
      for (int i : freeIndexes)
        put32(i);
      put32(static_cast<int32_t>(freeIndexes.size() * 4));
    }

    for (size_t f = 0; f < frames.size(); ++f) {
      if (charmm && extraBlock) {
        put32(48);
        for (double v : cell)
          putDouble(v);
        put32(48);
      }
      writeAxis(0, frames[f],
                f == 0 && corruptXTrailer >= 0 ? corruptXTrailer : 0);
      writeAxis(1, frames[f], 0);
      writeAxis(2, frames[f], 0);
      if (charmm && fourDims) {
        put32(static_cast<int32_t>(frames[f].size() * 4));
        for (size_t i = 0; i < frames[f].size(); ++i)
          putFloat(-1.0f);
        put32(static_cast<int32_t>(frames[f].size() * 4));
      }
    }
    return out;
  }
};

// Atom i of frame f: distinct everywhere, so any mix-up is visible.
Frame syntheticFrame(int f, int natoms)
{
  Frame frame;
  for (int i = 0; i < natoms; ++i)
    frame.push_back({ static_cast<float>(i + 0.25 * f),
                      static_cast<float>(100 + 2 * i + f),
                      static_cast<float>(-5.5 * i - 0.125 * f - 1.0) });
  return frame;
}

DcdBuilder syntheticTrajectory(int natoms, int nframes)
{
  DcdBuilder b;
  b.natoms = natoms;
  for (int f = 0; f < nframes; ++f)
    b.frames.push_back(syntheticFrame(f, natoms));
  return b;
}

// Everything the reader reports, for comparing two reads of the same data.
void expectSameMolecule(const Molecule& a, const Molecule& b)
{
  ASSERT_EQ(a.atomCount(), b.atomCount());
  ASSERT_EQ(a.coordinate3dCount(), b.coordinate3dCount());
  for (size_t f = 0; f < a.coordinate3dCount(); ++f) {
    const auto pa = a.coordinate3d(f);
    const auto pb = b.coordinate3d(f);
    ASSERT_EQ(pa.size(), pb.size()) << "frame " << f;
    for (size_t i = 0; i < pa.size(); ++i)
      ASSERT_EQ(pa[i], pb[i]) << "frame " << f << " atom " << i;
    bool sa = false, sb = false;
    EXPECT_EQ(a.timeStep(static_cast<int>(f), sa),
              b.timeStep(static_cast<int>(f), sb));
    EXPECT_EQ(sa, sb);
  }
  ASSERT_EQ(a.unitCell() != nullptr, b.unitCell() != nullptr);
  if (a.unitCell() != nullptr) {
    EXPECT_NEAR(a.unitCell()->a(), b.unitCell()->a(), 1e-9);
    EXPECT_NEAR(a.unitCell()->b(), b.unitCell()->b(), 1e-9);
    EXPECT_NEAR(a.unitCell()->c(), b.unitCell()->c(), 1e-9);
    EXPECT_NEAR(a.unitCell()->alpha(), b.unitCell()->alpha(), 1e-9);
    EXPECT_NEAR(a.unitCell()->beta(), b.unitCell()->beta(), 1e-9);
    EXPECT_NEAR(a.unitCell()->gamma(), b.unitCell()->gamma(), 1e-9);
  }
}

// Check a molecule against the builder's frames (expanding fixed atoms).
void expectMatchesBuilder(const Molecule& mol, const DcdBuilder& b)
{
  ASSERT_EQ(mol.atomCount(), static_cast<size_t>(b.natoms));
  ASSERT_EQ(mol.coordinate3dCount(), b.frames.size());
  for (size_t f = 0; f < b.frames.size(); ++f) {
    auto pos = mol.coordinate3d(f);
    ASSERT_EQ(pos.size(), static_cast<size_t>(b.natoms)) << "frame " << f;
    // Expected: frame 0 everywhere; later frames overwrite the free atoms.
    std::vector<std::array<float, 3>> want = b.frames[0];
    for (size_t i = 0; f > 0 && i < b.frames[f].size(); ++i) {
      size_t atom =
        b.freeIndexes.empty() ? i : static_cast<size_t>(b.freeIndexes[i] - 1);
      want[atom] = b.frames[f][i];
    }
    for (size_t i = 0; i < want.size(); ++i) {
      EXPECT_FLOAT_EQ(static_cast<float>(pos[i].x()), want[i][0])
        << "frame " << f << " atom " << i;
      EXPECT_FLOAT_EQ(static_cast<float>(pos[i].y()), want[i][1])
        << "frame " << f << " atom " << i;
      EXPECT_FLOAT_EQ(static_cast<float>(pos[i].z()), want[i][2])
        << "frame " << f << " atom " << i;
    }
  }
}

std::string villinPath()
{
  return std::string(AVOGADRO_DATA) + "/data/dcd/villin_N68H.dcd";
}

std::string readVillinBytes()
{
  std::ifstream in(villinPath(), std::ios::binary);
  return std::string((std::istreambuf_iterator<char>(in)),
                     std::istreambuf_iterator<char>());
}

void swapBytes(std::string& s, size_t pos, size_t width)
{
  std::reverse(s.begin() + static_cast<std::ptrdiff_t>(pos),
               s.begin() + static_cast<std::ptrdiff_t>(pos + width));
}

// Turn a little-endian DCD into the big-endian equivalent by walking its
// records: markers are 4-byte words; the header payload is words after CORD;
// the title payload is one word then text; the 48-byte cell record is doubles;
// every other payload (atom count, coordinates) is 4-byte words.
std::string byteSwapDcd(const std::string& in)
{
  std::string s = in;
  size_t pos = 0;
  int record = 0;
  while (pos + 4 <= s.size()) {
    uint32_t len;
    std::memcpy(&len, s.data() + pos, 4); // little-endian host assumed
    swapBytes(s, pos, 4);
    size_t payload = pos + 4;
    size_t width = 4;
    size_t first = payload;
    size_t count;
    if (record == 0) {
      first = payload + 4; // skip "CORD"
      count = (len - 4) / 4;
    } else if (record == 1) {
      count = 1; // NTITLE; the rest is text
    } else if (len == 48) {
      width = 8;
      count = 6;
    } else {
      count = len / 4;
    }
    for (size_t i = 0; i < count; ++i)
      swapBytes(s, first + i * width, width);
    swapBytes(s, payload + len, 4);
    pos = payload + len + 4;
    ++record;
  }
  return s;
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

TEST(DcdTest, timeStepsInPicoseconds)
{
  DcdFormat dcd;
  Molecule molecule;
  ASSERT_TRUE(dcd.readFile(
    std::string(AVOGADRO_DATA) + "/data/dcd/villin_N68H.dcd", molecule))
    << dcd.error();

  // This file is the CHARMM flavour, so its header DELTA is in AKMA time
  // units: 0.04090966 AKMA is the 2 fs integration step it was run with. Every
  // thousandth step was written (NSAVC = 1000), which puts the frames 2 ps
  // apart, and it starts at step zero.
  ASSERT_EQ(molecule.coordinate3dCount(), static_cast<size_t>(10));
  for (int i = 0; i < 10; ++i) {
    bool status = false;
    const double time = molecule.timeStep(i, status);
    EXPECT_TRUE(status) << "frame " << i << " has no timestep";
    EXPECT_NEAR(time, 2.0 * i, 1e-5) << "frame " << i;
  }
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

TEST(DcdTest, villinLaterFramesHaveEveryAtom)
{
  DcdFormat dcd;
  Molecule molecule;
  ASSERT_TRUE(dcd.readFile(villinPath(), molecule)) << dcd.error();
  ASSERT_EQ(molecule.coordinate3dCount(), static_cast<size_t>(10));

  // Reference values from an independent Python struct read of the file
  // (little-endian, float32): atom 0 of frame 1 and of frame 9.
  const struct
  {
    size_t frame;
    double x, y, z;
  } expected[] = {
    { 1, 24.51654624938965, 13.679356575012207, 19.174257278442383 },
    { 9, 25.10129737854004, 13.214531898498535, 18.47640037536621 }
  };
  for (size_t f = 0; f < 10; ++f) {
    auto pos = molecule.coordinate3d(f);
    ASSERT_EQ(pos.size(), static_cast<size_t>(8867)) << "frame " << f;
    size_t nonzero = 0;
    for (const auto& p : pos)
      if (p.squaredNorm() > 0.0)
        ++nonzero;
    EXPECT_GT(nonzero, static_cast<size_t>(8000)) << "frame " << f;
  }
  for (const auto& e : expected) {
    auto pos = molecule.coordinate3d(e.frame);
    EXPECT_NEAR(pos[0].x(), e.x, 1e-4) << "frame " << e.frame;
    EXPECT_NEAR(pos[0].y(), e.y, 1e-4) << "frame " << e.frame;
    EXPECT_NEAR(pos[0].z(), e.z, 1e-4) << "frame " << e.frame;
  }
}

// The file is CHARMM, little-endian, with the unit-cell record (cosines, all
// zero: a 49.163 x 45.981 x 38.869 orthogonal box), no fourth dimension and no
// fixed atoms.
TEST(DcdTest, villinUnitCell)
{
  DcdFormat dcd;
  Molecule molecule;
  ASSERT_TRUE(dcd.readFile(villinPath(), molecule)) << dcd.error();
  ASSERT_NE(molecule.unitCell(), nullptr);
  EXPECT_NEAR(molecule.unitCell()->a(), 49.163, 1e-9);
  EXPECT_NEAR(molecule.unitCell()->b(), 45.981, 1e-9);
  EXPECT_NEAR(molecule.unitCell()->c(), 38.869, 1e-9);
  EXPECT_NEAR(molecule.unitCell()->alpha(), M_PI_2, 1e-9);
  EXPECT_NEAR(molecule.unitCell()->beta(), M_PI_2, 1e-9);
  EXPECT_NEAR(molecule.unitCell()->gamma(), M_PI_2, 1e-9);
}

TEST(DcdTest, villinByteSwapped)
{
  const std::string original = readVillinBytes();
  ASSERT_FALSE(original.empty());
  const std::string swapped = byteSwapDcd(original);
  ASSERT_EQ(swapped.size(), original.size());
  ASSERT_NE(swapped, original);

  DcdFormat a, b;
  Molecule ma, mb;
  ASSERT_TRUE(a.readString(original, ma)) << a.error();
  ASSERT_TRUE(b.readString(swapped, mb)) << b.error();
  EXPECT_EQ(mb.coordinate3dCount(), static_cast<size_t>(10));
  expectSameMolecule(ma, mb);
}

TEST(DcdTest, syntheticByteOrdersAgree)
{
  Molecule readings[2];
  for (int big = 0; big < 2; ++big) {
    DcdBuilder b = syntheticTrajectory(5, 4);
    b.bigEndian = big == 1;
    b.extraBlock = true;
    b.nsavc = 10;
    b.istart = 20;
    b.cell = { 11.0, 0.0, 12.0, 0.0, 0.0, 13.0 };
    DcdFormat dcd;
    ASSERT_TRUE(dcd.readString(b.build(), readings[big])) << dcd.error();
    expectMatchesBuilder(readings[big], b);
  }
  expectSameMolecule(readings[0], readings[1]);
  bool ok = false;
  // CHARMM: delta 0.5 AKMA * 0.04888821 ps; frames 10 steps apart from step 20.
  EXPECT_NEAR(readings[1].timeStep(0, ok), 0.5 * 0.04888821 * 20, 1e-6);
  EXPECT_NEAR(readings[1].timeStep(3, ok), 0.5 * 0.04888821 * (20 + 30), 1e-6);
}

TEST(DcdTest, xplorDoubleDelta)
{
  for (int big = 0; big < 2; ++big) {
    DcdBuilder b = syntheticTrajectory(4, 3);
    b.bigEndian = big == 1;
    b.charmm = false;
    b.delta = 0.002; // ps already
    b.nsavc = 500;
    DcdFormat dcd;
    Molecule mol;
    ASSERT_TRUE(dcd.readString(b.build(), mol)) << dcd.error();
    expectMatchesBuilder(mol, b);
    EXPECT_EQ(mol.unitCell(), nullptr);
    bool ok = false;
    EXPECT_NEAR(mol.timeStep(2, ok), 2.0 * 500 * 0.002, 1e-9) << "big " << big;
    EXPECT_TRUE(ok);
  }
}

// With both optional records present a frame is cell, X, Y, Z, fourth
// dimension; reading the fourth dimension as the next frame's cell desyncs.
TEST(DcdTest, charmmExtraAndFourDims)
{
  for (int big = 0; big < 2; ++big) {
    DcdBuilder b = syntheticTrajectory(6, 4);
    b.bigEndian = big == 1;
    b.extraBlock = true;
    b.fourDims = true;
    DcdFormat dcd;
    Molecule mol;
    ASSERT_TRUE(dcd.readString(b.build(), mol)) << dcd.error();
    expectMatchesBuilder(mol, b);
    ASSERT_NE(mol.unitCell(), nullptr);
    EXPECT_NEAR(mol.unitCell()->a(), 10.0, 1e-9);
  }
}

TEST(DcdTest, charmmFourDimsWithoutCell)
{
  DcdBuilder b = syntheticTrajectory(3, 3);
  b.fourDims = true;
  DcdFormat dcd;
  Molecule mol;
  ASSERT_TRUE(dcd.readString(b.build(), mol)) << dcd.error();
  expectMatchesBuilder(mol, b);
  EXPECT_EQ(mol.unitCell(), nullptr);
}

TEST(DcdTest, fixedAtoms)
{
  for (int big = 0; big < 2; ++big) {
    // Atoms 2 and 4 (1-based) move; 1, 3 and 5 are fixed.
    DcdBuilder b;
    b.bigEndian = big == 1;
    b.natoms = 5;
    b.freeIndexes = { 2, 4 };
    b.extraBlock = true;
    b.fourDims = true;
    b.frames.push_back(syntheticFrame(0, 5));
    for (int f = 1; f < 4; ++f) {
      Frame frame;
      frame.push_back({ 1.0f * f, 2.0f * f, 3.0f * f });
      frame.push_back({ -1.0f * f, -2.0f * f, -3.0f * f });
      b.frames.push_back(frame);
    }
    DcdFormat dcd;
    Molecule mol;
    ASSERT_TRUE(dcd.readString(b.build(), mol)) << dcd.error();
    expectMatchesBuilder(mol, b);
    // Explicitly: fixed atom 0 never leaves its frame-0 position.
    for (size_t f = 1; f < 4; ++f)
      EXPECT_EQ(mol.coordinate3d(f)[0], mol.coordinate3d(0)[0]);
  }
}

TEST(DcdTest, freeIndexOutOfRangeRejected)
{
  for (int bad : { 0, 6, -1 }) {
    DcdBuilder b;
    b.natoms = 5;
    b.freeIndexes = { 2, bad };
    b.frames.push_back(syntheticFrame(0, 5));
    DcdFormat dcd;
    Molecule mol;
    EXPECT_FALSE(dcd.readString(b.build(), mol)) << "index " << bad;
    EXPECT_EQ(mol.atomCount(), static_cast<size_t>(0)) << "index " << bad;
  }
}

TEST(DcdTest, cellAnglesDegreesAndCosinesAgree)
{
  struct Case
  {
    double a, b, c, alpha, beta, gamma; // degrees
  };
  const Case cases[] = { { 10, 10, 15, 90, 90, 120 },
                         { 7.5, 9.25, 11.0, 80, 70, 100 } };
  for (const auto& k : cases) {
    const double deg = M_PI / 180.0;
    Molecule cosines, degrees;
    {
      DcdBuilder b = syntheticTrajectory(3, 2);
      b.extraBlock = true;
      b.cell = { k.a,
                 std::cos(k.gamma * deg),
                 k.b,
                 std::cos(k.beta * deg),
                 std::cos(k.alpha * deg),
                 k.c };
      DcdFormat dcd;
      ASSERT_TRUE(dcd.readString(b.build(), cosines)) << dcd.error();
    }
    {
      DcdBuilder b = syntheticTrajectory(3, 2);
      b.extraBlock = true;
      b.cell = { k.a, k.gamma, k.b, k.beta, k.alpha, k.c };
      DcdFormat dcd;
      ASSERT_TRUE(dcd.readString(b.build(), degrees)) << dcd.error();
    }
    for (const Molecule* m : { &cosines, &degrees }) {
      ASSERT_NE(m->unitCell(), nullptr);
      EXPECT_NEAR(m->unitCell()->a(), k.a, 1e-9);
      EXPECT_NEAR(m->unitCell()->b(), k.b, 1e-9);
      EXPECT_NEAR(m->unitCell()->c(), k.c, 1e-9);
      EXPECT_NEAR(m->unitCell()->alpha(), k.alpha * deg, 1e-9);
      EXPECT_NEAR(m->unitCell()->beta(), k.beta * deg, 1e-9);
      EXPECT_NEAR(m->unitCell()->gamma(), k.gamma * deg, 1e-9);
    }
    expectSameMolecule(cosines, degrees);
  }
}

TEST(DcdTest, recordMarkerMismatchRejected)
{
  DcdBuilder b = syntheticTrajectory(4, 2);
  b.corruptXTrailer = 4;
  DcdFormat dcd;
  Molecule mol;
  EXPECT_FALSE(dcd.readString(b.build(), mol));
  EXPECT_FALSE(dcd.error().empty());

  // A leading marker that disagrees with the expected cell size.
  DcdBuilder c = syntheticTrajectory(4, 2);
  c.extraBlock = true;
  std::string data = c.build();
  // Header 92 + title 88 + natoms 12 = 196: the cell record's leading marker.
  ASSERT_EQ(data[196], '\x30');
  data[196] = '\x28';
  DcdFormat dcd2;
  Molecule mol2;
  EXPECT_FALSE(dcd2.readString(data, mol2));
}

TEST(DcdTest, truncatedLastFrameDropsOnlyThatFrame)
{
  DcdBuilder b = syntheticTrajectory(4, 3);
  b.extraBlock = true;
  const std::string full = b.build();
  const size_t frameBytes = 56 + 3 * (8 + 4 * 4);
  ASSERT_EQ((full.size() - 196) % frameBytes, static_cast<size_t>(0));

  for (size_t cut : { size_t(1), size_t(4), size_t(30), frameBytes - 1 }) {
    DcdFormat dcd;
    Molecule mol;
    ASSERT_TRUE(dcd.readString(full.substr(0, full.size() - cut), mol))
      << "cut " << cut << ": " << dcd.error();
    EXPECT_EQ(mol.coordinate3dCount(), static_cast<size_t>(2)) << "cut " << cut;
    EXPECT_FALSE(dcd.error().empty()) << "cut " << cut;
    DcdBuilder expected = b;
    expected.frames.pop_back();
    expectMatchesBuilder(mol, expected);
  }

  // An exact frame boundary is not truncation.
  DcdFormat dcd;
  Molecule mol;
  ASSERT_TRUE(dcd.readString(full.substr(0, full.size() - frameBytes), mol));
  EXPECT_EQ(mol.coordinate3dCount(), static_cast<size_t>(2));
  EXPECT_TRUE(dcd.error().empty());
}

TEST(DcdTest, truncatedFirstFrameRejected)
{
  DcdBuilder b = syntheticTrajectory(4, 1);
  const std::string full = b.build();
  DcdFormat dcd;
  Molecule mol;
  EXPECT_FALSE(dcd.readString(full.substr(0, full.size() - 5), mol));
}
