/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

// Real proteins through the cartoon tessellation. The files come from
// avogadrodata (data/pdb); a test is skipped if its file is missing, so a
// checkout of avogadrodata older than the 6VXX/1PGA/4HHB commit still passes.
//
// The Cartoons plugin is a Qt plugin and cannot be linked here, so the
// C-alpha trace is built the way Cartoons::getBackboneByResidues() does it:
// non-heterogen residues with both CA and O, and a new curve whenever the
// chain, the residue numbering or a 6 A step breaks the trace. (The plugin
// also splits by bonded component; chain id plays that role here.)

#include <gtest/gtest.h>

#include "legacyspline.h"

#include <cartoondetail.h>

#include <avogadro/core/molecule.h>
#include <avogadro/core/residue.h>
#include <avogadro/core/vector.h>
#include <avogadro/io/pdbformat.h>
#include <avogadro/rendering/beziergeometry.h>
#include <avogadro/rendering/bsplinegeometry.h>
#include <avogadro/rendering/cartoongeometry.h>

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <filesystem>
#include <map>
#include <string>
#include <vector>

using Avogadro::Vector3f;
using Avogadro::Vector3ub;
using Avogadro::Core::Molecule;
using Avogadro::Core::Residue;
using Avogadro::Io::PdbFormat;
using Avogadro::QtPlugins::CartoonResidueCounts;
using Avogadro::QtPlugins::chooseCartoonDetailLevel;
using Avogadro::QtPlugins::kCartoonDetailLevels;
using Avogadro::Rendering::BezierGeometry;
using Avogadro::Rendering::BSplineGeometry;
using Avogadro::Rendering::Cartoon;
using Avogadro::Rendering::ColorNormalVertex;

namespace {

struct Chain
{
  std::vector<Vector3f> pos;
  std::vector<Residue::SecondaryStructure> ss;
};

struct Backbone
{
  std::vector<Chain> chains;
  size_t residues() const
  {
    size_t n = 0;
    for (const auto& c : chains)
      n += c.pos.size();
    return n;
  }
};

bool loadBackbone(const std::string& name, Backbone& result)
{
  const std::filesystem::path path =
    std::filesystem::path(AVOGADRO_DATA) / "data" / "pdb" / (name + ".pdb");
  if (!std::filesystem::exists(path))
    return false;
  Molecule molecule;
  PdbFormat pdb;
  if (!pdb.readFile(path.string(), molecule))
    return false;

  struct State
  {
    bool started = false;
    char chain = '\0';
    size_t residueId = 0;
    Vector3f position = Vector3f::Zero();
    size_t group = 0;
  };
  std::map<char, State> previous;
  std::map<char, size_t> groupOfChain;
  for (const auto& residue : molecule.residues()) {
    if (residue.isHeterogen())
      continue;
    auto ca = residue.atomByName("CA");
    auto o = residue.atomByName("O");
    if (!ca.isValid() || !o.isValid())
      continue;
    const Vector3f p = ca.position3d().cast<float>();
    State& s = previous[residue.chainId()];
    if (!s.started || residue.residueId() <= s.residueId ||
        (p - s.position).norm() > 6.0f) {
      result.chains.emplace_back();
      s.group = result.chains.size() - 1;
    }
    s.started = true;
    s.residueId = residue.residueId();
    s.position = p;
    result.chains[s.group].pos.push_back(p);
    result.chains[s.group].ss.push_back(residue.secondaryStructure());
  }
  return true;
}

Vector3ub idColor(size_t id)
{
  return Vector3ub(static_cast<unsigned char>(id & 255),
                   static_cast<unsigned char>((id >> 8) & 255),
                   static_cast<unsigned char>((id >> 16) & 255));
}

size_t colorId(const Vector3ub& c)
{
  return static_cast<size_t>(c[0]) | static_cast<size_t>(c[1]) << 8 |
         static_cast<size_t>(c[2]) << 16;
}

struct Rings
{
  std::vector<Vector3f> centre;
  std::vector<size_t> owner;
};

Rings rings(const std::vector<ColorNormalVertex>& v, size_t sides)
{
  Rings r;
  for (size_t base = 0; base + sides <= v.size(); base += sides) {
    Vector3f c = Vector3f::Zero();
    for (size_t j = 0; j < sides; ++j)
      c += v[base + j].vertex;
    r.centre.push_back(c / static_cast<float>(sides));
    r.owner.push_back(colorId(v[base].color));
  }
  return r;
}

struct StepStats
{
  float max = 0.0f, median = 0.0f;
  size_t reversals = 0;
};

StepStats steps(const std::vector<Vector3f>& p)
{
  std::vector<float> d;
  std::vector<Vector3f> s;
  for (size_t i = 1; i < p.size(); ++i) {
    Vector3f step = p[i] - p[i - 1];
    if (step.norm() < 1e-6f)
      continue;
    d.push_back(step.norm());
    s.push_back(step);
  }
  StepStats r;
  if (d.empty())
    return r;
  r.max = *std::max_element(d.begin(), d.end());
  std::sort(d.begin(), d.end());
  r.median = d[d.size() / 2];
  for (size_t i = 1; i < s.size(); ++i)
    if (s[i].dot(s[i - 1]) < 0.0f)
      ++r.reversals;
  return r;
}

const char* const kProteins[] = {
  "1CRN", "1PGA", "4HHB", "6VXX", "1FDT", "1MYK"
};

} // namespace

TEST(CartoonProteinsTest, tessellationIsFiniteAndCountedAtEveryLevel)
{
  std::vector<std::string> missing;
  for (const char* name : kProteins) {
    Backbone bb;
    if (!loadBackbone(name, bb)) {
      missing.push_back(name);
      continue;
    }
    ASSERT_GT(bb.residues(), 40u) << name;
    CartoonResidueCounts counts;
    counts.cartoon = bb.residues();
    const size_t chosen = chooseCartoonDetailLevel(counts);
    EXPECT_EQ(chosen, 0u) << name << " is small enough for full detail";

    for (const auto& level : kCartoonDetailLevels) {
      size_t totalVertices = 0;
      for (const auto& chain : bb.chains) {
        const size_t n = chain.pos.size();
        Cartoon cartoon(0.2f, 1.5f);
        for (size_t i = 0; i < n; ++i)
          cartoon.addPoint(chain.pos[i], idColor(i), 0, i, chain.ss[i]);
        cartoon.setSegmentsPerResidue(level.segments);
        cartoon.setSides(level.sides);
        std::vector<ColorNormalVertex> v;
        std::vector<unsigned int> idx;
        cartoon.tessellate(0, v, idx);
        if (n < 2) {
          EXPECT_TRUE(v.empty()) << name;
          continue;
        }
        // a ring at every sample of the n segments (including both ends);
        // rings are only repeated where the colour changes
        const size_t frames = n * level.segments + 1;
        EXPECT_GE(v.size(), frames * level.sides) << name << " n=" << n;
        EXPECT_LE(v.size(), (frames + n - 1) * level.sides)
          << name << " n=" << n;
        EXPECT_EQ(idx.size(), (frames - 1) * level.sides * 6) << name;
        for (const auto& x : v) {
          ASSERT_TRUE(x.vertex.allFinite()) << name;
          ASSERT_TRUE(x.normal.allFinite()) << name;
        }
        for (unsigned int i : idx)
          ASSERT_LT(i, v.size()) << name;
        totalVertices += v.size();
      }
      std::printf("%-5s %6zu residues %3zu curves  %2zu x %2zu: %9zu "
                  "vertices (%.1f MB)\n",
                  name, bb.residues(), bb.chains.size(), level.segments,
                  level.sides, totalVertices,
                  totalVertices * sizeof(ColorNormalVertex) / 1.0e6);
    }
  }
  if (!missing.empty()) {
    std::string list;
    for (const auto& m : missing)
      list += " " + m;
    if (missing.size() == sizeof(kProteins) / sizeof(kProteins[0])) {
      GTEST_SKIP() << "no protein files in avogadrodata:" << list;
    }
    std::printf("skipped (not in avogadrodata):%s\n", list.c_str());
  }
}

TEST(CartoonProteinsTest, curveIsContinuousAndAligned)
{
  std::vector<std::string> missing;
  for (const char* name : kProteins) {
    Backbone bb;
    if (!loadBackbone(name, bb)) {
      missing.push_back(name);
      continue;
    }
    float worstRatio = 0.0f, worstOldRatio = 0.0f, worstExcess = 0.0f;
    size_t reversals = 0, oldReversals = 0, rows = 0, exact = 0;
    for (const auto& chain : bb.chains) {
      const size_t n = chain.pos.size();
      if (n < 2)
        continue;
      BSplineGeometry g(false);
      for (size_t i = 0; i < n; ++i)
        g.addPoint(chain.pos[i], idColor(i), 0.1f, 0, i);
      std::vector<ColorNormalVertex> v;
      std::vector<unsigned int> idx;
      g.tessellate(0, v, idx);
      const Rings r = rings(v, 12);
      const StepStats now = steps(r.centre);
      reversals += now.reversals;
      // A segment's speed is at most the longer of its two chords per unit
      // of f, so no step can exceed that over 15 samples; a jump can.
      float maxChord = 0.0f;
      for (size_t i = 1; i < n; ++i)
        maxChord = std::max(maxChord, (chain.pos[i] - chain.pos[i - 1]).norm());
      const float bound = maxChord / 15.0f;
      worstRatio = std::max(worstRatio, now.max / bound);

      size_t previousOwner = 0;
      for (size_t i = 0; i < r.centre.size(); ++i) {
        ASSERT_LT(r.owner[i], n) << name;
        EXPECT_GE(r.owner[i], previousOwner) << name;
        previousOwner = r.owner[i];
        size_t nearest = 0;
        for (size_t m = 1; m < n; ++m)
          if ((chain.pos[m] - r.centre[i]).squaredNorm() <
              (chain.pos[nearest] - r.centre[i]).squaredNorm())
            nearest = m;
        const float excess = (chain.pos[r.owner[i]] - r.centre[i]).norm() -
                             (chain.pos[nearest] - r.centre[i]).norm();
        worstExcess = std::max(worstExcess, excess);
        exact += nearest == r.owner[i];
        ++rows;
      }

      std::vector<Vector3f> legacy;
      for (const auto& s : LegacySpline::samples(chain.pos))
        legacy.push_back(s.pos);
      if (legacy.size() > 30) {
        const StepStats old = steps(legacy);
        worstOldRatio = std::max(worstOldRatio, old.max / bound);
        oldReversals += old.reversals;
      }
    }
    std::printf("%-5s largest step / (longest chord / 15): new %.2f (%zu "
                "reversals), old %.2f "
                "(%zu reversals); owner is nearest CA for %zu of %zu rings, "
                "worst excess %.3f A\n",
                name, worstRatio, reversals, worstOldRatio, oldReversals, exact,
                rows, worstExcess);
    EXPECT_LE(worstRatio, 1.0f + 1e-3f) << name;
    EXPECT_EQ(reversals, 0u) << name;
    EXPECT_LT(worstExcess, 1.0f) << name;
  }
  if (!missing.empty()) {
    std::string list;
    for (const auto& m : missing)
      list += " " + m;
    if (missing.size() == sizeof(kProteins) / sizeof(kProteins[0])) {
      GTEST_SKIP() << "no protein files in avogadrodata:" << list;
    }
    std::printf("skipped (not in avogadrodata):%s\n", list.c_str());
  }
}

TEST(CartoonProteinsTest, ropeIsFiniteContinuousAndReachesTheTermini)
{
  std::vector<std::string> missing;
  for (const char* name : kProteins) {
    Backbone bb;
    if (!loadBackbone(name, bb)) {
      missing.push_back(name);
      continue;
    }
    float worst = 0.0f;
    size_t reversals = 0;
    for (const auto& chain : bb.chains) {
      const size_t n = chain.pos.size();
      if (n < 2)
        continue;
      BezierGeometry g;
      for (size_t i = 0; i < n; ++i)
        g.addPoint(chain.pos[i], idColor(i), 0.1f, 0, i);
      std::vector<ColorNormalVertex> v;
      std::vector<unsigned int> idx;
      g.tessellate(0, v, idx);
      const Rings r = rings(v, 12);
      ASSERT_FALSE(r.centre.empty()) << name;
      for (const auto& x : v)
        ASSERT_TRUE(x.vertex.allFinite() && x.normal.allFinite()) << name;
      EXPECT_LT((r.centre.front() - chain.pos.front()).norm(), 1e-3f) << name;
      EXPECT_LT((r.centre.back() - chain.pos.back()).norm(), 1e-3f) << name;
      EXPECT_EQ(r.owner.front(), 0u) << name;
      EXPECT_EQ(r.owner.back(), n - 1) << name;
      size_t previousOwner = 0;
      for (size_t o : r.owner) {
        EXPECT_GE(o, previousOwner) << name;
        previousOwner = o;
      }
      float maxChord = 0.0f;
      for (size_t i = 1; i < n; ++i)
        maxChord = std::max(maxChord, (chain.pos[i] - chain.pos[i - 1]).norm());
      const StepStats now = steps(r.centre);
      worst = std::max(worst, now.max / (maxChord / 15.0f));
      reversals += now.reversals;
    }
    std::printf("%-5s rope: largest step / (longest chord / 15) %.2f "
                "(%zu reversals)\n",
                name, worst, reversals);
    EXPECT_LE(worst, 1.0f + 1e-3f) << name;
    EXPECT_EQ(reversals, 0u) << name;
  }
  if (missing.size() == sizeof(kProteins) / sizeof(kProteins[0])) {
    GTEST_SKIP() << "no protein files in avogadrodata";
  }
}

TEST(CartoonProteinsTest, crambinEndsAreThinCoilAndStrand)
{
  // 1CRN's last residue is a lone sheet residue after coil; its cartoon
  // used to end in a block several times wider than the coil. The first
  // residues are a strand, which ends the chain at the strand width.
  Backbone bb;
  if (!loadBackbone("1CRN", bb))
    GTEST_SKIP() << "1CRN.pdb is not in avogadrodata";
  ASSERT_EQ(bb.chains.size(), 1u);
  const auto& chain = bb.chains[0];
  const size_t n = chain.pos.size();
  Cartoon cartoon(0.2f, 1.5f);
  for (size_t i = 0; i < n; ++i)
    cartoon.addPoint(chain.pos[i], idColor(i), 0, i, chain.ss[i]);
  std::vector<ColorNormalVertex> v;
  std::vector<unsigned int> idx;
  cartoon.tessellate(0, v, idx);
  float coilMax = 0.0f, firstMax = 0.0f;
  size_t coilRings = 0;
  for (size_t base = 0; base + 20 <= v.size(); base += 20) {
    float diameter = 0.0f;
    for (size_t j = 0; j < 20; ++j)
      for (size_t k = j + 1; k < 20; ++k)
        diameter =
          std::max(diameter, (v[base + j].vertex - v[base + k].vertex).norm());
    const size_t owner = colorId(v[base].color);
    if (owner >= n - 3) {
      coilMax = std::max(coilMax, diameter);
      ++coilRings;
    }
    if (owner < 2)
      firstMax = std::max(firstMax, diameter);
  }
  ASSERT_GT(coilRings, 20u);
  std::printf("1CRN: last three residues' widest ring %.3f (coil 0.300), "
              "first two residues' widest %.3f (strand 0.975)\n",
              coilMax, firstMax);
  EXPECT_NEAR(coilMax, 0.3f, 2e-3f);
  EXPECT_LE(firstMax, 0.975f + 2e-3f);
}
