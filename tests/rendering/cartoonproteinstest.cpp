/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

// Real proteins through the cartoon tessellation. The files come from
// avogadrodata (data/pdb); a test is skipped if its file is missing, so a
// checkout of avogadrodata older than the 6VXX/1PGA/4HHB commit still passes.
//
// The C-alpha traces come from loadBackbone() in curvetesthelpers.h.

#include <gtest/gtest.h>

#include "curvetesthelpers.h"
#include "legacyspline.h"

#include <cartoondetail.h>

#include <avogadro/core/vector.h>
#include <avogadro/rendering/beziergeometry.h>
#include <avogadro/rendering/bsplinegeometry.h>
#include <avogadro/rendering/cartoongeometry.h>

#include <algorithm>
#include <cstdio>
#include <string>
#include <vector>

using namespace CurveTest;
using Avogadro::Vector3f;
using Avogadro::QtPlugins::CartoonResidueCounts;
using Avogadro::QtPlugins::chooseCartoonDetailLevel;
using Avogadro::QtPlugins::kCartoonDetailLevels;
using Avogadro::Rendering::BezierGeometry;
using Avogadro::Rendering::BSplineGeometry;
using Avogadro::Rendering::Cartoon;
using Avogadro::Rendering::ColorNormalVertex;

// The proteins that are in avogadrodata, or a skip if there are none.
#define LOAD_PROTEINS_OR_SKIP(proteins)                                        \
  std::vector<std::string> missing;                                            \
  const auto proteins = loadProteins(missing);                                 \
  if (proteins.empty())                                                        \
    GTEST_SKIP() << "no protein files in avogadrodata";                        \
  for (const auto& name : missing)                                             \
    std::printf("skipped (not in avogadrodata): %s\n", name.c_str());

namespace {

std::vector<ColorNormalVertex> tessellateTube(const std::vector<Vector3f>& pos,
                                              BSplineGeometry& g)
{
  for (size_t i = 0; i < pos.size(); ++i)
    g.addPoint(pos[i], idColor(i), 0.1f, 0, i);
  std::vector<ColorNormalVertex> v;
  std::vector<unsigned int> idx;
  g.tessellate(0, v, idx);
  return v;
}

} // namespace

TEST(CartoonProteinsTest, tessellationIsFiniteAndCountedAtEveryLevel)
{
  LOAD_PROTEINS_OR_SKIP(proteins)
  for (const auto& [name, bb] : proteins) {
    SCOPED_TRACE(name);
    ASSERT_GT(bb.residues(), 40u);
    CartoonResidueCounts counts;
    counts.cartoon = bb.residues();
    EXPECT_EQ(chooseCartoonDetailLevel(counts), 0u)
      << "small enough for full detail";

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
          EXPECT_TRUE(v.empty());
          continue;
        }
        // a ring at every sample of the n segments (including both ends);
        // rings are only repeated where the colour changes
        const size_t frames = n * level.segments + 1;
        EXPECT_GE(v.size(), frames * level.sides) << "n=" << n;
        EXPECT_LE(v.size(), (frames + n - 1) * level.sides) << "n=" << n;
        EXPECT_EQ(idx.size(), (frames - 1) * level.sides * 6);
        ASSERT_TRUE(allFinite(v));
        for (unsigned int i : idx)
          ASSERT_LT(i, v.size());
        totalVertices += v.size();
      }
      std::printf("%-5s %6zu residues %3zu curves  %2zu x %2zu: %9zu "
                  "vertices (%.1f MB)\n",
                  name.c_str(), bb.residues(), bb.chains.size(), level.segments,
                  level.sides, totalVertices,
                  totalVertices * sizeof(ColorNormalVertex) / 1.0e6);
    }
  }
}

TEST(CartoonProteinsTest, curveIsContinuousAndAligned)
{
  LOAD_PROTEINS_OR_SKIP(proteins)
  for (const auto& [name, bb] : proteins) {
    SCOPED_TRACE(name);
    float worstRatio = 0.0f, worstOldRatio = 0.0f, worstExcess = 0.0f;
    size_t oldReversals = 0, rows = 0, exact = 0;
    for (const auto& chain : bb.chains) {
      const size_t n = chain.pos.size();
      if (n < 2)
        continue;
      BSplineGeometry g(false);
      const Rings r = ringsOf(tessellateTube(chain.pos, g), 12);
      worstRatio = std::max(worstRatio, checkChain(chain.pos, r));

      size_t previousOwner = 0;
      for (size_t i = 0; i < r.centre.size(); ++i) {
        ASSERT_LT(r.owner[i], n);
        EXPECT_GE(r.owner[i], previousOwner);
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
        worstOldRatio =
          std::max(worstOldRatio, old.max / (longestChord(chain.pos) / 15.0f));
        oldReversals += old.reversals;
      }
    }
    std::printf("%-5s largest step / (longest chord / 15): new %.2f, old %.2f "
                "(%zu reversals); owner is nearest CA for %zu of %zu rings, "
                "worst excess %.3f A\n",
                name.c_str(), worstRatio, worstOldRatio, oldReversals, exact,
                rows, worstExcess);
    EXPECT_LT(worstExcess, 1.0f);
  }
}

TEST(CartoonProteinsTest, ropeIsFiniteContinuousAndReachesTheTermini)
{
  LOAD_PROTEINS_OR_SKIP(proteins)
  for (const auto& [name, bb] : proteins) {
    SCOPED_TRACE(name);
    float worst = 0.0f;
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
      ASSERT_TRUE(allFinite(v));
      const Rings r = ringsOf(v, 12);
      worst = std::max(worst, checkChain(chain.pos, r));
      EXPECT_TRUE(std::is_sorted(r.owner.begin(), r.owner.end()));
    }
    std::printf("%-5s rope: largest step / (longest chord / 15) %.2f\n",
                name.c_str(), worst);
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
