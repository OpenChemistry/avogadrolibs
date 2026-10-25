/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include "curvetesthelpers.h"

#include <avogadro/core/vector.h>
#include <avogadro/rendering/bsplinegeometry.h>
#include <avogadro/rendering/cartoongeometry.h>

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using namespace CurveTest;
using Avogadro::Vector3f;
using Avogadro::Vector3ub;
using Avogadro::Core::Residue;
using Avogadro::Rendering::BSplineGeometry;
using Avogadro::Rendering::Cartoon;
using Avogadro::Rendering::ColorNormalVertex;
using Avogadro::Rendering::CurveGeometry;

namespace {

using SS = Residue::SecondaryStructure;

// Exposes a plain reference loop for tessellate(): frames from the global
// uniform spline are computed directly, and every segment emits both of its
// own rings (the ring at each segment end twice, once per neighbouring
// segment). tessellate() must produce the same triangles with shared rings.
template <class G>
class Reference : public G
{
public:
  template <class... Args>
  explicit Reference(Args... args) : G(args...)
  {
  }

  void tessellateOld(size_t lineIndex, std::vector<ColorNormalVertex>& vertices,
                     std::vector<unsigned int>& indices) const
  {
    vertices.clear();
    indices.clear();
    if (lineIndex >= this->lines().size())
      return;
    const auto* line = this->lines()[lineIndex];
    const size_t lineResolution = line->flat ? 20u : 15u;
    const size_t n = line->points.size();
    if (n < 2)
      return;
    const size_t segments = n;
    Vector3f previous = Vector3f::Zero();
    std::vector<Eigen::Affine3f> points;
    std::vector<size_t> color;
    for (size_t q = 0; q <= segments * lineResolution; ++q) {
      const size_t k = q / lineResolution;
      const size_t j = q % lineResolution;
      const float f =
        static_cast<float>(j) / static_cast<float>(lineResolution);
      Vector3f p = this->computeSegmentPoint(k, f, line->points);
      {
        // the first frame looks towards the second sample
        Vector3f tangent = q > 0 ? p - previous
                                 : this->computeSegmentPoint(
                                     0, 1.0f / lineResolution, line->points) -
                                     p;
        if (tangent.squaredNorm() < 1e-10f) {
          previous = p;
          continue;
        }
        Eigen::Matrix3f m;
        m.col(1) = tangent.normalized();
        m.col(0) = m.col(1).unitOrthogonal() * -1.0f;
        if (!points.empty()) {
          const auto& previousAngle = points.back().linear().col(0);
          float angle = previousAngle.dot(m.col(0));
          if (angle <= 0.0f)
            m.col(0) *= -1.0f;
          angle = previousAngle.dot(m.col(0));
          float denom = m.col(0).norm() * previousAngle.norm();
          float cosAngle = std::clamp(angle / denom, -1.0f, 1.0f);
          float degrees = std::acos(cosAngle) * Avogadro::RAD_TO_DEG_F;
          int maxIter = 10;
          while (degrees > 25.0f && --maxIter > 0) {
            m.col(0) = (m.col(0) + previousAngle).normalized();
            angle = previousAngle.dot(m.col(0));
            denom = m.col(0).norm() * previousAngle.norm();
            cosAngle = std::clamp(angle / denom, -1.0f, 1.0f);
            degrees = std::acos(cosAngle) * Avogadro::RAD_TO_DEG_F;
          }
        }
        m.col(2) = m.col(0).cross(m.col(1)) * -1.0f;
        Eigen::Affine3f affine;
        affine.translation() = p;
        affine.linear() = m;
        // segment k is owned by control point k
        const size_t owner = std::min(k, n - 1);
        affine.scale(this->computeScale(owner, k < n ? f : 1.0f, line->radius));
        points.push_back(affine);
        color.push_back(k >= n ? n - 1 : (j > 0 || k == 0 ? k : k - 1));
      }
      previous = p;
    }
    if (points.empty())
      return;
    ASSERT_FALSE(line->flat && this->m_canBeFlat);
    const size_t resolution = this->circleResolution(line->flat);
    std::vector<ColorNormalVertex> radials;
    for (size_t i = 1; i < points.size(); ++i) {
      radials.clear();
      this->appendCirclePoints(radials, points[i], points[i - 1], line->flat);
      for (auto& radial : radials) {
        radial.color = line->points[color[i]].color;
        vertices.push_back(radial);
      }
      const auto tubeStart =
        static_cast<unsigned int>(vertices.size() - radials.size());
      for (size_t j = 0; j < resolution; ++j) {
        unsigned int r1 = static_cast<unsigned int>(j * 2);
        unsigned int r2 =
          j != 0 ? r1 - 2 : static_cast<unsigned int>(radials.size() - 2);
        indices.push_back(tubeStart + r1);
        indices.push_back(tubeStart + r1 + 1);
        indices.push_back(tubeStart + r2);
        indices.push_back(tubeStart + r2);
        indices.push_back(tubeStart + r1 + 1);
        indices.push_back(tubeStart + r2 + 1);
      }
    }
  }
};

using Corner = std::array<float, 9>;
using Soup = std::vector<std::array<unsigned char, 3>>;

// Expand to per-triangle-corner (position, normal) and colour.
void expand(const std::vector<ColorNormalVertex>& v,
            const std::vector<unsigned int>& idx, std::vector<Corner>& corners,
            Soup& colors)
{
  corners.clear();
  colors.clear();
  for (unsigned int i : idx) {
    const auto& x = v[i];
    corners.push_back({ x.vertex[0], x.vertex[1], x.vertex[2], x.normal[0],
                        x.normal[1], x.normal[2], 0.0f, 0.0f, 0.0f });
    colors.push_back({ x.color[0], x.color[1], x.color[2] });
  }
}

template <class G>
void compareOldNew(const Reference<G>& g, size_t lineIndex = 0)
{
  std::vector<ColorNormalVertex> ov, nv;
  std::vector<unsigned int> oi, ni;
  g.tessellateOld(lineIndex, ov, oi);
  g.tessellate(lineIndex, nv, ni);
  ASSERT_FALSE(ov.empty());
  ASSERT_EQ(oi.size(), ni.size());
  std::vector<Corner> oc, nc;
  Soup ocol, ncol;
  expand(ov, oi, oc, ocol);
  expand(nv, ni, nc, ncol);
  // Bitwise comparison.
  ASSERT_EQ(0, std::memcmp(oc.data(), nc.data(), oc.size() * sizeof(Corner)));
  ASSERT_TRUE(ocol == ncol);
  EXPECT_LT(nv.size(), ov.size());
  for (unsigned int i : ni)
    ASSERT_LT(i, nv.size());
}

void addChain(Cartoon& c, int count, size_t group, int colorPeriod)
{
  for (int i = 0; i < count; ++i) {
    float t = static_cast<float>(i) * 100.0f * Avogadro::DEG_TO_RAD_F;
    SS ss = SS::coil;
    int phase = (i / 9) % 3;
    if (phase == 0)
      ss = SS::alphaHelix;
    else if (phase == 1)
      ss = SS::betaSheet;
    float x = phase == 0 ? 2.3f * std::cos(t) : 3.3f * i;
    float y = phase == 0 ? 2.3f * std::sin(t) : 1.1f * std::sin(0.7f * i);
    int cid = colorPeriod > 0 ? (i / colorPeriod) : 0;
    c.addPoint(Vector3f(x, y, 1.5f * i), Vector3ub(10 + cid, 20 + 3 * cid, 30),
               group, static_cast<size_t>(i), ss);
  }
}

} // namespace

TEST(CurveTessellationTest, cartoonMixedSecondaryStructure)
{
  Reference<Cartoon> c(0.1f, 0.5f);
  addChain(c, 60, 0, 0);
  compareOldNew(c);
}

TEST(CurveTessellationTest, cartoonColourChanges)
{
  for (int period : { 1, 2, 3, 7 }) {
    Reference<Cartoon> c(0.1f, 0.5f);
    addChain(c, 45, 0, period);
    compareOldNew(c);
  }
}

TEST(CurveTessellationTest, cartoonShortChains)
{
  for (int n = 5; n <= 14; ++n) {
    Reference<Cartoon> c(0.1f, 0.5f);
    addChain(c, n, 0, 2);
    std::vector<ColorNormalVertex> ov;
    std::vector<unsigned int> oi;
    c.tessellateOld(0, ov, oi);
    if (ov.empty())
      continue;
    compareOldNew(c);
  }
}

TEST(CurveTessellationTest, plainBSplineTube)
{
  for (int period : { 0, 4 }) {
    Reference<BSplineGeometry> s(false);
    for (int i = 0; i < 50; ++i) {
      int cid = period ? i / period : 0;
      s.addPoint(Vector3f(0.8f * i, 2.0f * std::sin(0.4f * i),
                          1.5f * std::cos(0.3f * i)),
                 Vector3ub(5 + cid, 6, 7 * cid), 0.2f, 0,
                 static_cast<size_t>(i));
    }
    compareOldNew(s);
  }
}

TEST(CurveTessellationTest, multipleLines)
{
  Reference<Cartoon> c(0.1f, 0.5f);
  addChain(c, 40, 0, 5);
  addChain(c, 33, 7, 0);
  addChain(c, 25, 3, 2);
  ASSERT_EQ(c.lines().size(), static_cast<size_t>(3));
  for (size_t l = 0; l < 3; ++l)
    compareOldNew(c, l);
}

namespace {

// Vertex and index counts of every line, shared rings against the reference
// with every ring doubled.
void report(const char* name, Reference<Cartoon>& c, size_t residues)
{
  size_t ov = 0, oi = 0, nv = 0, ni = 0;
  for (size_t line = 0; line < c.lines().size(); ++line) {
    std::vector<ColorNormalVertex> v;
    std::vector<unsigned int> idx;
    c.tessellateOld(line, v, idx);
    ov += v.size();
    oi += idx.size();
    c.tessellate(line, v, idx);
    nv += v.size();
    ni += idx.size();
  }
  const double ob = ov * sizeof(ColorNormalVertex) + oi * 4.0;
  const double nb = nv * sizeof(ColorNormalVertex) + ni * 4.0;
  std::printf("%-28s residues=%zu  doubled rings: V=%zu I=%zu  shared: V=%zu "
              "I=%zu  bytes/residue %.0f -> %.0f\n",
              name, residues, ov, oi, nv, ni, ob / residues, nb / residues);
}

} // namespace

TEST(CurveTessellationTest, reportCounts)
{
  {
    Reference<Cartoon> c(0.1f, 0.5f);
    addChain(c, 200, 0, 0);
    report("synthetic, one colour", c, 200);
  }
  {
    Reference<Cartoon> c(0.1f, 0.5f);
    addChain(c, 200, 0, 1);
    report("synthetic, colour/residue", c, 200);
  }
  // the real proteins of avogadrodata, one colour and a colour a residue
  std::vector<std::string> missing;
  for (const auto& [name, bb] : loadProteins(missing)) {
    for (int perResidue = 0; perResidue < 2; ++perResidue) {
      Reference<Cartoon> c(0.1f, 0.5f);
      size_t group = 0, n = 0;
      for (const auto& chain : bb.chains) {
        for (size_t i = 0; i < chain.pos.size(); ++i, ++n)
          c.addPoint(chain.pos[i], idColor(perResidue ? n % 200 : 0), group, n,
                     chain.ss[i]);
        ++group;
      }
      report((name + (perResidue ? " (colour/res)" : " (one colour)")).c_str(),
             c, n);
    }
  }
}
