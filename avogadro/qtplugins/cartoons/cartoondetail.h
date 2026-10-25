/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_CARTOONDETAIL_H
#define AVOGADRO_QTPLUGINS_CARTOONDETAIL_H

#include <avogadro/rendering/cartoongeometry.h>

#include <algorithm>
#include <array>
#include <cstddef>

// How finely the Cartoons plugin tessellates its curves. A residue costs
// segments x sides vertices (32 bytes each, plus indices), so a whole capsid
// at the full detail is gigabytes; the level is chosen once per process()
// call from the number of residues of every curve that is about to be drawn.
// Header only and free of Qt, so that it can be unit tested.

namespace Avogadro::QtPlugins {

struct CartoonDetail
{
  size_t segments; // per residue, for tubes (flat ribbons and lines use 4/3)
  size_t sides;    // of a cartoon tube; see tubeSides() for plain tubes

  // Set this detail on a curve: @p tube is true for a plain tube (the trace,
  // the tube and the rope) and false for the Cartoon cross-section. Flat
  // curves ignore the sides.
  void apply(Rendering::CurveGeometry& curve, bool tube) const;
};

// The curve styles of the Cartoons plugin that are drawn with a CurveGeometry.
enum class CartoonStyle
{
  Trace,
  Tube,
  Ribbon,
  SimpleCartoon,
  Cartoon,
  Rope
};

// Levels in order of decreasing detail; the first is the built-in detail of
// Rendering::Cartoon (15 segments x 20 sides). The last is the floor. The
// floor may exceed the budget for very large systems (9MB0 is 6.2 million at
// (6,8)); that is deliberate, there is no coarser level.
constexpr std::array<CartoonDetail, 5> kCartoonDetailLevels = { {
  { Rendering::CurveGeometry::kDefaultSegments,
    Rendering::Cartoon::kDefaultSides },
  { 12, 16 },
  { 10, 12 },
  { 8, 10 },
  { 6, 8 },
} };

// The most ring vertices (residues x segments x sides, summed over every
// curve drawn, ignoring the one extra ring a curve has) that is accepted
// before dropping to the next level: 5 million is about 160 MB of vertices.
// The last level is used even if it does not fit.
constexpr size_t kCartoonRingVertexBudget = 5000000;

// Residues drawn in each kind of curve. Cartoon and simple cartoon are
// 20-sided tubes, a tube (and the rope) is 12-sided, a ribbon is two vertices
// wide, a trace is a line.
struct CartoonResidueCounts
{
  size_t cartoon = 0;
  size_t tube = 0;
  size_t ribbon = 0;
  size_t trace = 0;

  // Count the @p residues of a curve drawn in @p style.
  void add(CartoonStyle style, size_t residues)
  {
    switch (style) {
      case CartoonStyle::Trace:
        trace += residues;
        break;
      case CartoonStyle::Tube:
      case CartoonStyle::Rope:
        tube += residues;
        break;
      case CartoonStyle::Ribbon:
        ribbon += residues;
        break;
      case CartoonStyle::SimpleCartoon:
      case CartoonStyle::Cartoon:
        cartoon += residues;
        break;
    }
  }
};

// Sides of a plain tube at a detail level: the tube default at the first
// level, in proportion to the cartoon sides, and at least 6.
constexpr size_t tubeSides(const CartoonDetail& detail)
{
  return std::max<size_t>(
    6, (Rendering::CurveGeometry::kDefaultTubeSides * detail.sides +
        Rendering::Cartoon::kDefaultSides / 2) /
         Rendering::Cartoon::kDefaultSides);
}

inline void CartoonDetail::apply(Rendering::CurveGeometry& curve,
                                 bool tube) const
{
  curve.setSegmentsPerResidue(segments);
  curve.setSides(tube ? tubeSides(*this) : sides);
}

// Segments of a flat line (ribbon, trace); flat lines are sampled more finely.
constexpr size_t flatSegments(const CartoonDetail& detail)
{
  return Rendering::CurveGeometry::flatSegmentsFor(detail.segments);
}

constexpr size_t cartoonRingVertices(const CartoonResidueCounts& counts,
                                     const CartoonDetail& detail)
{
  using Rendering::CurveGeometry;
  return CurveGeometry::ringVertices(counts.cartoon, detail.segments,
                                     detail.sides) +
         CurveGeometry::ringVertices(counts.tube, detail.segments,
                                     tubeSides(detail)) +
         CurveGeometry::ringVertices(counts.ribbon, flatSegments(detail), 2) +
         CurveGeometry::ringVertices(counts.trace, flatSegments(detail), 1);
}

// Index into kCartoonDetailLevels: the first level that fits the budget, or
// the last one.
constexpr size_t chooseCartoonDetailLevel(
  const CartoonResidueCounts& counts, size_t budget = kCartoonRingVertexBudget)
{
  for (size_t i = 0; i < kCartoonDetailLevels.size(); ++i) {
    if (cartoonRingVertices(counts, kCartoonDetailLevels[i]) <= budget)
      return i;
  }
  return kCartoonDetailLevels.size() - 1;
}

} // namespace Avogadro::QtPlugins

#endif
