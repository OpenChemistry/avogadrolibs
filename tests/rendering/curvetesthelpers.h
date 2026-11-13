/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

// Shared by the curve and cartoon tests: synthetic chains, a way to read the
// rings of a tessellated tube back as centres and owners, and C-alpha traces
// from the PDB files in avogadrodata.

#ifndef AVOGADRO_TESTS_RENDERING_CURVETESTHELPERS_H
#define AVOGADRO_TESTS_RENDERING_CURVETESTHELPERS_H

#include <gtest/gtest.h>

#include <avogadro/core/avogadrocore.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/residue.h>
#include <avogadro/core/vector.h>
#include <avogadro/io/pdbformat.h>
#include <avogadro/rendering/curvegeometry.h>

#include <algorithm>
#include <cmath>
#include <filesystem>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace CurveTest {

using Avogadro::Vector3f;
using Avogadro::Vector3ub;
using Avogadro::Rendering::ColorNormalVertex;

// A 24-bit id in a colour, so that a vertex says which residue it belongs to.
inline Vector3ub idColor(size_t id)
{
  return Vector3ub(static_cast<unsigned char>(id & 255),
                   static_cast<unsigned char>((id >> 8) & 255),
                   static_cast<unsigned char>((id >> 16) & 255));
}

inline size_t colorId(const Vector3ub& c)
{
  return static_cast<size_t>(c[0]) | static_cast<size_t>(c[1]) << 8 |
         static_cast<size_t>(c[2]) << 16;
}

// Alpha helix C-alpha trace: 2.3 A radius, 1.5 A rise, 100 degrees a residue.
inline std::vector<Vector3f> helix(int n)
{
  std::vector<Vector3f> pts;
  for (int i = 0; i < n; ++i) {
    const float t = static_cast<float>(i) * 100.0f * Avogadro::DEG_TO_RAD_F;
    pts.emplace_back(2.3f * std::cos(t), 2.3f * std::sin(t), 1.5f * i);
  }
  return pts;
}

// An extended chain with a sideways wobble, 3.5 A between points.
inline std::vector<Vector3f> wobble(int n)
{
  std::vector<Vector3f> pts;
  for (int i = 0; i < n; ++i)
    pts.emplace_back(3.5f * i, 1.5f * std::sin(0.9f * i), 1.2f * std::cos(i));
  return pts;
}

inline bool allFinite(const std::vector<ColorNormalVertex>& vertices)
{
  for (const auto& v : vertices) {
    if (!v.vertex.allFinite() || !v.normal.allFinite())
      return false;
  }
  return true;
}

// The rings of a tube, one entry per ring in drawing order (a ring is
// repeated where the colour changes): the centre of its vertices, the id
// in its colour, and the distance of its first vertex from the centre.
struct Rings
{
  std::vector<Vector3f> centre;
  std::vector<size_t> owner;
  std::vector<float> radius;
};

inline Rings ringsOf(const std::vector<ColorNormalVertex>& v, size_t sides)
{
  Rings r;
  for (size_t base = 0; base + sides <= v.size(); base += sides) {
    Vector3f c = Vector3f::Zero();
    for (size_t j = 0; j < sides; ++j)
      c += v[base + j].vertex;
    c /= static_cast<float>(sides);
    r.centre.push_back(c);
    r.owner.push_back(colorId(v[base].color));
    r.radius.push_back((v[base].vertex - c).norm());
  }
  return r;
}

// Length of the steps along a polyline and how many times it turns back.
struct StepStats
{
  float max = 0.0f, median = 0.0f;
  size_t reversals = 0;
};

inline StepStats steps(const std::vector<Vector3f>& p)
{
  std::vector<float> d;
  std::vector<Vector3f> s;
  for (size_t i = 1; i < p.size(); ++i) {
    const Vector3f step = p[i] - p[i - 1];
    if (step.norm() < 1e-6f)
      continue; // a repeated ring
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

// Longest distance between neighbouring points.
inline float longestChord(const std::vector<Vector3f>& pts)
{
  float longest = 0.0f;
  for (size_t i = 1; i < pts.size(); ++i)
    longest = std::max(longest, (pts[i] - pts[i - 1]).norm());
  return longest;
}

// What a drawn chain must satisfy whatever its curve: the first and last ring
// are on the end points, it never turns back, and no step is longer than the
// longest chord allows (a segment moves less than a chord in its `segments`
// samples, so a jump would stand out). Returns the largest step as a
// fraction of that bound.
inline float checkChain(const std::vector<Vector3f>& pts, const Rings& r,
                        size_t segments = 15)
{
  EXPECT_FALSE(r.centre.empty());
  if (r.centre.empty())
    return 0.0f;
  EXPECT_LT((r.centre.front() - pts.front()).norm(), 1e-3f);
  EXPECT_LT((r.centre.back() - pts.back()).norm(), 1e-3f);
  EXPECT_EQ(r.owner.front(), 0u);
  EXPECT_EQ(r.owner.back(), pts.size() - 1);
  const StepStats stats = steps(r.centre);
  EXPECT_EQ(stats.reversals, 0u);
  const float bound = longestChord(pts) / static_cast<float>(segments);
  EXPECT_LE(stats.max, bound * (1.0f + 1e-3f));
  return stats.max / bound;
}

// The C-alpha traces of a protein, built the way
// Cartoons::getBackboneByResidues() does it (the Cartoons plugin is a Qt
// plugin and cannot be linked here): non-heterogen residues with both CA and
// O, and a new curve whenever the chain, the residue numbering or a 6 A step
// breaks the trace. (The plugin also splits by bonded component; the chain id
// plays that role here.)
struct Chain
{
  std::vector<Vector3f> pos;
  std::vector<Avogadro::Core::Residue::SecondaryStructure> ss;
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

// Reads data/pdb/<name>.pdb from avogadrodata; false if it is not there.
inline bool loadBackbone(const std::string& name, Backbone& result)
{
  const std::filesystem::path path =
    std::filesystem::path(AVOGADRO_DATA) / "data" / "pdb" / (name + ".pdb");
  if (!std::filesystem::exists(path))
    return false;
  Avogadro::Core::Molecule molecule;
  Avogadro::Io::PdbFormat pdb;
  if (!pdb.readFile(path.string(), molecule))
    return false;

  struct State
  {
    bool started = false;
    size_t residueId = 0;
    Vector3f position = Vector3f::Zero();
    size_t group = 0;
  };
  std::map<char, State> previous;
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

// The proteins of avogadrodata the tests walk through, in this order.
inline const std::vector<std::string>& proteinNames()
{
  static const std::vector<std::string> names = { "1CRN", "1PGA", "4HHB",
                                                  "6VXX", "1FDT", "1MYK" };
  return names;
}

// Those of proteinNames() that are in avogadrodata, with their traces. A
// checkout without the newest files still passes; the missing names are left
// in `missing` for the test to say so.
inline std::vector<std::pair<std::string, Backbone>> loadProteins(
  std::vector<std::string>& missing)
{
  std::vector<std::pair<std::string, Backbone>> proteins;
  for (const auto& name : proteinNames()) {
    Backbone bb;
    if (loadBackbone(name, bb))
      proteins.emplace_back(name, std::move(bb));
    else
      missing.push_back(name);
  }
  return proteins;
}

} // namespace CurveTest

#endif
