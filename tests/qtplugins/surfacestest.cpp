/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "commandtestharness.h"

#include "edtfill.h"
#include "surfaceresolution.h"
#include "surfaces.h"

#include <avogadro/core/cube.h>
#include <avogadro/core/elements.h>
#include <avogadro/core/gaussianset.h>
#include <avogadro/core/mesh.h>
#include <avogadro/core/molecule.h>
#include <avogadro/qtgui/meshgenerator.h>

#include <QtCore/QEvent>
#include <QtCore/QMetaObject>
#include <QtCore/QStringList>
#include <QtCore/QTimer>
#include <QtCore/QVariantMap>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <functional>
#include <iostream>
#include <sstream>
#include <limits>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

using Avogadro::Index;
using Avogadro::Vector3;
using Avogadro::Vector3i;
using Avogadro::Core::Cube;
using Avogadro::Core::Mesh;
using Avogadro::QtPlugins::automaticSurfaceResolution;
using Avogadro::QtPlugins::Surfaces;
using Avogadro::QtPlugins::SurfaceVoxelBudget;
using Avogadro::QtPluginsTests::CommandOutcome;
using Avogadro::QtPluginsTests::CommandStatus;
using Avogadro::QtPluginsTests::CommandTestHarness;
using Avogadro::QtPluginsTests::describe;

namespace {

// Requested grid resolution in Angstrom; coarse so the cubes stay small.
constexpr float Resolution = 0.25f;
constexpr double SolventProbe = 1.4;
// Float arithmetic in the distance field, for distances of a few Angstrom.
constexpr float DistanceTolerance = 1.0e-4f;

using AtomSphere = Avogadro::QtPlugins::EdtSphere; // center, radius incl. probe

// The same arithmetic as Surfaces::calculateEDT(), written serially and
// against a plain array, so the threaded implementation is compared with an
// independent one. The flat-index bounds checks of Cube::fillStripe() are
// reproduced, including its unsigned wrap-around for negative indices.
class ReferenceGrid
{
public:
  ReferenceGrid(const Vector3i& dims) : m_dims(dims)
  {
    m_data.assign(static_cast<size_t>(dims(0)) * dims(1) * dims(2), -1.0f);
  }

  float at(int x, int y, int z) const { return m_data[flat(x, y, z)]; }
  float& at(int x, int y, int z) { return m_data[flat(x, y, z)]; }

  const std::vector<float>& data() const { return m_data; }

  size_t insideCount() const
  {
    return static_cast<size_t>(std::count_if(m_data.begin(), m_data.end(),
                                             [](float v) { return v > 0.0f; }));
  }

  void fillStripe(unsigned int i, unsigned int j, unsigned int kfirst,
                  unsigned int klast)
  {
    unsigned int start = i * static_cast<unsigned int>(m_dims(1)) *
                           static_cast<unsigned int>(m_dims(2)) +
                         j * static_cast<unsigned int>(m_dims(2));
    unsigned int first = start + kfirst;
    unsigned int last = start + klast;
    if (first >= m_data.size() || last >= m_data.size())
      return;
    std::fill(m_data.begin() + first, m_data.begin() + last + 1, 1.0f);
  }

  // The distance field of fillDistanceSpheres(), by brute force over every
  // voxel and atom: the largest (radius - distance), but no lower than
  // -margin, the background of voxels the plugin never visits.
  void fillDistance(const std::vector<AtomSphere>& atoms, const Vector3& min,
                    const Vector3& spacing, double margin)
  {
    for (int x = 0; x < m_dims(0); ++x) {
      for (int y = 0; y < m_dims(1); ++y) {
        for (int z = 0; z < m_dims(2); ++z) {
          const Vector3 pos = min + Vector3(x, y, z).cwiseProduct(spacing);
          double best = -margin;
          for (const AtomSphere& in : atoms)
            best = std::max(best, in.second - (pos - in.first).norm());
          at(x, y, z) = static_cast<float>(best);
        }
      }
    }
  }

  void fillSpheres(const std::vector<AtomSphere>& atoms, const Vector3& min,
                   const Vector3& spacing)
  {
    for (const AtomSphere& in : atoms) {
      double startPosX = in.first(0) - in.second;
      double endPosX = in.first(0) + in.second;
      int startIndexX = (startPosX - min(0)) / spacing(0);
      int endIndexX = (endPosX - min(0)) / spacing(0) + 1;
      for (int indexX = startIndexX; indexX < endIndexX; indexX++) {
        double posX = indexX * spacing(0) + min(0);
        double radiusXsq =
          in.second * in.second - (posX - in.first(0)) * (posX - in.first(0));
        if (radiusXsq < 0.0)
          continue;
        double radiusX = std::sqrt(radiusXsq);
        double startPosY = in.first(1) - radiusX;
        double endPosY = in.first(1) + radiusX;
        int startIndexY = (startPosY - min(1)) / spacing(1);
        int endIndexY = (endPosY - min(1)) / spacing(1) + 1;
        for (int indexY = startIndexY; indexY < endIndexY; indexY++) {
          double posY = indexY * spacing(1) + min(1);
          double lengthXYsq =
            radiusX * radiusX - (posY - in.first(1)) * (posY - in.first(1));
          if (lengthXYsq < 0.0)
            continue;
          double lengthXY = std::sqrt(lengthXYsq);
          double startPosZ = in.first(2) - lengthXY;
          double endPosZ = in.first(2) + lengthXY;
          int startIndexZ =
            static_cast<int>(std::ceil((startPosZ - min(2)) / spacing(2)));
          int endIndexZ = (endPosZ - min(2)) / spacing(2) + 1;
          fillStripe(static_cast<unsigned int>(indexX),
                     static_cast<unsigned int>(indexY),
                     static_cast<unsigned int>(startIndexZ),
                     static_cast<unsigned int>(endIndexZ - 1));
        }
      }
    }
  }

private:
  size_t flat(int x, int y, int z) const
  {
    return (static_cast<size_t>(x) * m_dims(1) + y) * m_dims(2) + z;
  }

  Vector3i m_dims;
  std::vector<float> m_data;
};

class SurfacesCommandTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    m_harness.buildEmpty();
    buildEthanol();
    m_harness.attach(&m_surfaces);
    m_harness.registerCommands();
  }

  // Ethanol with all hydrogens, staggered, roughly relaxed (Angstrom). The
  // neighbouring atoms are 1-1.5 A apart, so their spheres overlap heavily.
  void buildEthanol()
  {
    auto* mol = m_harness.molecule();
    mol->addAtom(6, Vector3(0.000, 0.000, 0.000));    // 0 C (methyl)
    mol->addAtom(6, Vector3(1.520, 0.000, 0.000));    // 1 C (methylene)
    mol->addAtom(8, Vector3(2.020, 1.340, 0.000));    // 2 O
    mol->addAtom(1, Vector3(2.980, 1.340, 0.000));    // 3 H (O)
    mol->addAtom(1, Vector3(-0.365, 1.027, 0.000));   // 4 H (C0)
    mol->addAtom(1, Vector3(-0.365, -0.513, 0.889));  // 5 H (C0)
    mol->addAtom(1, Vector3(-0.365, -0.513, -0.889)); // 6 H (C0)
    mol->addAtom(1, Vector3(1.885, -0.513, 0.889));   // 7 H (C1)
    mol->addAtom(1, Vector3(1.885, -0.513, -0.889));  // 8 H (C1)
  }

  std::vector<AtomSphere> spheres(double probe) const
  {
    std::vector<AtomSphere> atoms;
    const auto* mol = m_harness.molecule();
    for (Index i = 0; i < mol->atomCount(); ++i) {
      atoms.emplace_back(
        mol->atomPosition3d(i),
        Avogadro::Core::Elements::radiusVDW(mol->atomicNumber(i)) + probe);
    }
    return atoms;
  }

  // Run a surface command and return the (single) cube it produced.
  const Cube* runSurface(const char* command, CommandOutcome& out)
  {
    QVariantMap options;
    options.insert(QStringLiteral("resolution"), Resolution);
    out = m_harness.run(QString::fromLatin1(command), options);
    EXPECT_TRUE(out.claimed) << command;
    EXPECT_EQ(out.status, CommandStatus::Finished) << describe(out);
    EXPECT_TRUE(out.async) << command << " should run in the background";
    EXPECT_TRUE(out.clean()) << describe(out);
    EXPECT_DOUBLE_EQ(out.result.value("resolution").toDouble(),
                     static_cast<double>(Resolution));
    EXPECT_EQ(m_harness.molecule()->cubeCount(), 1u);
    return m_harness.molecule()->activeCube();
  }

  // Independent geometric check that does not depend on the stripe maths:
  // a voxel well inside a sphere is inside, one well outside every sphere is
  // not. "Well" is two voxels, which covers the truncation of the stripe ends.
  void expectGeometry(const Cube& cube, const std::vector<AtomSphere>& atoms)
  {
    const Vector3 min = cube.min();
    const Vector3i dims = cube.dimensions();
    const Vector3 spacing = cube.spacing();
    const double margin = Avogadro::QtPlugins::distanceFieldMargin(cube);
    size_t checkedInside = 0, checkedOutside = 0;
    for (int x = 0; x < dims(0); ++x) {
      for (int y = 0; y < dims(1); ++y) {
        for (int z = 0; z < dims(2); ++z) {
          const Vector3 pos = min + Vector3(x, y, z).cwiseProduct(spacing);
          double deepest = -1.0e9; // largest (radius - distance)
          for (const AtomSphere& a : atoms)
            deepest = std::max(deepest, a.second - (pos - a.first).norm());
          const bool inside = cube.value(x, y, z) > 0.0f;
          if (deepest > margin) {
            ++checkedInside;
            if (!inside) {
              ADD_FAILURE() << "voxel " << x << "," << y << "," << z << " is "
                            << deepest << " A inside a sphere";
              return;
            }
          } else if (deepest < -margin) {
            ++checkedOutside;
            if (inside) {
              ADD_FAILURE() << "voxel " << x << "," << y << "," << z << " is "
                            << -deepest << " A outside every sphere";
              return;
            }
          }
        }
      }
    }
    EXPECT_GT(checkedInside, 1000u);
    EXPECT_GT(checkedOutside, 1000u);
  }

  // Build the serial reference for a vdW (probe 0) or SAS (probe 1.4) cube
  // laid out like @p cube: the signed distance field those surfaces use, or
  // with @p binary the +1/-1 fill that the solvent-excluded one starts from.
  ReferenceGrid fillReference(const Cube& cube, double probe,
                              bool binary = false) const
  {
    ReferenceGrid ref(cube.dimensions());
    if (binary) {
      ref.fillSpheres(spheres(probe), cube.min(), cube.spacing());
    } else {
      ref.fillDistance(spheres(probe), cube.min(), cube.spacing(),
                       Avogadro::QtPlugins::distanceFieldMargin(cube));
    }
    return ref;
  }

  // The binary fill is exact; the distance field is float arithmetic.
  void expectEqual(const Cube& cube, const ReferenceGrid& ref, const char* what,
                   float tolerance = 0.0f)
  {
    const Vector3i dims = cube.dimensions();
    size_t mismatches = 0;
    for (int x = 0; x < dims(0); ++x) {
      for (int y = 0; y < dims(1); ++y) {
        for (int z = 0; z < dims(2); ++z) {
          const float value = cube.value(x, y, z);
          const float expected = ref.at(x, y, z);
          if (!std::isfinite(value) || !std::isfinite(expected) ||
              std::abs(value - expected) > tolerance) {
            if (mismatches++ < 5) {
              ADD_FAILURE()
                << what << ": voxel " << x << "," << y << "," << z << " is "
                << cube.value(x, y, z) << ", reference " << ref.at(x, y, z);
            }
          }
        }
      }
    }
    EXPECT_EQ(mismatches, 0u) << what << ": voxels differ from the reference";
  }

  Surfaces m_surfaces;
  CommandTestHarness m_harness{ 60000 };
};

} // namespace

TEST_F(SurfacesCommandTest, registersSurfaceCommands)
{
  const auto registered = m_harness.registerCommands();
  EXPECT_TRUE(m_harness.registrationViolations().isEmpty());
  EXPECT_TRUE(registered.contains("renderVDW"));
  EXPECT_TRUE(registered.contains("renderSolventAccessible"));
  EXPECT_TRUE(registered.contains("renderSolventExcluded"));
}

// A basis set GaussianSetTools refuses never starts a calculation, so the
// command must fail at once instead of leaving the caller waiting forever.
TEST_F(SurfacesCommandTest, rejectedBasisSetFailsTheCommand)
{
  auto* mol = m_harness.molecule();
  auto* basis = new Avogadro::Core::GaussianSet;
  basis->setMolecule(mol);
  unsigned int s = basis->addBasis(0, Avogadro::Core::GaussianSet::S);
  basis->addGto(s, 1.0, 1.3);
  // Ethanol has nine atoms; this shell sits on one that does not exist.
  s = basis->addBasis(99, Avogadro::Core::GaussianSet::S);
  basis->addGto(s, 1.0, 1.3);
  basis->setMolecularOrbitals({ 0.7, 0.7, 0.7, -0.7 },
                              Avogadro::Core::BasisSet::Paired);
  basis->setElectronCount(2);
  mol->setBasisSet(basis);
  m_surfaces.setMolecule(mol); // pick up the basis set

  for (const char* command : { "renderMO", "renderElectronDensity" }) {
    QVariantMap options;
    options.insert(QStringLiteral("resolution"), Resolution);
    options.insert(QStringLiteral("orbital"), 1);
    const CommandOutcome out =
      m_harness.run(QString::fromLatin1(command), options);
    EXPECT_TRUE(out.claimed) << command;
    EXPECT_EQ(out.status, CommandStatus::Failed) << describe(out);
    EXPECT_TRUE(out.clean()) << describe(out);
    EXPECT_EQ(mol->cubeCount(), 0u) << command << " left an empty cube";
  }
}

TEST_F(SurfacesCommandTest, vanDerWaalsMatchesSerialReference)
{
  CommandOutcome out;
  const Cube* cube = runSurface("renderVDW", out);
  ASSERT_NE(cube, nullptr);
  EXPECT_EQ(cube->cubeType(), Cube::Type::VdW);

  const Vector3i dims = cube->dimensions();
  const size_t total = static_cast<size_t>(dims(0)) * dims(1) * dims(2);
  EXPECT_GT(total, 10000u);

  const ReferenceGrid ref = fillReference(*cube, 0.0);
  const size_t inside = ref.insideCount();
  RecordProperty("vdw_voxels", static_cast<int>(total));
  RecordProperty("vdw_inside", static_cast<int>(inside));
  EXPECT_GT(inside, total / 50) << "the reference cube is nearly empty";
  EXPECT_LT(inside, total);

  expectEqual(*cube, ref, "VdW", DistanceTolerance);
  expectGeometry(*cube, spheres(0.0));

  // Every atom center is inside its own sphere.
  for (const AtomSphere& a : spheres(0.0)) {
    const Vector3 rel = (a.first - cube->min()).cwiseQuotient(cube->spacing());
    EXPECT_GT(cube->value(static_cast<int>(std::lround(rel(0))),
                          static_cast<int>(std::lround(rel(1))),
                          static_cast<int>(std::lround(rel(2)))),
              0.0f);
  }
}

TEST_F(SurfacesCommandTest, solventAccessibleMatchesSerialReference)
{
  CommandOutcome out;
  const Cube* cube = runSurface("renderSolventAccessible", out);
  ASSERT_NE(cube, nullptr);
  EXPECT_EQ(cube->cubeType(), Cube::Type::SolventAccessible);

  const Vector3i dims = cube->dimensions();
  const size_t total = static_cast<size_t>(dims(0)) * dims(1) * dims(2);
  EXPECT_GT(total, 10000u);

  const ReferenceGrid ref = fillReference(*cube, SolventProbe);
  const size_t inside = ref.insideCount();
  RecordProperty("sas_voxels", static_cast<int>(total));
  RecordProperty("sas_inside", static_cast<int>(inside));
  EXPECT_GT(inside, total / 50) << "the reference cube is nearly empty";
  EXPECT_LT(inside, total);

  // Regression: the probe once went missing, which made SAS equal to VdW.
  // Compare on the same grid, so only the radii differ.
  EXPECT_GT(inside, fillReference(*cube, 0.0).insideCount());

  expectEqual(*cube, ref, "SAS", DistanceTolerance);
  expectGeometry(*cube, spheres(SolventProbe));
}

TEST_F(SurfacesCommandTest, solventExcludedMatchesSerialReference)
{
  CommandOutcome out;
  const Cube* cube = runSurface("renderSolventExcluded", out);
  ASSERT_NE(cube, nullptr);
  EXPECT_EQ(cube->cubeType(), Cube::Type::SolventExcluded);

  const Vector3i size = cube->dimensions();
  const size_t total = static_cast<size_t>(size(0)) * size(1) * size(2);
  EXPECT_GT(total, 10000u);

  // Stage 1: the SAS fill with a 1.4 A probe (calculateEDT).
  ReferenceGrid ref = fillReference(*cube, SolventProbe, true);
  const size_t sasInside = ref.insideCount();
  EXPECT_GT(sasInside, total / 50) << "the reference cube is nearly empty";

  // Stage 2: the field is sqrt(D2) - probe, with D2 the squared distance in
  // Angstrom to the nearest voxel outside the SAS spheres. Brute force over
  // every inside voxel and every outside voxel; outside voxels are exactly
  // -probe.
  const Vector3 spacing = cube->spacing();
  const double probe = SolventProbe;
  // The nearest outside voxel always has an inside 6-neighbor (the step
  // toward the inside voxel is closer), so only those need checking.
  auto hasInsideNeighbor = [&](int x, int y, int z) {
    const Vector3i voxel(x, y, z);
    for (int axis = 0; axis < 3; ++axis) {
      for (int step : { -1, 1 }) {
        Vector3i n = voxel;
        n(axis) += step;
        if (n(axis) >= 0 && n(axis) < size(axis) &&
            ref.at(n(0), n(1), n(2)) > 0.0f)
          return true;
      }
    }
    return false;
  };
  std::vector<Vector3> outsideVoxels;
  for (int x = 0; x < size(0); x++)
    for (int y = 0; y < size(1); y++)
      for (int z = 0; z < size(2); z++)
        if (ref.at(x, y, z) <= 0.0f && hasInsideNeighbor(x, y, z))
          outsideVoxels.push_back(Vector3(x, y, z).cwiseProduct(spacing));
  EXPECT_FALSE(outsideVoxels.empty());

  size_t negativeInside = 0;
  for (int x = 0; x < size(0); x++) {
    for (int y = 0; y < size(1); y++) {
      for (int z = 0; z < size(2); z++) {
        if (ref.at(x, y, z) <= 0.0f) {
          ref.at(x, y, z) = static_cast<float>(-probe);
          continue;
        }
        const Vector3 pos = Vector3(x, y, z).cwiseProduct(spacing);
        double best = std::numeric_limits<double>::max();
        for (const Vector3& other : outsideVoxels)
          best = std::min(best, (other - pos).squaredNorm());
        const float value = static_cast<float>(std::sqrt(best) - probe);
        ref.at(x, y, z) = value;
        if (value <= 0.0f)
          ++negativeInside;
      }
    }
  }
  size_t sesInside = ref.insideCount();
  RecordProperty("ses_voxels", static_cast<int>(total));
  RecordProperty("ses_sas_inside", static_cast<int>(sasInside));
  RecordProperty("ses_inside", static_cast<int>(sesInside));
  // The probe must erode something, but not everything.
  EXPECT_GT(negativeInside, 0u);
  EXPECT_GT(sesInside, 0u);
  EXPECT_LT(sesInside, sasInside);

  // Near the zero level the plugin measures to the SAS surface itself instead
  // of to voxel centers, which is up to a voxel less than the center-to-center
  // distance. Elsewhere the two agree exactly.
  {
    const double band = 3.0 * spacing.maxCoeff();
    size_t refined = 0, bad = 0;
    for (int x = 0; x < size(0); x++) {
      for (int y = 0; y < size(1); y++) {
        for (int z = 0; z < size(2); z++) {
          const double expected = ref.at(x, y, z);
          const double value = cube->value(x, y, z);
          const bool untouched =
            expected <= -probe + 1.0e-6 || expected >= band;
          if (untouched) {
            if (std::abs(value - expected) > DistanceTolerance)
              ++bad;
          } else {
            ++refined;
            // The center distance overestimates by at most a voxel diagonal
            // over two, 0.87 of a voxel.
            if (value < expected - 0.9 * spacing.maxCoeff() ||
                value > expected + 0.25 * spacing.maxCoeff())
              ++bad;
          }
        }
      }
    }
    EXPECT_GT(refined, 100u);
    EXPECT_EQ(bad, 0u);
  }

  // A heavy atom is buried deeper (its SAS sphere reaches 3.1 A) than the
  // probe can erode (1.4 A), so its center voxel survives.
  for (Index i = 0; i < 3; ++i) {
    const Vector3 rel = (m_harness.molecule()->atomPosition3d(i) - cube->min())
                          .cwiseQuotient(cube->spacing());
    EXPECT_GT(cube->value(static_cast<int>(std::lround(rel(0))),
                          static_cast<int>(std::lround(rel(1))),
                          static_cast<int>(std::lround(rel(2)))),
              0.0f)
      << "heavy atom " << i;
  }
}

namespace {

// Number of grid points along an axis for the given length and spacing.
double voxels(const Vector3& extent, float resolution)
{
  return (extent.x() / resolution) * (extent.y() / resolution) *
         (extent.z() / resolution);
}

} // namespace

TEST(SurfacesResolutionTest, smallMoleculeUnchanged)
{
  // 4HHB-like: 4.7k atoms in a ~70 A padded box. The formula gives
  // 0.02 * cbrt(4700) = 0.34 A, well inside the budget.
  const Vector3 extent(70.0, 80.0, 70.0);
  const float formula = 0.02f * std::cbrt(4700.0f);
  EXPECT_FLOAT_EQ(formula, automaticSurfaceResolution(4700, extent));
  EXPECT_LE(voxels(extent, formula), SurfaceVoxelBudget);

  // Tiny molecule: the clamp to the minimum still applies.
  EXPECT_FLOAT_EQ(0.05f, automaticSurfaceResolution(1, Vector3(8.0, 8.0, 8.0)));
  EXPECT_FLOAT_EQ(0.1f,
                  automaticSurfaceResolution(1, Vector3(8.0, 8.0, 8.0), 0.1f));
  // Over 16k atoms the formula is capped at 0.5 A when the box is small.
  EXPECT_FLOAT_EQ(0.5f,
                  automaticSurfaceResolution(100000, Vector3(60, 60, 60)));
}

TEST(SurfacesResolutionTest, largeExtentIsBudgetLimited)
{
  // A 2MS2-like capsid: 184k atoms in a ~330 A box, which at 0.5 A would be
  // 290M voxels.
  const Vector3 capsid(330.0, 330.0, 330.0);
  ASSERT_GT(voxels(capsid, 0.5f), SurfaceVoxelBudget);
  const float res = automaticSurfaceResolution(184000, capsid);
  EXPECT_GT(res, 0.5f);
  EXPECT_NEAR(SurfaceVoxelBudget, voxels(capsid, res),
              SurfaceVoxelBudget * 1e-3);

  // And a 1M-atom one.
  const Vector3 huge(800.0, 700.0, 750.0);
  const float resHuge = automaticSurfaceResolution(1000000, huge);
  EXPECT_LE(voxels(huge, resHuge), SurfaceVoxelBudget * 1.001);
  EXPECT_GT(resHuge, res);
}

TEST(SurfacesResolutionTest, neverBelowFormula)
{
  for (size_t atoms :
       { size_t(1), size_t(100), size_t(5000), size_t(200000) }) {
    for (float minimum : { 0.05f, 0.1f }) {
      const float formula =
        std::clamp(0.02f * std::cbrt(static_cast<float>(atoms)), minimum, 0.5f);
      for (double length : { 1.0, 20.0, 100.0, 400.0, 2000.0 }) {
        EXPECT_GE(
          automaticSurfaceResolution(
            atoms, Vector3(length, 0.7 * length, 1.3 * length), minimum),
          formula);
      }
    }
  }
}

TEST(SurfacesResolutionTest, monotonicInExtent)
{
  float previous = 0.0f;
  for (double length = 10.0; length <= 3000.0; length *= 1.25) {
    const float res =
      automaticSurfaceResolution(50000, Vector3(length, length, length));
    EXPECT_GE(res, previous) << "length " << length;
    previous = res;
  }
  EXPECT_GT(previous, 0.5f);
}

TEST(SurfacesResolutionTest, degenerateExtent)
{
  const float formula = 0.02f * std::cbrt(1000.0f);
  EXPECT_FLOAT_EQ(formula, automaticSurfaceResolution(1000, Vector3::Zero()));
  EXPECT_FLOAT_EQ(formula, automaticSurfaceResolution(
                             1000, Vector3(1e308, 1e308, 1e308) * 10.0));
}

namespace {

// Calls back on every queued call delivered to the watched object, before
// the slot runs.
class QueuedCallFilter : public QObject
{
public:
  explicit QueuedCallFilter(std::function<void()> callback)
    : m_callback(std::move(callback))
  {
  }

protected:
  bool eventFilter(QObject* watched, QEvent* event) override
  {
    if (event->type() == QEvent::MetaCall)
      m_callback();
    return QObject::eventFilter(watched, event);
  }

private:
  std::function<void()> m_callback;
};

// Watches what the renderer, or a copy of the molecule taken for undo, could
// see while a surface command runs, and copies the molecule mid-calculation.
class PublishProbe
{
public:
  using Hook = std::function<void()>;

  /**
   * @param expectedMeshes The meshes the finished surface has: once any is
   * visible, all of them must be, and complete.
   * @param midCalculation Run once, right after the first copy is taken.
   */
  PublishProbe(Avogadro::QtGui::Molecule* molecule, Index expectedMeshes,
               Hook midCalculation = Hook())
    : m_molecule(molecule), m_expectedMeshes(expectedMeshes),
      m_hook(std::move(midCalculation))
  {
    // calculateEDT() and calculateQM() announce the cleared surfaces before
    // they start any worker, so a call posted from here is queued ahead of
    // every completion and runs while the calculation is still pending.
    QObject::connect(molecule, &Avogadro::QtGui::Molecule::changed, &m_context,
                     [this](unsigned int) {
                       check("changed()");
                       if (m_posted)
                         return;
                       m_posted = true;
                       QMetaObject::invokeMethod(
                         &m_context, [this]() { copyMidCalculation(); },
                         Qt::QueuedConnection);
                     });
    QObject::connect(&m_timer, &QTimer::timeout, &m_context,
                     [this]() { check("event loop"); });
    m_timer.start(0);
  }

  ~PublishProbe() { m_timer.stop(); }

  const QStringList& problems() const { return m_problems; }
  /// Taken while the calculation was running; null if that never happened.
  const Avogadro::Core::Molecule* firstCopy() const { return m_first.get(); }
  /// Taken just before the first queued call delivered to the plugin once the
  /// cube is published: the cube is there, no mesh is yet.
  const Avogadro::Core::Molecule* cubeCopy() const { return m_cubeCopy.get(); }

  /// Take cubeCopy() ahead of the plugin's queued calls (the mesh generators'
  /// finished() reach it that way, after the cube and before any mesh).
  void copyBeforeQueuedCalls(QObject* plugin)
  {
    m_filter = std::make_unique<QueuedCallFilter>([this]() {
      if (!m_cubeCopy && m_molecule->cubeCount() == 1 &&
          m_molecule->meshCount() == 0)
        m_cubeCopy = std::make_unique<Avogadro::Core::Molecule>(*m_molecule);
    });
    plugin->installEventFilter(m_filter.get());
  }

private:
  void copyMidCalculation()
  {
    m_first = std::make_unique<Avogadro::Core::Molecule>(*m_molecule);
    if (m_first->cubeCount() != 0 || m_first->meshCount() != 0) {
      m_problems << QStringLiteral("the copy taken mid-calculation already "
                                   "has %1 cube(s) and %2 mesh(es)")
                      .arg(m_first->cubeCount())
                      .arg(m_first->meshCount());
    }
    if (m_hook)
      m_hook();
  }

  void check(const char* where)
  {
    const Avogadro::QtGui::Molecule& mol = *m_molecule;
    const Index meshes = mol.meshCount();
    if (meshes != 0 && meshes != m_expectedMeshes) {
      m_problems << QStringLiteral("%1: %2 of %3 meshes visible")
                      .arg(QString::fromLatin1(where))
                      .arg(meshes)
                      .arg(m_expectedMeshes);
    }
    for (Index i = 0; i < meshes; ++i) {
      if (mol.mesh(i)->numVertices() == 0) {
        m_problems << QStringLiteral("%1: mesh %2 is visible but empty")
                        .arg(QString::fromLatin1(where))
                        .arg(i);
      }
    }
  }

  Avogadro::QtGui::Molecule* m_molecule;
  Index m_expectedMeshes;
  Hook m_hook;
  QObject m_context;
  QTimer m_timer;
  bool m_posted = false;
  QStringList m_problems;
  std::unique_ptr<Avogadro::Core::Molecule> m_first;
  std::unique_ptr<Avogadro::Core::Molecule> m_cubeCopy;
  std::unique_ptr<QueuedCallFilter> m_filter;
};

// Two s functions, on the two carbons, and a bonding/antibonding pair of
// orbitals: the second has a positive and a negative lobe.
void addTwoCentreBasis(Avogadro::QtGui::Molecule* mol)
{
  auto* basis = new Avogadro::Core::GaussianSet;
  basis->setMolecule(mol);
  unsigned int s = basis->addBasis(0, Avogadro::Core::GaussianSet::S);
  basis->addGto(s, 1.0, 1.3);
  s = basis->addBasis(1, Avogadro::Core::GaussianSet::S);
  basis->addGto(s, 1.0, 1.3);
  basis->setMolecularOrbitals({ 0.7, 0.7, 0.7, -0.7 },
                              Avogadro::Core::BasisSet::Paired);
  basis->setElectronCount(2);
  mol->setBasisSet(basis);
}

} // namespace

// The cube is filled off the molecule and published when complete: a copy
// taken mid-calculation (as an undo snapshot would be) has no cube, and keeps
// none, while the live molecule ends up with the full cube and mesh.
TEST_F(SurfacesCommandTest, copyMidCalculationSeesNoPartialSurface)
{
  struct Case
  {
    const char* command;
    double probe;
  };
  for (const Case& c :
       { Case{ "renderVDW", 0.0 }, Case{ "renderSolventExcluded", -1.0 } }) {
    SCOPED_TRACE(c.command);
    auto* mol = m_harness.molecule();
    PublishProbe probe(mol, 1);
    probe.copyBeforeQueuedCalls(&m_surfaces);
    CommandOutcome out;
    const Cube* cube = runSurface(c.command, out);
    ASSERT_NE(cube, nullptr);
    EXPECT_TRUE(probe.problems().isEmpty())
      << probe.problems().join("; ").toStdString();

    ASSERT_NE(probe.firstCopy(), nullptr) << "never copied mid-calculation";
    EXPECT_EQ(probe.firstCopy()->cubeCount(), 0u);
    EXPECT_EQ(probe.firstCopy()->meshCount(), 0u);

    ASSERT_EQ(mol->meshCount(), 1u);
    EXPECT_GT(std::as_const(*mol).mesh(0)->numVertices(), 0u);
    if (c.probe >= 0.0)
      expectEqual(*cube, fillReference(*cube, c.probe), c.command,
                  DistanceTolerance);

    // Copied between the cube's publication and the mesh's: the cube there
    // is already complete, and it stays without a mesh.
    ASSERT_NE(probe.cubeCopy(), nullptr)
      << "never copied between the cube and its mesh";
    ASSERT_EQ(probe.cubeCopy()->cubeCount(), 1u);
    EXPECT_EQ(*probe.cubeCopy()->cube(0)->data(), *cube->data());
    EXPECT_EQ(probe.cubeCopy()->meshCount(), 0u);
  }
}

TEST_F(SurfacesCommandTest, copyMidOrbitalSeesNoPartialSurface)
{
  auto* mol = m_harness.molecule();
  addTwoCentreBasis(mol);
  m_surfaces.setMolecule(mol); // pick up the basis set

  PublishProbe probe(mol, 2);
  probe.copyBeforeQueuedCalls(&m_surfaces);
  QVariantMap options;
  options.insert(QStringLiteral("resolution"), 0.3);
  options.insert(QStringLiteral("orbital"), 2);
  const CommandOutcome out = m_harness.run(QStringLiteral("renderMO"), options);
  EXPECT_EQ(out.status, CommandStatus::Finished) << describe(out);
  EXPECT_TRUE(out.clean()) << describe(out);
  EXPECT_EQ(out.result.value("cubeIndex").toInt(), 1);
  EXPECT_TRUE(probe.problems().isEmpty())
    << probe.problems().join("; ").toStdString();

  ASSERT_NE(probe.firstCopy(), nullptr) << "never copied mid-calculation";
  EXPECT_EQ(probe.firstCopy()->cubeCount(), 0u);
  EXPECT_EQ(probe.firstCopy()->meshCount(), 0u);

  ASSERT_EQ(mol->cubeCount(), 1u);
  const Cube* cube = std::as_const(*mol).cube(0);
  EXPECT_EQ(cube->cubeType(), Cube::Type::MO);
  const auto range =
    std::minmax_element(cube->data()->begin(), cube->data()->end());
  EXPECT_LT(*range.first, -0.03f);
  EXPECT_GT(*range.second, 0.03f);
  // Copied between the cube's publication and the meshes': complete cube, no
  // mesh yet.
  ASSERT_NE(probe.cubeCopy(), nullptr)
    << "never copied between the cube and its meshes";
  ASSERT_EQ(probe.cubeCopy()->cubeCount(), 1u);
  EXPECT_EQ(*probe.cubeCopy()->cube(0)->data(), *cube->data());
  EXPECT_EQ(probe.cubeCopy()->meshCount(), 0u);
  // Both lobes are published together.
  ASSERT_EQ(mol->meshCount(), 2u);
  EXPECT_GT(std::as_const(*mol).mesh(0)->numVertices(), 0u);
  EXPECT_GT(std::as_const(*mol).mesh(1)->numVertices(), 0u);
}

// An edit that invalidates derived data while the cube is being calculated
// discards the result and fails the command, instead of publishing a surface
// for a structure that no longer exists.
TEST_F(SurfacesCommandTest, editMidCalculationInterruptsCommand)
{
  for (const char* command : { "renderVDW", "renderMO" }) {
    SCOPED_TRACE(command);
    m_harness.buildEmpty();
    buildEthanol();
    auto* mol = m_harness.molecule();
    const bool orbital = QByteArray(command) == "renderMO";
    if (orbital)
      addTwoCentreBasis(mol);
    m_surfaces.setMolecule(mol);

    PublishProbe probe(mol, orbital ? 2 : 1, [mol]() {
      mol->addAtom(1, Vector3(-1.0, -1.0, -1.0));
      mol->emitChanged(Avogadro::QtGui::Molecule::Atoms |
                       Avogadro::QtGui::Molecule::Added);
    });
    QVariantMap options;
    options.insert(QStringLiteral("resolution"), Resolution);
    options.insert(QStringLiteral("orbital"), 2);
    const CommandOutcome out =
      m_harness.run(QString::fromLatin1(command), options);
    ASSERT_NE(probe.firstCopy(), nullptr) << "never copied mid-calculation";
    // The test's own edit is what the harness reports as a violation here.
    EXPECT_EQ(out.status, CommandStatus::Failed) << describe(out);
    EXPECT_EQ(out.failedCount, 1) << describe(out);
    EXPECT_EQ(out.finishedCount, 0) << describe(out);
    EXPECT_EQ(mol->cubeCount(), 0u);
    EXPECT_EQ(mol->meshCount(), 0u);
    EXPECT_TRUE(probe.problems().isEmpty())
      << probe.problems().join("; ").toStdString();
  }

  // And the plugin is ready for the next one.
  CommandOutcome out;
  const Cube* cube = runSurface("renderVDW", out);
  ASSERT_NE(cube, nullptr);
  EXPECT_EQ(m_harness.molecule()->meshCount(), 1u);
  expectEqual(*cube, fillReference(*cube, 0.0), "VdW after an interruption",
              DistanceTolerance);
}

// Switching to another molecule mid-calculation (as closing a window does)
// publishes nothing to either molecule and fails the command.
TEST_F(SurfacesCommandTest, switchMoleculeMidCalculationInterruptsCommand)
{
  Avogadro::QtGui::Molecule other;
  auto* mol = m_harness.molecule();
  PublishProbe probe(mol, 1,
                     [this, &other]() { m_harness.setPluginMolecule(&other); });
  QVariantMap options;
  options.insert(QStringLiteral("resolution"), Resolution);
  const CommandOutcome out =
    m_harness.run(QStringLiteral("renderVDW"), options);
  ASSERT_NE(probe.firstCopy(), nullptr) << "never copied mid-calculation";
  EXPECT_EQ(out.status, CommandStatus::Failed) << describe(out);
  EXPECT_TRUE(out.clean()) << describe(out);
  EXPECT_EQ(mol->cubeCount(), 0u);
  EXPECT_EQ(mol->meshCount(), 0u);
  EXPECT_EQ(other.cubeCount(), 0u);
  EXPECT_EQ(other.meshCount(), 0u);
  m_harness.setPluginMolecule(mol);
}

// The zero level of the distance field is the sphere itself: on an isolated
// atom, with no smoothing, every mesh vertex lies on the van der Waals sphere
// to within a small fraction of the grid spacing. The old +1/-1 fill put the
// vertices at edge midpoints, up to half a voxel off.
TEST(SurfacesDistanceFieldTest, isolatedAtomVerticesLieOnTheSphere)
{
  // Off the grid in every axis, and a few different spacings.
  const Vector3 center(0.137, -0.211, 0.318);
  const double radius = Avogadro::Core::Elements::radiusVDW(6);
  ASSERT_GT(radius, 1.0);

  for (float resolution : { 0.3f, 0.2f, 0.1f }) {
    SCOPED_TRACE(resolution);
    Surfaces surfaces;
    CommandTestHarness harness{ 60000 };
    harness.buildEmpty();
    harness.molecule()->addAtom(6, center);
    harness.attach(&surfaces);
    harness.registerCommands();

    QVariantMap options;
    options.insert(QStringLiteral("resolution"), resolution);
    options.insert(QStringLiteral("smoothing"), 0);
    const CommandOutcome out =
      harness.run(QStringLiteral("renderVDW"), options);
    ASSERT_EQ(out.status, CommandStatus::Finished) << describe(out);
    EXPECT_FLOAT_EQ(out.result.value("isovalue").toFloat(), 0.0f);

    const Cube* cube = harness.molecule()->activeCube();
    ASSERT_NE(cube, nullptr);
    ASSERT_EQ(harness.molecule()->meshCount(), 1u);
    const Mesh* mesh = std::as_const(*harness.molecule()).mesh(0);
    ASSERT_NE(mesh, nullptr);
    ASSERT_GT(mesh->numVertices(), 100u);

    const double spacing = cube->spacing().maxCoeff();
    double worst = 0.0;
    for (const Avogadro::Vector3f& vertex : mesh->vertices()) {
      const double distance = (vertex.cast<double>() - center).norm();
      worst = std::max(worst, std::abs(distance - radius));
    }
    RecordProperty("max_vertex_error_over_spacing",
                   std::to_string(worst / spacing));
    EXPECT_LE(worst, 0.05 * spacing)
      << "max |distance - radius| = " << worst << " A over "
      << mesh->numVertices() << " vertices, spacing " << spacing << " A";
  }
}

namespace {

using Avogadro::Vector3f;

// Unit of work for the tests below: a cube laid out over some spheres.
struct SesGrid
{
  Cube cube;
  std::vector<AtomSphere> sas; // radii include the probe
};

// Lay out a cube over @p atoms (vdW radii) as Surfaces::calculateEDT() does
// and fill it with the new solvent-excluded field. Returns false on failure.
bool buildSes(const std::vector<std::pair<Vector3, int>>& atoms,
              float resolution, SesGrid& grid)
{
  Vector3 low = atoms[0].first, high = atoms[0].first;
  double maxRadius = 0.0;
  for (const auto& atom : atoms) {
    low = low.cwiseMin(atom.first);
    high = high.cwiseMax(atom.first);
    const double radius =
      Avogadro::Core::Elements::radiusVDW(atom.second) + SolventProbe;
    maxRadius = std::max(maxRadius, radius);
    grid.sas.emplace_back(atom.first, radius);
  }
  const float padding = static_cast<float>(maxRadius + SolventProbe + 0.2);
  const Vector3 pad(padding, padding, padding);
  if (!grid.cube.setLimits(Vector3(low - pad), Vector3(high + pad), resolution))
    return false;
  return Avogadro::QtPlugins::fillSolventExcluded(grid.cube, grid.sas,
                                                  SolventProbe);
}

} // namespace

// The exact squared distances of the separable transform, against brute
// force, on a grid whose three spacings differ.
TEST(SurfacesSolventExcludedTest, distanceTransformMatchesBruteForce)
{
  const Vector3i dims(13, 9, 11);
  const Vector3 spacing(0.3, 0.17, 0.5);
  const size_t total = static_cast<size_t>(dims(0)) * dims(1) * dims(2);
  const float inf = std::numeric_limits<float>::infinity();

  for (unsigned seed : { 1u, 2u, 3u }) {
    SCOPED_TRACE(seed);
    // A small deterministic generator; seeds are about 3%, 15% and 40%.
    const unsigned threshold = seed == 1 ? 3 : (seed == 2 ? 15 : 40);
    unsigned state = 12345u * seed;
    std::vector<float> field(total);
    for (float& v : field) {
      state = state * 1664525u + 1013904223u;
      v = ((state >> 16) % 100) < threshold ? 0.0f : inf;
    }
    std::vector<size_t> zeros;
    for (size_t i = 0; i < total; ++i)
      if (field[i] == 0.0f)
        zeros.push_back(i);
    ASSERT_FALSE(zeros.empty());

    std::vector<float> result = field;
    Avogadro::QtPlugins::squaredDistanceTransform(result, dims, spacing);

    auto position = [&](size_t i) -> Vector3 {
      const int z = static_cast<int>(i % dims(2));
      const int y = static_cast<int>((i / dims(2)) % dims(1));
      const int x =
        static_cast<int>(i / (static_cast<size_t>(dims(2)) * dims(1)));
      return Vector3(x, y, z).cwiseProduct(spacing);
    };
    double worst = 0.0;
    for (size_t i = 0; i < total; ++i) {
      double best = std::numeric_limits<double>::max();
      for (size_t j : zeros)
        best = std::min(best, (position(i) - position(j)).squaredNorm());
      ASSERT_TRUE(std::isfinite(result[i]));
      worst = std::max(worst, std::abs(result[i] - best));
      EXPECT_NEAR(result[i], best, 1.0e-5 * (1.0 + best)) << "voxel " << i;
    }
    RecordProperty("worst_error", std::to_string(worst));
  }

  // No seeds at all: nothing is reachable, and nothing becomes NaN.
  std::vector<float> empty(total, inf);
  Avogadro::QtPlugins::squaredDistanceTransform(empty, dims, spacing);
  for (float v : empty)
    EXPECT_TRUE(std::isinf(v));
}

// Two overlapping SAS spheres of radius R at (+-a, 0, 0) cross in a circle of
// radius rho = sqrt(R^2 - a^2) in the plane x = 0. The solvent-excluded
// field is the distance to the complement of the union, less the probe. Near
// the origin the nearest boundary is that crease circle, so at (x, y, z) with
// r = sqrt(y^2 + z^2) the field is sqrt(x^2 + (r - rho)^2) - probe. The zero
// level there is a torus around the crease, at r = rho - sqrt(probe^2 - x^2).
TEST(SurfacesSolventExcludedTest, reentrantCreaseOfTwoSpheres)
{
  const double R = 2.0, a = 0.8, probe = 1.0;
  const double rho = std::sqrt(R * R - a * a); // 1.833 > probe
  ASSERT_GT(rho, probe);
  const double spacing = 0.2;
  const std::vector<AtomSphere> sas = { { Vector3(a, 0, 0), R },
                                        { Vector3(-a, 0, 0), R } };
  // Without and with the grid shifted off the axis.
  for (const Vector3& shift : { Vector3(0, 0, 0), Vector3(0.07, 0.03, 0.05) }) {
    SCOPED_TRACE(shift.norm());
    const Vector3i dims(41, 41, 41);
    Cube cube;
    ASSERT_TRUE(cube.setLimits(Vector3(-4.0, -4.0, -4.0) + shift, dims,
                               Vector3::Constant(spacing)));
    ASSERT_TRUE(Avogadro::QtPlugins::fillSolventExcluded(cube, sas, probe));

    double worstField = 0.0;
    size_t checked = 0;
    for (int ix = 0; ix < dims(0); ++ix) {
      for (int iy = 0; iy < dims(1); ++iy) {
        for (int iz = 0; iz < dims(2); ++iz) {
          const Vector3 pos = cube.min() + Vector3(ix, iy, iz) * spacing;
          const double r = std::hypot(pos(1), pos(2));
          if (std::abs(pos(0)) > 0.4 || r > rho - 0.3)
            continue;
          const double expected = std::hypot(pos(0), r - rho) - probe;
          if (std::abs(expected) > 1.5 * spacing)
            continue; // beyond the refined band
          ++checked;
          worstField =
            std::max(worstField, std::abs(cube.value(ix, iy, iz) - expected));
        }
      }
    }
    EXPECT_GT(checked, 50u);
    RecordProperty("crease_field_error_over_spacing_" +
                     std::to_string(shift.norm()),
                   std::to_string(worstField / spacing));
    EXPECT_LE(worstField, 0.15 * spacing);

    Avogadro::QtGui::MeshGenerator generator;
    Mesh mesh;
    generator.initialize(&cube, &mesh, 0.0f, 0);
    generator.start();
    generator.wait();
    double worstVertex = 0.0;
    size_t vertices = 0;
    for (const Vector3f& vertex : mesh.vertices()) {
      const double x = vertex(0);
      const double r = std::hypot(vertex(1), vertex(2));
      if (std::abs(x) > 0.35 || r > rho)
        continue;
      ++vertices;
      const double residual = std::abs(std::hypot(x, r - rho) - probe);
      worstVertex = std::max(worstVertex, residual);
    }
    EXPECT_GT(vertices, 20u);
    RecordProperty("crease_vertex_error_over_spacing_" +
                     std::to_string(shift.norm()),
                   std::to_string(worstVertex / spacing));
    EXPECT_LE(worstVertex, 0.15 * spacing);
  }
}

// One atom: the solvent-excluded surface is its van der Waals sphere, to
// within the accuracy of the VdW and SAS fields.
TEST(SurfacesSolventExcludedTest, isolatedAtomIsTheVdwSphere)
{
  const Vector3 center(0.137, -0.211, 0.318);
  const double radius = Avogadro::Core::Elements::radiusVDW(6);
  const double sasRadius = radius + SolventProbe;

  struct Layout
  {
    Vector3 spacing;
    const char* name;
  };
  for (const Layout& layout :
       { Layout{ Vector3(0.2, 0.2, 0.2), "cubic_0.2" },
         Layout{ Vector3(0.1, 0.1, 0.1), "cubic_0.1" },
         Layout{ Vector3(0.25, 0.15, 0.2), "anisotropic" } }) {
    SCOPED_TRACE(layout.name);
    const double pad = sasRadius + SolventProbe + 0.2;
    const Vector3 low = center - Vector3::Constant(pad);
    const Vector3i dims =
      (Vector3::Constant(2.0 * pad).cwiseQuotient(layout.spacing))
        .array()
        .ceil()
        .cast<int>()
        .matrix() +
      Vector3i(1, 1, 1);
    Cube cube;
    ASSERT_TRUE(cube.setLimits(low, dims, layout.spacing));
    std::vector<AtomSphere> sas = { { center, sasRadius } };
    ASSERT_TRUE(
      Avogadro::QtPlugins::fillSolventExcluded(cube, sas, SolventProbe));
    for (float v : *cube.data())
      ASSERT_TRUE(std::isfinite(v));

    Avogadro::QtGui::MeshGenerator generator;
    Mesh mesh;
    generator.initialize(&cube, &mesh, 0.0f, 0);
    generator.start();
    generator.wait();
    ASSERT_GT(mesh.numVertices(), 100u);

    const double spacing = layout.spacing.maxCoeff();
    double lowest = 1.0e9, highest = -1.0e9;
    for (const Vector3f& vertex : mesh.vertices()) {
      const double error = (vertex.cast<double>() - center).norm() - radius;
      lowest = std::min(lowest, error);
      highest = std::max(highest, error);
    }
    RecordProperty(
      std::string("error_over_spacing_") + layout.name,
      std::to_string(std::max(std::abs(lowest), std::abs(highest)) / spacing));
    EXPECT_LE(std::max(std::abs(lowest), std::abs(highest)), 0.05 * spacing)
      << "vertex radius error in [" << lowest << ", " << highest
      << "] A, spacing " << spacing << " A";
  }
}

namespace {

// Lisdexamfetamine (Open Babel --gen3d), element and x y z in Angstrom.
const char* const LisdexamfetamineXyz = "C 1.07567 -0.64825 -0.48944\n"
                                        "C 2.51395 -0.27211 -0.13409\n"
                                        "C 3.41366 -1.51182 0.06376\n"
                                        "C 2.98053 -2.41922 1.18950\n"
                                        "C 2.47686 -3.69797 0.91284\n"
                                        "C 2.05655 -4.53170 1.94855\n"
                                        "C 2.13876 -4.09923 3.27054\n"
                                        "C 2.64556 -2.83204 3.55742\n"
                                        "C 3.06772 -1.99690 2.52290\n"
                                        "N 3.05257 0.58147 -1.18696\n"
                                        "C 4.16025 1.38439 -0.99520\n"
                                        "O 4.67725 1.57825 0.10030\n"
                                        "C 4.63592 2.05301 -2.30876\n"
                                        "C 6.10615 2.48192 -2.20278\n"
                                        "C 6.59671 3.26298 -3.42470\n"
                                        "C 8.02891 3.76646 -3.22097\n"
                                        "C 8.52500 4.62948 -4.38199\n"
                                        "N 8.59806 3.87071 -5.62576\n"
                                        "N 4.39836 1.12226 -3.44362\n"
                                        "H 0.59381 -1.20912 0.31685\n"
                                        "H 1.03968 -1.25724 -1.39953\n"
                                        "H 0.47449 0.25026 -0.66871\n"
                                        "H 2.50199 0.32015 0.78922\n"
                                        "H 4.44821 -1.20120 0.26172\n"
                                        "H 3.46134 -2.07868 -0.87593\n"
                                        "H 2.40615 -4.05089 -0.11333\n"
                                        "H 1.66375 -5.51984 1.72313\n"
                                        "H 1.80985 -4.74879 4.07633\n"
                                        "H 2.71239 -2.49517 4.58856\n"
                                        "H 3.46721 -1.01234 2.76284\n"
                                        "H 2.88704 0.34771 -2.16440\n"
                                        "H 4.00426 2.93785 -2.45187\n"
                                        "H 6.74333 1.60166 -2.04596\n"
                                        "H 6.23249 3.10852 -1.31097\n"
                                        "H 5.92913 4.11411 -3.60392\n"
                                        "H 6.55890 2.62464 -4.31373\n"
                                        "H 8.70229 2.91175 -3.07887\n"
                                        "H 8.07627 4.36111 -2.30024\n"
                                        "H 9.51911 5.02194 -4.14166\n"
                                        "H 7.85842 5.48761 -4.52150\n"
                                        "H 9.26069 3.10321 -5.51669\n"
                                        "H 8.97622 4.46754 -6.36078\n"
                                        "H 5.10895 0.38919 -3.40433\n"
                                        "H 4.58251 1.62425 -4.31464\n";

// Caffeine (Open Babel --gen3d).
const char* const CaffeineXyz = "C -3.24648 -1.13001 0.01710\n"
                                "N -2.26204 -0.07794 0.01141\n"
                                "C -2.51652 1.26813 0.00439\n"
                                "N -1.40270 1.97347 0.00102\n"
                                "C -0.41054 1.04011 0.00609\n"
                                "C -0.90503 -0.22869 0.01229\n"
                                "C -0.08039 -1.38610 0.01839\n"
                                "O -0.53632 -2.52567 0.02497\n"
                                "N 1.28337 -1.07869 0.01630\n"
                                "C 2.23113 -2.17576 0.02196\n"
                                "C 1.83395 0.22031 0.01030\n"
                                "O 3.05683 0.39068 0.00943\n"
                                "N 0.94002 1.29161 0.00551\n"
                                "C 1.42493 2.65964 -0.00149\n"
                                "H -4.24801 -0.69215 0.01470\n"
                                "H -3.10930 -1.73019 0.92000\n"
                                "H -3.10928 -1.74007 -0.87915\n"
                                "H -3.51907 1.67754 0.00213\n"
                                "H 1.74314 -3.15348 0.02300\n"
                                "H 2.86391 -2.09412 0.91184\n"
                                "H 2.86978 -2.09905 -0.86418\n"
                                "H 2.51705 2.70546 0.00624\n"
                                "H 1.04753 3.17744 0.88604\n"
                                "H 1.06056 3.16294 -0.90267\n";

std::vector<std::pair<Vector3, int>> parseXyzBody(const char* text)
{
  std::vector<std::pair<Vector3, int>> atoms;
  std::istringstream in(text);
  std::string symbol;
  double x, y, z;
  while (in >> symbol >> x >> y >> z) {
    const unsigned char number =
      Avogadro::Core::Elements::atomicNumberFromSymbol(symbol);
    atoms.emplace_back(Vector3(x, y, z), number);
  }
  return atoms;
}

struct LipschitzResult
{
  size_t pairs = 0, violations = 0;
  double worst = 0.0; // largest |f(a) - f(b)| - |a - b|
};

// f is a distance minus a constant, so it changes by no more than the
// distance between two voxels. Check every pair of 6-neighbors that both lie
// in the refined zone just inside the SAS.
LipschitzResult lipschitz(const std::vector<std::pair<Vector3, int>>& atoms,
                          float resolution)
{
  LipschitzResult result;
  SesGrid grid;
  EXPECT_TRUE(buildSes(atoms, resolution, grid));
  const Vector3i dims = grid.cube.dimensions();
  const Vector3 spacing = grid.cube.spacing();
  const double band = 2.0 * spacing.maxCoeff();
  auto inZone = [&](float v) {
    return v > -SolventProbe + 1.0e-4 && std::abs(v) < band;
  };
  for (int x = 0; x < dims(0); ++x) {
    for (int y = 0; y < dims(1); ++y) {
      for (int z = 0; z < dims(2); ++z) {
        const float a = grid.cube.value(x, y, z);
        if (!inZone(a))
          continue;
        for (int axis = 0; axis < 3; ++axis) {
          const int nx = x + (axis == 0), ny = y + (axis == 1),
                    nz = z + (axis == 2);
          if (nx >= dims(0) || ny >= dims(1) || nz >= dims(2))
            continue;
          const float b = grid.cube.value(nx, ny, nz);
          if (!inZone(b))
            continue;
          ++result.pairs;
          const double excess = std::abs(a - b) - spacing(axis);
          if (excess > 1.0e-4)
            ++result.violations;
          result.worst = std::max(result.worst, excess);
        }
      }
    }
  }
  return result;
}

} // namespace

TEST(SurfacesSolventExcludedTest, fieldIsLipschitzOnSmallMolecules)
{
  const auto caffeine = parseXyzBody(CaffeineXyz);
  ASSERT_EQ(caffeine.size(), 24u);
  const auto lisdex = parseXyzBody(LisdexamfetamineXyz);
  ASSERT_EQ(lisdex.size(), 44u);
  struct Case
  {
    const char* name;
    const std::vector<std::pair<Vector3, int>>* atoms;
    float resolution;
  };
  for (const Case& c : { Case{ "caffeine_0.3", &caffeine, 0.3f },
                         Case{ "caffeine_0.15", &caffeine, 0.15f },
                         Case{ "lisdex_0.3", &lisdex, 0.3f },
                         Case{ "lisdex_0.15", &lisdex, 0.15f } }) {
    SCOPED_TRACE(c.name);
    if (c.atoms->empty())
      continue;
    const LipschitzResult r = lipschitz(*c.atoms, c.resolution);
    std::cout << "lipschitz " << c.name << ": pairs " << r.pairs
              << ", violations " << r.violations << ", worst excess " << r.worst
              << " A\n";
    EXPECT_EQ(r.violations, 0u);
  }
}

// Three equal SAS spheres of radius R, centers on a circle of radius s about
// the z axis at 90, 210 and 330 degrees in the plane z = 0. Their surfaces
// meet at the two points (0, 0, +-hv), where hv = sqrt(R^2 - s^2): those are
// at distance R from all three centers. Between them the axis lies inside
// all three spheres. At (0, 0, t) with t just below hv, the exposed surface
// is the apex of the cone of outside space, with outward normals
// n_m = (-s e_m, hv) / R, e_m the horizontal direction to center m, and the
// displacement (0, 0, -eps) from the apex is the sum of -n_m with equal
// positive weights (the horizontal parts cancel), so the apex is the nearest
// exterior point: the distance is hv - t, and the SES field is hv - t -
// probe. It holds while the apex stays nearer than the creases, which the
// brute-force comparison below confirms for the range tested.
TEST(SurfacesSolventExcludedTest, threeSphereVertex)
{
  const double R = 2.0, s = 1.0, probe = 0.5, spacing = 0.1;
  const double hv = std::sqrt(R * R - s * s);
  std::vector<AtomSphere> sas;
  for (double degrees : { 90.0, 210.0, 330.0 }) {
    const double angle = degrees * 3.141592653589793 / 180.0;
    sas.emplace_back(Vector3(s * std::cos(angle), s * std::sin(angle), 0.0), R);
  }
  Cube cube;
  ASSERT_TRUE(cube.setLimits(Vector3(-4.0, -4.0, -4.0), Vector3i(81, 81, 81),
                             Vector3::Constant(spacing)));
  ASSERT_TRUE(Avogadro::QtPlugins::fillSolventExcluded(cube, sas, probe));

  double worst = 0.0;
  size_t checked = 0;
  for (int iz = 40; iz < 81; ++iz) {
    const double t = cube.min()(2) + iz * spacing;
    const double eps = hv - t;
    if (eps < 0.25 || eps > 0.6)
      continue;
    ++checked;
    worst = std::max(worst, std::abs(cube.value(40, 40, iz) - (eps - probe)));
  }
  EXPECT_GE(checked, 3u);
  RecordProperty("vertex_error_over_spacing", std::to_string(worst / spacing));
  EXPECT_LE(worst, 0.1 * spacing);
}

namespace {

// @p count atoms (C, N, O, H, C, ... in turn) at deterministic pseudo-random
// positions in a cube of side @p box Angstrom, no two closer than
// @p minDistance.
std::vector<std::pair<Vector3, int>> randomCluster(unsigned seed, size_t count,
                                                   double box,
                                                   double minDistance)
{
  std::vector<std::pair<Vector3, int>> atoms;
  unsigned state = seed;
  auto next = [&]() {
    state = state * 1664525u + 1013904223u;
    return static_cast<double>((state >> 8) & 0xFFFF) / 65536.0;
  };
  const int elements[] = { 6, 7, 8, 1, 6 };
  while (atoms.size() < count) {
    const Vector3 p(box * next(), box * next(), box * next());
    const bool clash = std::any_of(atoms.begin(), atoms.end(), [&](auto& a) {
      return (a.first - p).norm() < minDistance;
    });
    if (!clash)
      atoms.emplace_back(p, elements[atoms.size() % 5]);
  }
  return atoms;
}

} // namespace

// The refined field against the distance to a dense sampling of the exposed
// SAS surface, for a crowded cluster of atoms (many creases and vertices).
TEST(SurfacesSolventExcludedTest, matchesSampledSurfaceDistance)
{
  const auto atoms = randomCluster(77u, 22, 5.0, 1.0);
  SesGrid grid;
  ASSERT_TRUE(buildSes(atoms, 0.3f, grid));

  // Fibonacci points on each sphere that no other sphere strictly covers.
  std::vector<Vector3> exposed;
  const int perSphere = 20000;
  for (size_t i = 0; i < grid.sas.size(); ++i) {
    for (int n = 0; n < perSphere; ++n) {
      const double z = 1.0 - 2.0 * (n + 0.5) / perSphere;
      const double r = std::sqrt(1.0 - z * z);
      const double phi = 2.399963229728653 * n;
      const Vector3 p =
        grid.sas[i].first +
        grid.sas[i].second * Vector3(r * std::cos(phi), r * std::sin(phi), z);
      bool covered = false;
      for (size_t k = 0; k < grid.sas.size() && !covered; ++k)
        covered = k != i && (p - grid.sas[k].first).norm() < grid.sas[k].second;
      if (!covered)
        exposed.push_back(p);
    }
  }
  ASSERT_GT(exposed.size(), 1000u);

  const Vector3i dims = grid.cube.dimensions();
  const double band = 2.0 * grid.cube.spacing().maxCoeff();
  size_t checked = 0, tooLow = 0, tooHigh = 0;
  double worstLow = 0.0, worstHigh = 0.0;
  for (int x = 0; x < dims(0); ++x) {
    for (int y = 0; y < dims(1); ++y) {
      for (int z = 0; z < dims(2); ++z) {
        const double f = grid.cube.value(x, y, z);
        if (f <= -SolventProbe + 1.0e-4 || std::abs(f) > band ||
            (x + y + z) % 5 != 0)
          continue;
        const Vector3 pos =
          grid.cube.min() + Vector3(x, y, z).cwiseProduct(grid.cube.spacing());
        double best = 1.0e9;
        for (const Vector3& p : exposed)
          best = std::min(best, (p - pos).squaredNorm());
        best = std::sqrt(best);
        ++checked;
        // The samples are a bit farther than the true surface, up to about
        // half their spacing; the field must never be below the true value.
        const double excess = f + SolventProbe - best;
        if (excess > 0.003) {
          ++tooHigh;
          worstHigh = std::max(worstHigh, excess);
        }
        if (excess < -0.06) {
          ++tooLow;
          worstLow = std::max(worstLow, -excess);
        }
      }
    }
  }
  std::cout << "sampled surface: " << checked << " voxels, " << tooHigh
            << " above (worst " << worstHigh << " A), " << tooLow
            << " below (worst " << worstLow << " A)\n";
  EXPECT_GT(checked, 300u);
  EXPECT_EQ(tooHigh, 0u);
  EXPECT_EQ(tooLow, 0u);
}
