/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "commandtestharness.h"

#include "surfaces.h"

#include <avogadro/core/cube.h>
#include <avogadro/core/elements.h>

#include <QtCore/QVariantMap>

#include <algorithm>
#include <cmath>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

using Avogadro::Index;
using Avogadro::Vector3;
using Avogadro::Vector3i;
using Avogadro::Core::Cube;
using Avogadro::QtPlugins::Surfaces;
using Avogadro::QtPluginsTests::CommandOutcome;
using Avogadro::QtPluginsTests::CommandStatus;
using Avogadro::QtPluginsTests::CommandTestHarness;
using Avogadro::QtPluginsTests::describe;
using Avogadro::QtPluginsTests::recordKnownDeviation;

namespace {

// Requested grid resolution in Angstrom; coarse so the cubes stay small.
constexpr float Resolution = 0.25f;
constexpr double SolventProbe = 1.4;
// calculateEDT() only adds the probe radius for the solvent-excluded type; the
// solvent-accessible type is filled with plain van der Waals radii. The test
// pins that (see solventAccessibleMatchesSerialReference).
constexpr double SasFillProbe = 0.0;

using AtomSphere = std::pair<Vector3, double>; // centre, radius incl. probe

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

  void fillSpheres(const std::vector<AtomSphere>& atoms, const Vector3& min,
                   float res)
  {
    for (const AtomSphere& in : atoms) {
      double startPosX = in.first(0) - in.second;
      double endPosX = in.first(0) + in.second;
      int startIndexX = (startPosX - min(0)) / res;
      int endIndexX = (endPosX - min(0)) / res + 1;
      for (int indexX = startIndexX; indexX < endIndexX; indexX++) {
        double posX = indexX * res + min(0);
        double radiusXsq =
          in.second * in.second - (posX - in.first(0)) * (posX - in.first(0));
        if (radiusXsq < 0.0)
          continue;
        double radiusX = std::sqrt(radiusXsq);
        double startPosY = in.first(1) - radiusX;
        double endPosY = in.first(1) + radiusX;
        int startIndexY = (startPosY - min(1)) / res;
        int endIndexY = (endPosY - min(1)) / res + 1;
        for (int indexY = startIndexY; indexY < endIndexY; indexY++) {
          double posY = indexY * res + min(1);
          double lengthXYsq =
            radiusX * radiusX - (posY - in.first(1)) * (posY - in.first(1));
          if (lengthXYsq < 0.0)
            continue;
          double lengthXY = std::sqrt(lengthXYsq);
          double startPosZ = in.first(2) - lengthXY;
          double endPosZ = in.first(2) + lengthXY;
          int startIndexZ = (startPosZ - min(2)) / res;
          int endIndexZ = (endPosZ - min(2)) / res + 1;
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
    const double margin = 2.0 * Resolution;
    size_t checkedInside = 0, checkedOutside = 0;
    for (int x = 0; x < dims(0); ++x) {
      for (int y = 0; y < dims(1); ++y) {
        for (int z = 0; z < dims(2); ++z) {
          const Vector3 pos(min(0) + x * Resolution, min(1) + y * Resolution,
                            min(2) + z * Resolution);
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
  // laid out like @p cube.
  ReferenceGrid fillReference(const Cube& cube, double probe) const
  {
    ReferenceGrid ref(cube.dimensions());
    ref.fillSpheres(spheres(probe), cube.min(), Resolution);
    return ref;
  }

  void expectEqual(const Cube& cube, const ReferenceGrid& ref, const char* what)
  {
    const Vector3i dims = cube.dimensions();
    size_t mismatches = 0;
    for (int x = 0; x < dims(0); ++x) {
      for (int y = 0; y < dims(1); ++y) {
        for (int z = 0; z < dims(2); ++z) {
          if (cube.value(x, y, z) != ref.at(x, y, z)) {
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

  expectEqual(*cube, ref, "VdW");
  expectGeometry(*cube, spheres(0.0));

  // Every atom centre is inside its own sphere.
  for (const AtomSphere& a : spheres(0.0)) {
    const Vector3 rel = (a.first - cube->min()) / Resolution;
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

  // Surfaces::calculateEDT() leaves probeRadius at 0 for the solvent-accessible
  // type, so today this cube is the van der Waals one. A real SAS surface
  // would use SolventProbe here; when that is fixed, change SasFillProbe.
  recordKnownDeviation("solvent-accessible surface is filled without the "
                       "probe radius");
  const ReferenceGrid ref = fillReference(*cube, SasFillProbe);
  const size_t inside = ref.insideCount();
  RecordProperty("sas_voxels", static_cast<int>(total));
  RecordProperty("sas_inside", static_cast<int>(inside));
  EXPECT_GT(inside, total / 50) << "the reference cube is nearly empty";
  EXPECT_LT(inside, total);

  expectEqual(*cube, ref, "SAS");
  expectGeometry(*cube, spheres(SasFillProbe));
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
  ReferenceGrid ref = fillReference(*cube, SolventProbe);
  const size_t sasInside = ref.insideCount();
  EXPECT_GT(sasInside, total / 50) << "the reference cube is nearly empty";

  // Stage 2: performEDTStep(). It calls resolution() with no argument, which
  // is NOT the resolution the cube was built with: with no dialog it is the
  // automatic value derived from the atom count. Mirror that, so the test
  // pins what the plugin does today.
  const float automatic = std::clamp(
    0.02f * std::pow(static_cast<float>(m_harness.molecule()->atomCount()),
                     1.0f / 3.0f),
    0.05f, 0.5f);
  const double scaledProbe = SolventProbe / automatic;
  if (automatic != Resolution) {
    recordKnownDeviation("performEDTStep() uses resolution() instead of the "
                         "resolution the cube was built with");
  }

  std::vector<Vector3> outsideContact;
  std::vector<Vector3i> insideVoxels;
  for (int z = 0; z < size(2); z++) {
    const int zp = std::max(z - 1, 0);
    const int zn = std::min(z + 1, size(2) - 1);
    for (int y = 0; y < size(1); y++) {
      const int yp = std::max(y - 1, 0);
      const int yn = std::min(y + 1, size(1) - 1);
      for (int x = 0; x < size(0); x++) {
        if (ref.at(x, y, z) > 0.0f) {
          insideVoxels.emplace_back(x, y, z);
          continue;
        }
        const int xp = std::max(x - 1, 0);
        const int xn = std::min(x + 1, size(0) - 1);
        if (ref.at(xp, y, z) > 0.0f || ref.at(xn, y, z) > 0.0f ||
            ref.at(x, yp, z) > 0.0f || ref.at(x, yn, z) > 0.0f ||
            ref.at(x, y, zp) > 0.0f || ref.at(x, y, zn) > 0.0f) {
          outsideContact.emplace_back(x, y, z);
        }
      }
    }
  }
  EXPECT_FALSE(outsideContact.empty());

  // Brute force, no neighbour lists. Marks are applied after the scan, like
  // the plugin, which only ever reads the original outside voxels.
  size_t erased = 0;
  for (const Vector3i& in : insideVoxels) {
    const Vector3 pos = in.cast<double>();
    for (const Vector3& npos : outsideContact) {
      const float distance = (npos - pos).norm();
      if (distance <= scaledProbe) {
        ref.at(in(0), in(1), in(2)) = -1.0f;
        ++erased;
        break;
      }
    }
  }
  const size_t sesInside = ref.insideCount();
  RecordProperty("ses_voxels", static_cast<int>(total));
  RecordProperty("ses_sas_inside", static_cast<int>(sasInside));
  RecordProperty("ses_inside", static_cast<int>(sesInside));
  EXPECT_EQ(sasInside - sesInside, erased);
  EXPECT_LE(sesInside, sasInside);

  expectEqual(*cube, ref, "SES");
}
