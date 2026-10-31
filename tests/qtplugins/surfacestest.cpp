/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "commandtestharness.h"

#include "surfaceresolution.h"
#include "surfaces.h"

#include <avogadro/core/cube.h>
#include <avogadro/core/elements.h>
#include <avogadro/core/gaussianset.h>
#include <avogadro/core/mesh.h>

#include <QtCore/QEvent>
#include <QtCore/QMetaObject>
#include <QtCore/QStringList>
#include <QtCore/QTimer>
#include <QtCore/QVariantMap>

#include <algorithm>
#include <cmath>
#include <functional>
#include <memory>
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

  const ReferenceGrid ref = fillReference(*cube, SolventProbe);
  const size_t inside = ref.insideCount();
  RecordProperty("sas_voxels", static_cast<int>(total));
  RecordProperty("sas_inside", static_cast<int>(inside));
  EXPECT_GT(inside, total / 50) << "the reference cube is nearly empty";
  EXPECT_LT(inside, total);

  // Regression: the probe once went missing, which made SAS equal to VdW.
  // Compare on the same grid, so only the radii differ.
  EXPECT_GT(inside, fillReference(*cube, 0.0).insideCount());

  expectEqual(*cube, ref, "SAS");
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
  ReferenceGrid ref = fillReference(*cube, SolventProbe);
  const size_t sasInside = ref.insideCount();
  EXPECT_GT(sasInside, total / 50) << "the reference cube is nearly empty";

  // Stage 2: performEDTStep() erodes inside voxels within the probe radius,
  // in voxels of the resolution the cube was built with, of the "outside"
  // voxels touching the filled region.
  const double scaledProbe = SolventProbe / Resolution;

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
  // The probe must erode something, but not everything.
  EXPECT_GT(sesInside, 0u);
  EXPECT_LT(sesInside, sasInside);

  expectEqual(*cube, ref, "SES");

  // A heavy atom is buried deeper (its SAS sphere reaches 3.1 A) than the
  // probe can erode (1.4 A), so its centre voxel survives.
  for (Index i = 0; i < 3; ++i) {
    const Vector3 rel =
      (m_harness.molecule()->atomPosition3d(i) - cube->min()) / Resolution;
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
      expectEqual(*cube, fillReference(*cube, c.probe), c.command);

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
  expectEqual(*cube, fillReference(*cube, 0.0), "VdW after an interruption");
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
