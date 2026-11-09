/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

// BallAndStick::updateCoordinates() must leave exactly what a fresh process()
// would build for the new positions.

#include "ballandstick.h"

#include <avogadro/core/layermanager.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/rendering/cylindergeometry.h>
#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/groupnode.h>
#include <avogadro/rendering/spheregeometry.h>

#include <QtCore/QSettings>
#include <QtCore/QTemporaryDir>

#include <gtest/gtest.h>

#include <functional>
#include <memory>
#include <vector>

using namespace Avogadro;
using Avogadro::QtPlugins::BallAndStick;
using Avogadro::Rendering::CylinderGeometry;
using Avogadro::Rendering::GeometryNode;
using Avogadro::Rendering::GroupNode;
using Avogadro::Rendering::SphereGeometry;

namespace {

struct ActiveMolecule : Core::LayerManager
{
  static void set(const Core::Molecule* molecule)
  {
    setActiveMolecule(molecule);
  }
};

class BallAndStickUpdateTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    ASSERT_TRUE(m_settingsDir.isValid());
    m_oldFormat = QSettings::defaultFormat();
    QSettings::setDefaultFormat(QSettings::IniFormat);
    QSettings::setPath(QSettings::IniFormat, QSettings::UserScope,
                       m_settingsDir.path());
    QSettings::setPath(QSettings::IniFormat, QSettings::SystemScope,
                       m_settingsDir.path());
    QSettings().clear();
    ActiveMolecule::set(&m_molecule);
    buildMolecule();
  }

  void TearDown() override
  {
    ActiveMolecule::set(nullptr);
    QSettings::setDefaultFormat(m_oldFormat);
  }

  // C2H5-CH=CH-C#C-H plus a second frame with every atom displaced.
  void buildMolecule()
  {
    auto& m = m_molecule;
    m.addAtom(6, Vector3(0.0, 0.0, 0.0));  // 0
    m.addAtom(6, Vector3(1.5, 0.1, 0.0));  // 1
    m.addAtom(6, Vector3(2.7, 0.7, 0.3));  // 2
    m.addAtom(6, Vector3(4.0, 0.2, -0.2)); // 3
    m.addAtom(6, Vector3(5.2, 0.5, 0.1));  // 4
    m.addAtom(1, Vector3(6.2, 0.6, 0.2));  // 5
    m.addAtom(1, Vector3(-0.5, 0.9, 0.3)); // 6
    m.addAtom(1, Vector3(2.6, 1.8, 0.4));  // 7
    m.addAtom(8, Vector3(1.6, -1.2, 0.8)); // 8
    m.addBond(0, 1, 1);
    m.addBond(1, 2, 1);
    m.addBond(2, 3, 2);
    m.addBond(3, 4, 3);
    m.addBond(4, 5, 1);
    m.addBond(0, 6, 1);
    m.addBond(2, 7, 1);
    m.addBond(1, 8, 2);
    m.setCoordinate3d(0);
    Core::Array<Vector3> second;
    for (Index i = 0; i < m.atomCount(); ++i) {
      Vector3 p = m.atomPosition3d(i);
      second.push_back(
        Vector3(p.x() * 1.1 + 0.3 * i, p.y() - 0.2 * i, p.z() + 0.05 * i * i));
    }
    m.setCoordinate3d(second, 1);
    m.setCoordinate3d(0);
  }

  void moveAtoms()
  {
    m_molecule.setAtomPosition3d(2, Vector3(2.9, 0.4, 0.9));
    m_molecule.setAtomPosition3d(3, Vector3(4.1, 0.9, -0.6));
    m_molecule.setAtomPosition3d(8, Vector3(1.0, -1.5, 0.1));
  }

  static std::vector<Rendering::Drawable*> drawablesOf(GroupNode& node)
  {
    EXPECT_EQ(node.children().size(), 1u);
    auto* geometry = dynamic_cast<GeometryNode*>(node.children().front().node);
    EXPECT_NE(geometry, nullptr);
    return geometry ? geometry->drawables()
                    : std::vector<Rendering::Drawable*>();
  }

  // Exact comparison of every drawable, including what picking sees.
  void expectSame(GroupNode& a, GroupNode& b)
  {
    auto da = drawablesOf(a);
    auto db = drawablesOf(b);
    ASSERT_EQ(da.size(), 5u);
    ASSERT_EQ(db.size(), 5u);
    for (size_t d = 0; d < 3; ++d) {
      auto* sa = dynamic_cast<SphereGeometry*>(da[d]);
      auto* sb = dynamic_cast<SphereGeometry*>(db[d]);
      ASSERT_TRUE(sa && sb);
      ASSERT_EQ(sa->size(), sb->size());
      EXPECT_EQ(sa->renderPass(), sb->renderPass());
      EXPECT_EQ(sa->opacity(), sb->opacity());
      for (size_t i = 0; i < sa->size(); ++i) {
        const auto& x = sa->spheres()[i];
        const auto& y = sb->spheres()[i];
        EXPECT_EQ(x.center, y.center) << d << ":" << i;
        EXPECT_EQ(x.radius, y.radius) << d << ":" << i;
        EXPECT_EQ(x.color, y.color) << d << ":" << i;
        // Rays through each centre must give the same hits and identifiers.
        Vector3f origin = y.center - Vector3f(0, 0, 10);
        Vector3f dir(0, 0, 1);
        auto ha = sa->hits(origin, origin + dir * 20.0f, dir);
        auto hb = sb->hits(origin, origin + dir * 20.0f, dir);
        ASSERT_EQ(ha.size(), hb.size());
        auto ia = ha.begin();
        auto ib = hb.begin();
        for (; ia != ha.end(); ++ia, ++ib) {
          EXPECT_EQ(ia->first, ib->first);
          EXPECT_EQ(ia->second, ib->second);
        }
      }
    }
    for (size_t d = 3; d < 5; ++d) {
      auto* ca = dynamic_cast<CylinderGeometry*>(da[d]);
      auto* cb = dynamic_cast<CylinderGeometry*>(db[d]);
      ASSERT_TRUE(ca && cb);
      ASSERT_EQ(ca->size(), cb->size());
      EXPECT_EQ(ca->renderPass(), cb->renderPass());
      EXPECT_EQ(ca->opacity(), cb->opacity());
      for (size_t i = 0; i < ca->size(); ++i) {
        const auto& x = ca->cylinders()[i];
        const auto& y = cb->cylinders()[i];
        EXPECT_EQ(x.end1, y.end1) << d << ":" << i;
        EXPECT_EQ(x.end2, y.end2) << d << ":" << i;
        EXPECT_EQ(x.radius, y.radius) << d << ":" << i;
        EXPECT_EQ(x.color, y.color) << d << ":" << i;
        EXPECT_EQ(x.color2, y.color2) << d << ":" << i;
        Vector3f mid = (y.end1 + y.end2) * 0.5f;
        Vector3f origin = mid - Vector3f(0, 0, 10);
        Vector3f dir(0, 0, 1);
        auto ha = ca->hits(origin, origin + dir * 20.0f, dir);
        auto hb = cb->hits(origin, origin + dir * 20.0f, dir);
        ASSERT_EQ(ha.size(), hb.size());
        auto ia = ha.begin();
        auto ib = hb.begin();
        for (; ia != ha.end(); ++ia, ++ib) {
          EXPECT_EQ(ia->first, ib->first);
          EXPECT_EQ(ia->second, ib->second);
        }
      }
    }
  }

  // Build, move, update in place, and compare against a fresh build.
  void runCase(const std::function<void()>& move)
  {
    BallAndStick plugin;
    GroupNode a;
    plugin.process(m_molecule, a);
    auto before = drawablesOf(a);

    move();

    ASSERT_TRUE(plugin.updateCoordinates(m_molecule, a));
    // The same drawables, updated rather than replaced.
    EXPECT_EQ(drawablesOf(a), before);

    BallAndStick fresh;
    GroupNode b;
    fresh.process(m_molecule, b);
    expectSame(a, b);
  }

  QtGui::Molecule m_molecule;
  QTemporaryDir m_settingsDir;
  QSettings::Format m_oldFormat = QSettings::NativeFormat;
};

} // namespace

TEST_F(BallAndStickUpdateTest, movedAtomsMultiBonds)
{
  BallAndStick setup;
  setup.multiBonds(true);
  runCase([this] { moveAtoms(); });
}

TEST_F(BallAndStickUpdateTest, movedAtomsSingleBondsOnly)
{
  BallAndStick setup;
  setup.multiBonds(false);
  runCase([this] { moveAtoms(); });
}

TEST_F(BallAndStickUpdateTest, switchedCoordinateSet)
{
  BallAndStick setup;
  setup.multiBonds(true);
  ASSERT_EQ(m_molecule.coordinate3dCount(), 2u);
  runCase([this] { m_molecule.setCoordinate3d(1); });
}

TEST_F(BallAndStickUpdateTest, translucent)
{
  BallAndStick setup;
  setup.multiBonds(true);
  setup.opacityChanged(40);
  runCase([this] { moveAtoms(); });
}

TEST_F(BallAndStickUpdateTest, hiddenHydrogens)
{
  BallAndStick setup;
  setup.multiBonds(true);
  setup.showHydrogens(false);
  runCase([this] { m_molecule.setCoordinate3d(1); });
}

TEST_F(BallAndStickUpdateTest, selectedAtoms)
{
  BallAndStick setup;
  setup.multiBonds(true);
  m_molecule.setAtomSelected(1, true);
  m_molecule.setAtomSelected(4, true);
  runCase([this] { moveAtoms(); });
}

TEST_F(BallAndStickUpdateTest, fallsBackWhenStale)
{
  BallAndStick plugin;
  GroupNode node;
  // Nothing built yet.
  EXPECT_FALSE(plugin.updateCoordinates(m_molecule, node));

  plugin.process(m_molecule, node);
  EXPECT_TRUE(plugin.updateCoordinates(m_molecule, node));

  // A different node.
  GroupNode other;
  EXPECT_FALSE(plugin.updateCoordinates(m_molecule, other));

  // A different molecule.
  QtGui::Molecule copy(m_molecule);
  EXPECT_FALSE(plugin.updateCoordinates(copy, node));

  // The node was cleared, as GLWidget does before a rebuild.
  node.clear();
  EXPECT_FALSE(plugin.updateCoordinates(m_molecule, node));

  // Rebuilt, then an atom is added.
  plugin.process(m_molecule, node);
  EXPECT_TRUE(plugin.updateCoordinates(m_molecule, node));
  m_molecule.addAtom(1, Vector3(9.0, 9.0, 9.0));
  EXPECT_FALSE(plugin.updateCoordinates(m_molecule, node));

  // Rebuilt, then a bond is added.
  node.clear();
  plugin.process(m_molecule, node);
  m_molecule.addBond(5, 9, 1);
  EXPECT_FALSE(plugin.updateCoordinates(m_molecule, node));
}
