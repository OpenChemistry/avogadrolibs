/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

// Label must not compute partial charges while the scene is being built: the
// Open Babel charge models run a nested event loop, which delivered queued
// mouse moves and rebuilt (and freed) the scene mid-build. Charges are now
// calculated from a queued call after the pass, then the scene is rebuilt.
//
// TextLabel3D's constructor makes OpenGL calls, so these tests need a current
// GL context; they skip when the platform cannot provide one.

#include "commandtestharness.h"

#include "label.h"

#include <avogadro/calc/chargemanager.h>
#include <avogadro/calc/chargemodel.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/groupnode.h>

#include <QtCore/QCoreApplication>
#include <QtCore/QSettings>
#include <QtCore/QTemporaryDir>
#include <QtGui/QOffscreenSurface>
#include <QtGui/QOpenGLContext>
#include <QtGui/QSurfaceFormat>
#include <QtTest/QSignalSpy>

#include <gtest/gtest.h>

#include <string>

using Avogadro::Index;
using Avogadro::MatrixX;
using Avogadro::Vector3;
using Avogadro::QtPlugins::Label;
using Avogadro::QtPluginsTests::CommandTestHarness;
namespace R = Avogadro::Rendering;

namespace {

constexpr int kPartialCharge = 32; // LayerLabel::LabelOptions::PartialCharge
const char* kModelId = "labeltestcharges";

// Counts how often it is asked for charges.
class CountingModel : public Avogadro::Calc::ChargeModel
{
public:
  static int calls;

  ChargeModel* newInstance() const override { return new CountingModel; }
  std::string identifier() const override { return kModelId; }
  std::string name() const override { return "Label test charges"; }
  Avogadro::Core::Molecule::ElementMask elements() const override
  {
    Avogadro::Core::Molecule::ElementMask mask;
    mask.set();
    return mask;
  }
  MatrixX partialCharges(Avogadro::Core::Molecule& mol) const override
  {
    return compute(mol);
  }
  MatrixX partialCharges(const Avogadro::Core::Molecule& mol) const override
  {
    return compute(mol);
  }

private:
  static MatrixX compute(const Avogadro::Core::Molecule& mol)
  {
    ++calls;
    MatrixX charges(mol.atomCount(), 1);
    charges.setConstant(0.25);
    return charges;
  }
};
int CountingModel::calls = 0;

struct GLContext
{
  QOffscreenSurface surface;
  QOpenGLContext context;
  bool ok = false;

  GLContext()
  {
    QSurfaceFormat format;
    format.setVersion(4, 1);
    format.setProfile(QSurfaceFormat::CoreProfile);
    context.setFormat(format);
    if (!context.create())
      return;
    surface.setFormat(context.format());
    surface.create();
    ok = context.makeCurrent(&surface);
  }
  ~GLContext()
  {
    if (ok)
      context.doneCurrent();
  }
};

size_t countDrawables(R::Node* node)
{
  size_t count = 0;
  if (auto* geometry = dynamic_cast<R::GeometryNode*>(node))
    count += geometry->drawables().size();
  if (auto* group = dynamic_cast<R::GroupNode*>(node)) {
    for (const auto& child : group->children())
      count += countDrawables(child.node);
  }
  return count;
}

class LabelChargeTest : public testing::Test
{
protected:
  void SetUp() override
  {
    // Use scratch settings so the user's label options are untouched.
    QSettings::setDefaultFormat(QSettings::IniFormat);
    QSettings::setPath(QSettings::IniFormat, QSettings::UserScope,
                       m_settingsDir.path());
    QSettings settings;
    settings.setValue("label/atomoptions", kPartialCharge);
    settings.setValue("label/bondoptions", 0);
    settings.setValue("label/residueoptions", 0);
    settings.sync();

    if (!m_gl.ok)
      GTEST_SKIP() << "no OpenGL context available";

    CountingModel::calls = 0;
    Avogadro::Calc::ChargeManager::registerModel(new CountingModel);
    m_registered = true;

    m_harness.buildEmpty();
    m_harness.molecule()->addAtom(6, Vector3(0, 0, 0));
    m_harness.molecule()->addAtom(8, Vector3(1.4, 0, 0));
    m_harness.molecule()->addAtom(1, Vector3(-0.6, 0.9, 0));
  }

  void TearDown() override
  {
    if (m_registered)
      Avogadro::Calc::ChargeManager::unregisterModel(kModelId);
  }

  size_t process(Label& label)
  {
    R::GroupNode root;
    auto* node = new R::GroupNode(&root);
    label.process(*m_harness.molecule(), *node);
    return countDrawables(node);
  }

  QTemporaryDir m_settingsDir;
  GLContext m_gl;
  CommandTestHarness m_harness;
  bool m_registered = false;
};

} // namespace

TEST_F(LabelChargeTest, processDoesNotCalculateCharges)
{
  Label label;
  label.setEnabled(true);
  QSignalSpy changed(&label, &Label::drawablesChanged);

  // No charges are stored, so the first pass has none to show, and must not
  // call the model itself.
  process(label);
  EXPECT_EQ(CountingModel::calls, 0);
  EXPECT_TRUE(m_harness.molecule()->partialChargeTypes().empty());

  // A second pass before the event loop runs queues nothing more.
  process(label);
  EXPECT_EQ(CountingModel::calls, 0);

  // From the event loop the charges are calculated once and stored, and a
  // scene rebuild is requested.
  QCoreApplication::processEvents();
  EXPECT_EQ(CountingModel::calls, 1);
  EXPECT_EQ(changed.count(), 1);
  const auto types = m_harness.molecule()->partialChargeTypes();
  ASSERT_EQ(types.size(), 1u);
  const MatrixX charges = m_harness.molecule()->partialCharges(*types.begin());
  EXPECT_EQ(static_cast<Index>(charges.rows()), 3);

  // The rebuild finds them and does not ask again.
  EXPECT_GT(process(label), 0u);
  QCoreApplication::processEvents();
  EXPECT_EQ(CountingModel::calls, 1);
  EXPECT_EQ(changed.count(), 1);
}

TEST_F(LabelChargeTest, failedCalculationIsNotRetried)
{
  // An unregistered model: nothing can calculate charges.
  Avogadro::Calc::ChargeManager::unregisterModel(kModelId);
  m_registered = false;

  Label label;
  label.setEnabled(true);
  QSignalSpy changed(&label, &Label::drawablesChanged);
  for (int i = 0; i < 3; ++i) {
    process(label);
    QCoreApplication::processEvents();
  }
  EXPECT_EQ(CountingModel::calls, 0);
  EXPECT_EQ(changed.count(), 0);
}

TEST_F(LabelChargeTest, shortStoredChargesAreSafe)
{
  // setPartialCharges() only checks the matrix size, so a 1x3 matrix is
  // accepted for three atoms but has fewer rows than atoms; reading
  // charges(atom, 0) for the later atoms used to run past the end.
  MatrixX charges(1, 3);
  charges.setConstant(-0.5);
  m_harness.molecule()->setPartialCharges("mmff94", charges);
  ASSERT_EQ(m_harness.molecule()->atomCount(), 3u);
  ASSERT_FALSE(m_harness.molecule()->partialChargeTypes().empty());

  Label label;
  label.setEnabled(true);
  EXPECT_GT(process(label), 0u);
  QCoreApplication::processEvents();
  EXPECT_EQ(CountingModel::calls, 0);
}
