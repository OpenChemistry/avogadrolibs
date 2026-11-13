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
#include <avogadro/qtgui/rwmolecule.h>
#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/groupnode.h>
#include <avogadro/rendering/textlabel3d.h>

#include <QtCore/QCoreApplication>
#include <QtCore/QSettings>
#include <QtCore/QTemporaryDir>
#include <QtGui/QOffscreenSurface>
#include <QtGui/QOpenGLContext>
#include <QtGui/QSurfaceFormat>
#include <QtTest/QSignalSpy>
#include <QtTest/QTest>

#include <gtest/gtest.h>

#include <string>
#include <vector>

using Avogadro::Index;
using Avogadro::MatrixX;
using Avogadro::Vector3;
using Avogadro::QtPlugins::Label;
using Avogadro::QtPluginsTests::CommandTestHarness;
namespace R = Avogadro::Rendering;

namespace {

constexpr int kPartialCharge = 32; // LayerLabel::LabelOptions::PartialCharge
constexpr int kSettle = 600;       // longer than Label's 300 ms debounce
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
    // Depends on the geometry so a recalculation after a move shows.
    for (Index i = 0; i < mol.atomCount(); ++i)
      charges(i, 0) = 0.25 + mol.atomPosition3d(i).x();
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
    m_previousFormat = QSettings::defaultFormat();
    QSettings::setDefaultFormat(QSettings::IniFormat);
    QSettings::setPath(QSettings::IniFormat, QSettings::UserScope,
                       m_settingsDir.path());
    QSettings settings;
    settings.setValue("label/atomOptions", kPartialCharge);
    settings.setValue("label/bondOptions", 0);
    settings.setValue("label/residueOptions", 0);
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
    QSettings::setDefaultFormat(m_previousFormat);
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
  QSettings::Format m_previousFormat = QSettings::NativeFormat;
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

  // After the debounce the charges are calculated once and stored, and a
  // scene rebuild is requested.
  QTest::qWait(kSettle);
  EXPECT_EQ(CountingModel::calls, 1);
  EXPECT_EQ(changed.count(), 1);
  const auto types = m_harness.molecule()->partialChargeTypes();
  ASSERT_EQ(types.size(), 1u);
  const MatrixX charges = m_harness.molecule()->partialCharges(*types.begin());
  EXPECT_EQ(static_cast<Index>(charges.rows()), 3);

  // The rebuild finds them and does not ask again.
  EXPECT_GT(process(label), 0u);
  QTest::qWait(kSettle);
  EXPECT_EQ(CountingModel::calls, 1);
  EXPECT_EQ(changed.count(), 1);
}

TEST_F(LabelChargeTest, chargesAreRecalculatedAfterAnEditKeepingAtomCount)
{
  Label label;
  label.setEnabled(true);
  auto* mol = m_harness.molecule();

  process(label);
  QTest::qWait(kSettle);
  ASSERT_EQ(CountingModel::calls, 1);
  ASSERT_FALSE(mol->partialChargeTypes().empty());

  // Adding and removing a bond clears the charges but keeps the atom count.
  mol->addBond(0, 1, 1);
  ASSERT_EQ(mol->atomCount(), 3u);
  mol->removeBond(0, 1);
  ASSERT_TRUE(mol->partialChargeTypes().empty());
  ASSERT_EQ(mol->atomCount(), 3u);

  process(label);
  QTest::qWait(kSettle);
  EXPECT_EQ(CountingModel::calls, 2);
  EXPECT_FALSE(mol->partialChargeTypes().empty());
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
    QTest::qWait(kSettle);
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
  QTest::qWait(kSettle);
  EXPECT_EQ(CountingModel::calls, 0);
}

TEST_F(LabelChargeTest, movedAtomsRecomputeOwnChargesDebounced)
{
  Label label;
  label.setEnabled(true);
  auto* mol = m_harness.molecule();

  process(label);
  QTest::qWait(kSettle);
  ASSERT_EQ(CountingModel::calls, 1);
  const std::string type = *mol->partialChargeTypes().begin();
  ASSERT_DOUBLE_EQ(mol->partialCharges(type)(0, 0), 0.25);
  QSignalSpy changed(&label, &Label::drawablesChanged);

  // A burst of moves, as during a drag or an optimization.
  for (int i = 1; i <= 5; ++i) {
    mol->setAtomPosition3d(0, Vector3(i, 0, 0));
    mol->emitChanged(Avogadro::QtGui::Molecule::Atoms |
                     Avogadro::QtGui::Molecule::Moved);
  }
  QCoreApplication::processEvents();
  EXPECT_EQ(CountingModel::calls, 1);
  // The old values stay until the recomputed ones are ready.
  EXPECT_DOUBLE_EQ(mol->partialCharges(type)(0, 0), 0.25);

  QTest::qWait(600);
  EXPECT_EQ(CountingModel::calls, 2);
  EXPECT_DOUBLE_EQ(mol->partialCharges(type)(0, 0), 5.25);
  EXPECT_EQ(changed.count(), 1);

  // Nothing further is pending.
  QTest::qWait(600);
  EXPECT_EQ(CountingModel::calls, 2);
}

TEST_F(LabelChargeTest, movedAtomsLeaveForeignChargesAlone)
{
  Label label;
  label.setEnabled(true);
  auto* mol = m_harness.molecule();

  MatrixX charges(3, 1);
  charges << 0.1, 0.2, 0.3;
  mol->setPartialCharges("From File", charges);

  EXPECT_GT(process(label), 0u);
  QTest::qWait(kSettle);

  mol->setAtomPosition3d(0, Vector3(3, 0, 0));
  mol->emitChanged(Avogadro::QtGui::Molecule::Atoms |
                   Avogadro::QtGui::Molecule::Moved);
  QTest::qWait(600);

  EXPECT_EQ(CountingModel::calls, 0);
  const auto types = mol->partialChargeTypes();
  ASSERT_EQ(types.size(), 1u);
  EXPECT_EQ(*types.begin(), "From File");
  EXPECT_DOUBLE_EQ(mol->partialCharges("From File")(0, 0), 0.1);
}

TEST_F(LabelChargeTest, structuralEditDropsAndRecalculatesCharges)
{
  Label label;
  label.setEnabled(true);
  auto* mol = m_harness.molecule();

  process(label);
  QTest::qWait(kSettle);
  ASSERT_EQ(CountingModel::calls, 1);
  ASSERT_FALSE(mol->partialChargeTypes().empty());

  // An element change goes through RWMolecule; the editing tool then emits
  // Atoms|Modified, which is what discards the charges.
  mol->undoMolecule()->setAtomicNumber(2, 7);
  mol->emitChanged(Avogadro::QtGui::Molecule::Atoms |
                   Avogadro::QtGui::Molecule::Modified);
  EXPECT_TRUE(mol->partialChargeTypes().empty());

  // No debounce is involved: the rebuild queues the calculation.
  process(label);
  QTest::qWait(kSettle);
  EXPECT_EQ(CountingModel::calls, 2);
  EXPECT_FALSE(mol->partialChargeTypes().empty());
}

namespace {
std::vector<std::string> labelTexts(R::Node* node)
{
  std::vector<std::string> texts;
  if (auto* geometry = dynamic_cast<R::GeometryNode*>(node)) {
    for (const auto* drawable : geometry->drawables()) {
      if (const auto* label = dynamic_cast<const R::TextLabel3D*>(drawable))
        texts.push_back(label->text());
    }
  }
  if (auto* group = dynamic_cast<R::GroupNode*>(node)) {
    for (const auto& child : group->children()) {
      auto sub = labelTexts(child.node);
      texts.insert(texts.end(), sub.begin(), sub.end());
    }
  }
  return texts;
}
} // namespace

TEST_F(LabelChargeTest, dragBurstCalculatesOnceAndKeepsLabelsVisible)
{
  Label label;
  label.setEnabled(true);
  auto* mol = m_harness.molecule();

  process(label);
  QTest::qWait(kSettle);
  ASSERT_EQ(CountingModel::calls, 1);
  const std::string type = *mol->partialChargeTypes().begin();
  // The rebuild that drawablesChanged requests displays (and caches) them.
  EXPECT_GT(process(label), 0u);

  // The draw tool and others flag every drag frame as Atoms|Modified, which
  // drops the charges each time.
  for (int i = 1; i <= 10; ++i) {
    mol->setAtomPosition3d(0, Vector3(i, 0, 0));
    mol->emitChanged(Avogadro::QtGui::Molecule::Atoms |
                     Avogadro::QtGui::Molecule::Modified);
    ASSERT_TRUE(mol->partialChargeTypes().empty());

    R::GroupNode root;
    auto* node = new R::GroupNode(&root);
    label.process(*mol, *node);
    // The labels keep the last values instead of blanking.
    const auto texts = labelTexts(node);
    ASSERT_EQ(texts.size(), 3u);
    EXPECT_NE(texts[0].find("0.25"), std::string::npos) << texts[0];
    QCoreApplication::processEvents();
  }
  EXPECT_EQ(CountingModel::calls, 1);

  QTest::qWait(kSettle);
  EXPECT_EQ(CountingModel::calls, 2);
  ASSERT_FALSE(mol->partialChargeTypes().empty());
  EXPECT_DOUBLE_EQ(mol->partialCharges(type)(0, 0), 10.25);

  // A changed atom count must not reuse the cached values.
  mol->addAtom(1, Vector3(3, 3, 0));
  mol->emitChanged(Avogadro::QtGui::Molecule::Atoms |
                   Avogadro::QtGui::Molecule::Added);
  R::GroupNode root;
  auto* node = new R::GroupNode(&root);
  label.process(*mol, *node);
  for (const auto& text : labelTexts(node))
    EXPECT_EQ(text.find("0.25"), std::string::npos) << text;
}
