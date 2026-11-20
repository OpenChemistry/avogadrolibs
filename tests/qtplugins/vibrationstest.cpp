/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <vibrationframes.h>
#include <vibrations.h>

#include <avogadro/qtgui/molecule.h>

#include <QtCore/QTimer>
#include <QtGui/QAction>
#include <QtWidgets/QDialog>
#include <QtWidgets/QLabel>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QWidget>

#include <cmath>

using Avogadro::Vector3;
using Avogadro::Core::Array;
using Avogadro::QtPlugins::nearestVibrationFrame;
using Avogadro::QtPlugins::vibrationFrames;

namespace {

constexpr double pi = 3.14159265358979323846;

// Array's brace initialization picks the iterator constructor for two
// Vector3 values, so build the arrays explicitly.
Array<Vector3> pair(const Vector3& a, const Vector3& b)
{
  Array<Vector3> result;
  result.push_back(a);
  result.push_back(b);
  return result;
}

Array<Vector3> restGeometry()
{
  return pair(Vector3(0.0, 0.0, 0.0), Vector3(1.0, 0.5, -0.25));
}

Array<Vector3> mode()
{
  return pair(Vector3(0.1, 0.0, 0.0), Vector3(-0.2, 0.3, 0.4));
}

} // namespace

TEST(VibrationsCommandTest, FramesFollowSineWithRestFirst)
{
  const int count = 8;
  const auto rest = restGeometry();
  const auto lx = mode();
  const auto frames = vibrationFrames(rest, lx, 2.0, count);
  ASSERT_EQ(frames.size(), static_cast<size_t>(count));

  // Frame 0 is the rest geometry, and the last frame is not a second copy.
  for (size_t i = 0; i < rest.size(); ++i)
    EXPECT_EQ(frames[0][i], rest[i]);
  EXPECT_NE(frames[count - 1][1], rest[1]);

  for (int k = 0; k < count; ++k) {
    ASSERT_EQ(frames[k].size(), rest.size());
    const double s = std::sin(2.0 * pi * k / count);
    for (size_t i = 0; i < rest.size(); ++i)
      EXPECT_NEAR((frames[k][i] - (rest[i] + lx[i] * 2.0 * s)).norm(), 0.0,
                  1e-12);
  }
}

TEST(VibrationsCommandTest, FramesScaleLinearlyWithPeak)
{
  const auto rest = restGeometry();
  const auto lx = mode();
  const auto one = vibrationFrames(rest, lx, 1.0, 12);
  const auto three = vibrationFrames(rest, lx, 3.0, 12);
  ASSERT_EQ(one.size(), three.size());
  for (size_t k = 0; k < one.size(); ++k)
    for (size_t i = 0; i < rest.size(); ++i)
      EXPECT_NEAR(
        ((three[k][i] - rest[i]) - 3.0 * (one[k][i] - rest[i])).norm(), 0.0,
        1e-12);
}

TEST(VibrationsCommandTest, FramesRejectBadInput)
{
  const auto rest = restGeometry();
  const auto lx = mode();
  EXPECT_TRUE(vibrationFrames(rest, lx, 1.0, 0).empty());
  EXPECT_TRUE(vibrationFrames(rest, lx, 1.0, -4).empty());
  EXPECT_TRUE(
    vibrationFrames(Array<Vector3>(), Array<Vector3>(), 1.0, 8).empty());
  Array<Vector3> shortMode;
  shortMode.push_back(Vector3(1.0, 0.0, 0.0));
  EXPECT_TRUE(vibrationFrames(rest, shortMode, 1.0, 8).empty());
  EXPECT_EQ(vibrationFrames(rest, lx, 1.0, 1).size(), 1u);
}

TEST(VibrationsCommandTest, NearestFrame)
{
  EXPECT_EQ(nearestVibrationFrame({ 5, 9 }, 0), 5);
  EXPECT_EQ(nearestVibrationFrame({ 2, 3 }, 10), 3);
  EXPECT_EQ(nearestVibrationFrame({ 9, 2, 5 }, 4), 5);
  EXPECT_EQ(nearestVibrationFrame({ 2, 6 }, 4), 6); // tie goes later
  EXPECT_EQ(nearestVibrationFrame({ 6, 2 }, 4), 6);
  // The current frame is skipped.
  EXPECT_EQ(nearestVibrationFrame({ 1, 4 }, 4), 1);
  EXPECT_EQ(nearestVibrationFrame({ 4 }, 4), -1);
  EXPECT_EQ(nearestVibrationFrame({}, 4), -1);
}

namespace {

// Three coordinate sets, with modes only on set 1.
class VibrationsPluginTest : public testing::Test
{
protected:
  void SetUp() override
  {
    m_molecule.addAtom(6);
    m_molecule.addAtom(8);
    for (size_t set = 0; set < 3; ++set) {
      m_molecule.setCoordinate3d(
        pair(Vector3(0.0, 0.0, set), Vector3(1.2, 0.0, set)), set);
    }
    m_molecule.setCoordinate3d(0);

    Array<double> freqs;
    freqs.push_back(0.1);
    freqs.push_back(1234.56);
    freqs.push_back(2000.0);
    Array<Array<Vector3>> lx;
    for (int mode = 0; mode < 3; ++mode)
      lx.push_back(pair(Vector3(0.0, 0.0, 0.5 * (mode + 1)),
                        Vector3(0.0, 0.0, -0.25 * (mode + 1))));
    m_molecule.setVibrationFrequencies(freqs, 1);
    m_molecule.setVibrationLx(lx, 1);

    m_plugin = new Avogadro::QtPlugins::Vibrations(&m_parent);
    m_plugin->setMolecule(&m_molecule);
  }

  void goTo(int frame)
  {
    m_molecule.setCoordinate3d(frame);
    m_molecule.emitChanged(Avogadro::QtGui::Molecule::Atoms |
                           Avogadro::QtGui::Molecule::Moved |
                           Avogadro::QtGui::Molecule::Conformer);
  }

  QDialog* dialog() { return m_parent.findChild<QDialog*>(); }

  QWidget m_parent;
  Avogadro::QtGui::Molecule m_molecule;
  Avogadro::QtPlugins::Vibrations* m_plugin = nullptr;
};

} // namespace

TEST_F(VibrationsPluginTest, ActionEnabledOnAnyFrame)
{
  EXPECT_EQ(m_molecule.coordinate3d(), 0);
  EXPECT_FALSE(m_molecule.hasVibrations());
  ASSERT_EQ(m_plugin->actions().size(), 1);
  EXPECT_TRUE(m_plugin->actions()[0]->isEnabled());
}

TEST_F(VibrationsPluginTest, PublishesFramesOnlyWhereModesExist)
{
  const QString id = QStringLiteral("vibration");
  EXPECT_TRUE(m_molecule.animationFrameIds().isEmpty());

  goTo(1);
  EXPECT_EQ(m_molecule.animationFrameIds(), QStringList({ id }));
  EXPECT_EQ(m_molecule.animationFrames(id).size(), 20u);
  // The first mode with a positive frequency is the default.
  EXPECT_EQ(m_molecule.animationFrameLabel(id),
            QString::fromUtf8("Vibration: mode 2, 1234.6 cm⁻¹"));

  goTo(2);
  EXPECT_TRUE(m_molecule.animationFrameIds().isEmpty());
  goTo(1);
  EXPECT_FALSE(m_molecule.animationFrameIds().isEmpty());
  goTo(0);
  EXPECT_TRUE(m_molecule.animationFrameIds().isEmpty());
}

TEST_F(VibrationsPluginTest, FramesPerCycleChangesFrameCount)
{
  goTo(1);
  m_plugin->setFramesPerCycle(8);
  EXPECT_EQ(m_molecule.animationFrames("vibration").size(), 8u);
  m_plugin->setFramesPerCycle(1);
  EXPECT_EQ(m_molecule.animationFrames("vibration").size(), 4u);
  m_plugin->setFramesPerCycle(100000);
  EXPECT_EQ(m_molecule.animationFrames("vibration").size(), 200u);
}

TEST_F(VibrationsPluginTest, AmplitudeKeepsItsSquaredScale)
{
  goTo(1);
  m_plugin->setFramesPerCycle(4);
  m_plugin->setAmplitude(20);
  const auto frames = m_molecule.animationFrames("vibration");
  ASSERT_EQ(frames.size(), 4u);
  const Array<Vector3> rest = m_molecule.coordinate3d(1);
  const Array<Vector3> lx = m_molecule.vibrationLx(1);
  EXPECT_EQ(frames[0][0], rest[0]);
  // Frame 1 is the +peak: lx * 0.001 * amplitude^2.
  EXPECT_NEAR((frames[1][1] - (rest[1] + lx[1] * 0.4)).norm(), 0.0, 1e-12);
  EXPECT_NEAR((frames[3][1] - (rest[1] - lx[1] * 0.4)).norm(), 0.0, 1e-12);
}

TEST_F(VibrationsPluginTest, GoToFrameMovesTheActiveFrame)
{
  m_plugin->goToFrame(1);
  EXPECT_EQ(m_molecule.coordinate3d(), 1);
  EXPECT_FALSE(m_molecule.animationFrameIds().isEmpty());
  m_plugin->goToFrame(7); // out of range: ignored
  EXPECT_EQ(m_molecule.coordinate3d(), 1);
}

TEST_F(VibrationsPluginTest, ConformerChangeDoesNotShowDialog)
{
  // Loading a molecule with modes may open the dialog; playback must not.
  QDialog* dlg = dialog();
  if (dlg != nullptr)
    dlg->hide();
  goTo(1);
  goTo(2);
  goTo(0);
  dlg = dialog();
  if (dlg != nullptr)
    EXPECT_FALSE(dlg->isVisible());
}

TEST_F(VibrationsPluginTest, ForeignClaimStopsAnimation)
{
  goTo(1);
  m_plugin->startVibrationAnimation();
  auto* timer = m_plugin->findChild<QTimer*>();
  ASSERT_NE(timer, nullptr);
  EXPECT_TRUE(timer->isActive());

  // Our own claim is not a reason to stop.
  m_molecule.claimAnimationPlayback(m_plugin);
  EXPECT_TRUE(timer->isActive());

  QObject other;
  m_molecule.claimAnimationPlayback(&other);
  EXPECT_FALSE(timer->isActive());
  // The frames stay available for the Animation tool.
  EXPECT_FALSE(m_molecule.animationFrameIds().isEmpty());
}

TEST_F(VibrationsPluginTest, EmptyFramePageOffersNearestFrame)
{
  // Set 0 has no modes, so the dialog points at set 1 (frame numbers are
  // one-based, as in the Animation tool).
  QDialog* dlg = dialog();
  ASSERT_NE(dlg, nullptr);

  bool foundLabel = false;
  for (QLabel* label : dlg->findChildren<QLabel*>()) {
    if (label->text() == QStringLiteral("Vibrations available at frame(s): 2"))
      foundLabel = true;
  }
  EXPECT_TRUE(foundLabel);

  QPushButton* go = nullptr;
  for (QPushButton* button : dlg->findChildren<QPushButton*>()) {
    if (button->text() == QStringLiteral("Go to frame 2"))
      go = button;
  }
  ASSERT_NE(go, nullptr);
  go->click();
  EXPECT_EQ(m_molecule.coordinate3d(), 1);
  EXPECT_FALSE(m_molecule.animationFrameIds().isEmpty());
}

TEST_F(VibrationsPluginTest, HiddenDialogCatchesUpWhenOpened)
{
  QDialog* dlg = dialog();
  ASSERT_NE(dlg, nullptr);
  dlg->hide();
  goTo(1);

  // Still showing the page built for frame 1 (no modes): not rebuilt while
  // hidden.
  bool stale = false;
  for (QLabel* label : dlg->findChildren<QLabel*>()) {
    if (label->text().startsWith(QStringLiteral("Vibrations available")))
      stale = true;
  }
  EXPECT_TRUE(stale);

  m_plugin->openDialog();
  EXPECT_TRUE(dlg->isVisible());
  QPushButton* start = nullptr;
  for (QPushButton* button : dlg->findChildren<QPushButton*>()) {
    if (button->text() == QStringLiteral("Start Animation"))
      start = button;
  }
  ASSERT_NE(start, nullptr);
  EXPECT_TRUE(start->isEnabled()); // the modes page is up to date
}

TEST_F(VibrationsPluginTest, ConformerChangeNeverWithdrawsFramesBetweenModes)
{
  // Give set 2 modes as well, so moving 1 -> 2 republishes.
  Array<double> freqs;
  freqs.push_back(900.0);
  Array<Array<Vector3>> lx;
  lx.push_back(pair(Vector3(0.0, 0.0, 0.5), Vector3(0.0, 0.0, -0.25)));
  m_molecule.setVibrationFrequencies(freqs, 2);
  m_molecule.setVibrationLx(lx, 2);
  goTo(1);
  ASSERT_FALSE(m_molecule.animationFrameIds().isEmpty());

  int emissions = 0;
  bool everMissing = false;
  QObject::connect(&m_molecule,
                   &Avogadro::QtGui::Molecule::animationFramesChanged, [&]() {
                     ++emissions;
                     if (m_molecule.animationFrameIds().isEmpty())
                       everMissing = true;
                   });
  goTo(2);
  EXPECT_GT(emissions, 0);
  EXPECT_FALSE(everMissing);
  EXPECT_EQ(m_molecule.animationFrameLabel("vibration"),
            QString::fromUtf8("Vibration: mode 1, 900.0 cm⁻¹"));

  // Moving to a frame without modes still withdraws them.
  goTo(0);
  EXPECT_TRUE(m_molecule.animationFrameIds().isEmpty());
}

TEST_F(VibrationsPluginTest, AnimationShowsFramesAndStopRestoresRest)
{
  goTo(1);
  const Array<Vector3> rest = m_molecule.coordinate3d(1);
  m_plugin->startVibrationAnimation();
  QMetaObject::invokeMethod(m_plugin, "advanceFrame");
  QMetaObject::invokeMethod(m_plugin, "advanceFrame");
  EXPECT_EQ(m_molecule.shownAnimationId(), QString("vibration"));
  EXPECT_EQ(m_molecule.shownAnimationFrame(), 2);
  EXPECT_EQ(m_molecule.restPositions3d(), rest);
  EXPECT_EQ(m_molecule.coordinate3d(), 1);

  m_plugin->stopVibrationAnimation();
  EXPECT_FALSE(m_molecule.isShowingAnimationFrame());
  EXPECT_EQ(m_molecule.atomPositions3d(), rest);
}

TEST_F(VibrationsPluginTest, ChangingModeKeepsTheShownIndex)
{
  goTo(1);
  m_plugin->startVibrationAnimation();
  QMetaObject::invokeMethod(m_plugin, "advanceFrame");
  QMetaObject::invokeMethod(m_plugin, "advanceFrame");
  const Array<Vector3> rest = m_molecule.coordinate3d(1);

  // Rebuilt frames are built from the rest geometry, not the displaced one.
  m_plugin->setAmplitude(40);
  EXPECT_EQ(m_molecule.restPositions3d(), rest);
  EXPECT_TRUE(m_molecule.isShowingAnimationFrame());
}
