/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include "commandtestharness.h"

#include <playertool.h>

#include <avogadro/core/array.h>
#include <avogadro/core/vector.h>
#include <avogadro/qtgui/molecule.h>

#include <QtCore/QTimer>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QSpinBox>
#include <QtWidgets/QWidget>

using Avogadro::Vector3;
using Avogadro::Core::Array;
using Avogadro::QtGui::Molecule;
using Avogadro::QtPlugins::PlayerTool;
using Avogadro::QtPluginsTests::CommandOutcome;
using Avogadro::QtPluginsTests::CommandStatus;
using Avogadro::QtPluginsTests::CommandTestHarness;
using Avogadro::QtPluginsTests::describe;

namespace {

QSpinBox* frameRateControl(QWidget* widget)
{
  for (auto* spinBox : widget->findChildren<QSpinBox*>()) {
    if (spinBox->suffix().trimmed() == QStringLiteral("FPS"))
      return spinBox;
  }
  return nullptr;
}

} // namespace

TEST(PlayerToolCommandTest, FrameRateRejectsNonpositiveValues)
{
  QWidget parent;
  PlayerTool tool(&parent);
  auto* frameRate = frameRateControl(tool.toolWidget());
  ASSERT_NE(frameRate, nullptr);

  frameRate->setValue(0);
  EXPECT_GT(frameRate->value(), 0);

  frameRate->setValue(-1);
  EXPECT_GT(frameRate->value(), 0);
}

TEST(PlayerToolCommandTest, PreservesSupportedFrameRates)
{
  QWidget parent;
  PlayerTool tool(&parent);
  auto* frameRate = frameRateControl(tool.toolWidget());
  ASSERT_NE(frameRate, nullptr);

  EXPECT_EQ(frameRate->value(), 5);
  for (int fps : { 1, 100, 1000 }) {
    frameRate->setValue(fps);
    EXPECT_EQ(frameRate->value(), fps);
  }
}

namespace {

Array<Vector3> positionsAt(double x)
{
  Array<Vector3> result;
  result.push_back(Vector3(x, 0.0, 0.0));
  result.push_back(Vector3(x + 1.0, 0.5, 0.0));
  return result;
}

// A molecule with two atoms and @p sets coordinate sets at x = 10 * set,
// owned by the harness, with the tool attached once it is built.
class PlayerToolSourceTest : public testing::Test
{
protected:
  void build(int sets, int active = 0)
  {
    m_harness.buildEmpty();
    mol().addAtom(6);
    mol().addAtom(8);
    for (int i = 0; i < sets; ++i)
      mol().setCoordinate3d(positionsAt(10.0 * i), i);
    if (sets > 0)
      mol().setCoordinate3d(active);
    else
      mol().setAtomPositions3d(positionsAt(0.0));
    m_harness.attach(&m_tool);
    m_harness.registerCommands();
  }

  // Frames at x = 1, 2, 3 ... (frame 0 is not the rest geometry on purpose,
  // so a displayed frame is easy to tell from the rest).
  Array<Array<Vector3>> frames(int count, double offset = 1.0)
  {
    Array<Array<Vector3>> result;
    for (int i = 0; i < count; ++i)
      result.push_back(positionsAt(offset + i));
    return result;
  }

  // @return Whether the command finished (rather than failed) cleanly.
  bool run(const QString& command, const QVariantMap& options = QVariantMap())
  {
    m_outcome = m_harness.run(command, options);
    EXPECT_TRUE(m_outcome.claimed) << command.toStdString();
    EXPECT_TRUE(m_outcome.clean()) << describe(m_outcome);
    return m_outcome.status == CommandStatus::Finished;
  }

  bool useSource(const QString& id)
  {
    QVariantMap options;
    options.insert("source", id);
    return run("setAnimationSource", options);
  }

  // buildEmpty() replaces the harness molecule, so never cache it.
  Molecule& mol() { return *m_harness.molecule(); }

  // The tool outlives the harness, which disconnects from it on destruction.
  QWidget m_parent;
  PlayerTool m_tool{ &m_parent };
  CommandTestHarness m_harness{ 5000, 5 };
  CommandOutcome m_outcome;
};

} // namespace

TEST_F(PlayerToolSourceTest, ListsTrajectoryFirst)
{
  build(3);
  mol().setAnimationFrames("vibration", "Vibration: mode 1", frames(4));

  ASSERT_TRUE(run("listAnimationSources"));
  const QVariantList sources = m_outcome.result.value("sources").toList();
  ASSERT_EQ(sources.size(), 2);
  EXPECT_EQ(sources[0].toMap().value("id").toString(), QString("trajectory"));
  EXPECT_EQ(sources[0].toMap().value("frames").toInt(), 3);
  EXPECT_EQ(sources[1].toMap().value("id").toString(), QString("vibration"));
  EXPECT_EQ(sources[1].toMap().value("label").toString(),
            QString("Vibration: mode 1"));
  EXPECT_EQ(sources[1].toMap().value("frames").toInt(), 4);
  EXPECT_EQ(m_outcome.result.value("current").toString(),
            QString("trajectory"));
}

// With no coordinate sets, or just one, prefer the published frames.
TEST_F(PlayerToolSourceTest, DefaultSourceWithoutATrajectory)
{
  build(0);
  mol().setAnimationFrames("vibration", "V", frames(4));
  ASSERT_TRUE(run("coordinateSetCount"));
  EXPECT_EQ(m_outcome.result.value("source").toString(), QString("vibration"));
  EXPECT_EQ(m_outcome.result.value("count").toInt(), 4);
}

TEST_F(PlayerToolSourceTest, DefaultSourceWithOneSet)
{
  build(1);
  mol().setAnimationFrames("vibration", "V", frames(4));
  ASSERT_TRUE(run("coordinateSetCount"));
  EXPECT_EQ(m_outcome.result.value("source").toString(), QString("vibration"));
  EXPECT_EQ(m_outcome.result.value("count").toInt(), 4);
}

// With a real trajectory the trajectory stays the default.
TEST_F(PlayerToolSourceTest, DefaultSourceWithATrajectory)
{
  build(3);
  mol().setAnimationFrames("vibration", "V", frames(4));
  ASSERT_TRUE(run("coordinateSetCount"));
  EXPECT_EQ(m_outcome.result.value("source").toString(), QString("trajectory"));
  EXPECT_EQ(m_outcome.result.value("count").toInt(), 3);
}

TEST_F(PlayerToolSourceTest, SetAnimationSource)
{
  build(3);
  mol().setAnimationFrames("vibration", "V", frames(4));

  ASSERT_TRUE(useSource("vibration"));
  EXPECT_EQ(m_outcome.result.value("source").toString(), QString("vibration"));
  EXPECT_EQ(m_outcome.result.value("count").toInt(), 4);

  EXPECT_FALSE(useSource("nonsense"));
  EXPECT_FALSE(run("setAnimationSource"));
  // The failed switch left the source alone.
  ASSERT_TRUE(run("coordinateSetCount"));
  EXPECT_EQ(m_outcome.result.value("source").toString(), QString("vibration"));
}

TEST_F(PlayerToolSourceTest, PublishedFramesWrapAndKeepActiveSet)
{
  build(3, 1);
  mol().setAnimationFrames("vibration", "V", frames(4));
  ASSERT_TRUE(useSource("vibration"));

  const Array<Array<Vector3>> shown = frames(4);
  for (int step = 1; step <= 5; ++step) {
    ASSERT_TRUE(run("nextFrame"));
    const int expected = step % 4;
    EXPECT_EQ(m_outcome.result.value("frame").toInt(), expected);
    EXPECT_EQ(mol().atomPositions3d(), shown[expected]);
    EXPECT_EQ(mol().coordinate3d(), 1);
  }
  ASSERT_TRUE(run("previousFrame"));
  EXPECT_EQ(m_outcome.result.value("frame").toInt(), 0);
  ASSERT_TRUE(run("previousFrame"));
  EXPECT_EQ(m_outcome.result.value("frame").toInt(), 3);

  QVariantMap options;
  options.insert("index", 4);
  EXPECT_FALSE(run("setCoordinateSet", options));
  options.insert("index", 2);
  ASSERT_TRUE(run("setCoordinateSet", options));
  EXPECT_EQ(mol().atomPositions3d(), shown[2]);
}

TEST_F(PlayerToolSourceTest, SwitchingBackRestoresRestGeometry)
{
  build(3, 1);
  mol().setAnimationFrames("vibration", "V", frames(4));
  const Array<Vector3> rest = mol().coordinate3d(1);
  ASSERT_TRUE(useSource("vibration"));
  ASSERT_TRUE(run("nextFrame"));
  EXPECT_NE(mol().atomPositions3d(), rest);

  ASSERT_TRUE(useSource("trajectory"));
  EXPECT_EQ(mol().atomPositions3d(), rest);
  EXPECT_EQ(mol().coordinate3d(), 1);
}

TEST_F(PlayerToolSourceTest, RemovedSourceFallsBackAndRestores)
{
  build(3);
  mol().setAnimationFrames("vibration", "V", frames(4));
  const Array<Vector3> rest = mol().coordinate3d(0);
  ASSERT_TRUE(useSource("vibration"));
  ASSERT_TRUE(run("nextFrame"));

  mol().removeAnimationFrames("vibration");
  EXPECT_EQ(mol().atomPositions3d(), rest);
  ASSERT_TRUE(run("coordinateSetCount"));
  EXPECT_EQ(m_outcome.result.value("source").toString(), QString("trajectory"));
}

TEST_F(PlayerToolSourceTest, RepublishedFramesRedisplayCurrentIndex)
{
  build(3);
  mol().setAnimationFrames("vibration", "V", frames(4));
  ASSERT_TRUE(useSource("vibration"));
  ASSERT_TRUE(run("nextFrame"));
  ASSERT_TRUE(run("nextFrame"));
  EXPECT_EQ(m_outcome.result.value("frame").toInt(), 2);

  const Array<Array<Vector3>> other = frames(6, 100.0);
  mol().setAnimationFrames("vibration", "V2", other);
  EXPECT_EQ(mol().atomPositions3d(), other[2]);
  ASSERT_TRUE(run("coordinateSetCount"));
  EXPECT_EQ(m_outcome.result.value("frame").toInt(), 2);
  EXPECT_EQ(m_outcome.result.value("count").toInt(), 6);
}

TEST_F(PlayerToolSourceTest, ConformerChangeElsewhereResetsFrame)
{
  build(3);
  mol().setAnimationFrames("vibration", "V", frames(4));
  ASSERT_TRUE(useSource("vibration"));
  ASSERT_TRUE(run("nextFrame"));

  mol().setCoordinate3d(2);
  mol().emitChanged(Molecule::Atoms | Molecule::Moved | Molecule::Conformer);
  ASSERT_TRUE(run("coordinateSetCount"));
  EXPECT_EQ(m_outcome.result.value("frame").toInt(), 0);
  // Nothing is displaced until the user steps.
  EXPECT_EQ(mol().atomPositions3d(), mol().coordinate3d(2));

  // Going back to the trajectory leaves the new set alone.
  ASSERT_TRUE(useSource("trajectory"));
  EXPECT_EQ(mol().atomPositions3d(), mol().coordinate3d(2));
}

TEST_F(PlayerToolSourceTest, ForeignClaimStopsPlayback)
{
  build(3);
  mol().setAnimationFrames("vibration", "V", frames(4));
  ASSERT_TRUE(useSource("vibration"));

  auto* timer = m_tool.findChild<QTimer*>();
  ASSERT_NE(timer, nullptr);
  QMetaObject::invokeMethod(&m_tool, "play");
  EXPECT_TRUE(timer->isActive());

  mol().claimAnimationPlayback(&m_tool); // our own claim: keep going
  EXPECT_TRUE(timer->isActive());

  QObject other;
  mol().claimAnimationPlayback(&other);
  EXPECT_FALSE(timer->isActive());
}

TEST_F(PlayerToolSourceTest, SourceComboRowStaysOnceShown)
{
  build(3);
  auto* combo = m_tool.toolWidget()->findChild<QComboBox*>();
  ASSERT_NE(combo, nullptr);
  // Only the trajectory so far: the row is not shown.
  EXPECT_TRUE(combo->parentWidget()->isHidden());

  mol().setAnimationFrames("vibration", "V", frames(4));
  EXPECT_FALSE(combo->parentWidget()->isHidden());
  EXPECT_EQ(combo->count(), 2);
  EXPECT_EQ(combo->itemData(0).toString(), QString("trajectory"));
  EXPECT_EQ(combo->itemData(1).toString(), QString("vibration"));

  mol().removeAnimationFrames("vibration");
  EXPECT_EQ(combo->count(), 1);
  EXPECT_FALSE(combo->parentWidget()->isHidden());
}

namespace {

QPushButton* keepButton(QWidget* widget)
{
  for (auto* button : widget->findChildren<QPushButton*>()) {
    if (button->text() == QStringLiteral("Keep This Frame"))
      return button;
  }
  return nullptr;
}

void addVibrations(Molecule& molecule, size_t conformer)
{
  Array<double> freqs;
  freqs.push_back(1000.0);
  molecule.setVibrationFrequencies(freqs, conformer);
}

} // namespace

TEST_F(PlayerToolSourceTest, KeepFrameAppendsASet)
{
  build(3, 1);
  addVibrations(mol(), 1);
  mol().setAnimationFrames("vibration", "V", frames(4));
  QWidget* widget = m_tool.toolWidget();
  QPushButton* keep = keepButton(widget);
  ASSERT_NE(keep, nullptr);
  // Only offered on a published source.
  EXPECT_TRUE(keep->isHidden());

  ASSERT_TRUE(useSource("vibration"));
  EXPECT_FALSE(keep->isHidden());
  // Nothing is displaced yet, so there is nothing to keep.
  EXPECT_FALSE(keep->isEnabled());
  ASSERT_TRUE(run("nextFrame"));
  ASSERT_TRUE(run("nextFrame"));
  EXPECT_TRUE(keep->isEnabled());
  const Array<Vector3> displayed = mol().atomPositions3d();

  keep->click();
  ASSERT_EQ(mol().coordinate3dCount(), 4u);
  EXPECT_EQ(mol().coordinate3d(3), displayed);
  EXPECT_EQ(mol().coordinate3d(), 1);
  EXPECT_TRUE(mol().hasVibrations(1));
  EXPECT_FALSE(mol().animationFrameIds().isEmpty());

  // Still on the published source, and the trajectory entry counts the set.
  ASSERT_TRUE(run("listAnimationSources"));
  EXPECT_EQ(m_outcome.result.value("current").toString(), QString("vibration"));
  EXPECT_EQ(
    m_outcome.result.value("sources").toList()[0].toMap().value("frames"), 4);
  EXPECT_EQ(mol().atomPositions3d(), displayed);
}

TEST_F(PlayerToolSourceTest, KeepFrameStoresRestAsSetZero)
{
  build(0);
  addVibrations(mol(), 0);
  mol().setAnimationFrames("vibration", "V", frames(4));
  ASSERT_TRUE(run("coordinateSetCount"));
  ASSERT_EQ(m_outcome.result.value("source").toString(), QString("vibration"));
  const Array<Vector3> rest = mol().atomPositions3d();
  ASSERT_TRUE(run("nextFrame"));
  const Array<Vector3> displayed = mol().atomPositions3d();

  QPushButton* keep = keepButton(m_tool.toolWidget());
  ASSERT_NE(keep, nullptr);
  keep->click();
  ASSERT_EQ(mol().coordinate3dCount(), 2u);
  EXPECT_EQ(mol().coordinate3d(0), rest);
  EXPECT_EQ(mol().coordinate3d(1), displayed);
  EXPECT_EQ(mol().coordinate3d(), 0);
  EXPECT_TRUE(mol().hasVibrations(0));
  EXPECT_FALSE(mol().animationFrameIds().isEmpty());
  ASSERT_TRUE(run("coordinateSetCount"));
  EXPECT_EQ(m_outcome.result.value("source").toString(), QString("vibration"));
  EXPECT_EQ(mol().atomPositions3d(), displayed);
}

TEST_F(PlayerToolSourceTest, ReplacingFramesKeepsUserPickedSource)
{
  build(3);
  mol().setAnimationFrames("vibration", "V", frames(4));
  ASSERT_TRUE(useSource("vibration"));

  // The set is replaced in place when the conformer moves between two frames
  // that both have modes.
  mol().setCoordinate3d(1);
  mol().setAnimationFrames("vibration", "V2", frames(5));
  mol().emitChanged(Molecule::Atoms | Molecule::Moved | Molecule::Conformer);
  ASSERT_TRUE(run("coordinateSetCount"));
  EXPECT_EQ(m_outcome.result.value("source").toString(), QString("vibration"));
  EXPECT_EQ(m_outcome.result.value("count").toInt(), 5);
  EXPECT_EQ(mol().atomPositions3d(), mol().coordinate3d(1));
}

TEST_F(PlayerToolSourceTest, RepublishBeforeConformerSignalDoesNotDisplace)
{
  build(3);
  mol().setAnimationFrames("vibration", "V", frames(4));
  ASSERT_TRUE(useSource("vibration"));
  ASSERT_TRUE(run("nextFrame")); // a displaced frame is on screen

  // The plugin that owns the frames republishes before the Player hears
  // about the conformer change.
  mol().setCoordinate3d(2);
  mol().setAnimationFrames("vibration", "V2", frames(4, 50.0));
  mol().emitChanged(Molecule::Atoms | Molecule::Moved | Molecule::Conformer);
  EXPECT_EQ(mol().atomPositions3d(), mol().coordinate3d(2));
  ASSERT_TRUE(run("coordinateSetCount"));
  EXPECT_EQ(m_outcome.result.value("frame").toInt(), 0);

  ASSERT_TRUE(useSource("trajectory"));
  EXPECT_EQ(mol().atomPositions3d(), mol().coordinate3d(2));
}

TEST_F(PlayerToolSourceTest, DisplayLivesInTheMolecule)
{
  build(3);
  mol().setAnimationFrames("vibration", "V", frames(4));
  mol().setAnimationFrames("other", "O", frames(2, 90.0));
  ASSERT_TRUE(useSource("vibration"));
  ASSERT_TRUE(run("nextFrame"));
  EXPECT_EQ(mol().shownAnimationId(), QString("vibration"));
  EXPECT_EQ(mol().shownAnimationFrame(), 1);
  EXPECT_EQ(mol().restPositions3d(), mol().coordinate3d(0));

  // The Player only clears a display it owns.
  ASSERT_TRUE(mol().showAnimationFrame("other", 1));
  ASSERT_TRUE(useSource("trajectory"));
  EXPECT_EQ(mol().shownAnimationId(), QString("other"));

  ASSERT_TRUE(useSource("vibration"));
  ASSERT_TRUE(run("nextFrame"));
  ASSERT_TRUE(useSource("trajectory"));
  EXPECT_FALSE(mol().isShowingAnimationFrame());
  EXPECT_EQ(mol().atomPositions3d(), mol().coordinate3d(0));
}

TEST_F(PlayerToolSourceTest, EditingDisplacedAtomsKeepsTheEdit)
{
  build(3);
  mol().setAnimationFrames("vibration", "V", frames(4));
  ASSERT_TRUE(useSource("vibration"));
  ASSERT_TRUE(run("nextFrame"));

  Array<Vector3> edited = mol().atomPositions3d();
  edited[0] = Vector3(-7.0, 0.0, 0.0);
  mol().setAtomPositions3d(edited);
  mol().emitChanged(Molecule::Atoms | Molecule::Moved);
  EXPECT_FALSE(mol().isShowingAnimationFrame());

  // Leaving the source must not undo the edit.
  ASSERT_TRUE(useSource("trajectory"));
  EXPECT_EQ(mol().atomPositions3d(), edited);
}

TEST_F(PlayerToolSourceTest, LeavesAFrameShownByAnotherAnimatorAlone)
{
  build(3);
  mol().setAnimationFrames("vibration", "V", frames(4));
  ASSERT_TRUE(useSource("vibration"));
  ASSERT_TRUE(run("nextFrame"));

  // The Vibrations plugin claims after us and shows a frame of the same set.
  QObject other;
  mol().claimAnimationPlayback(&other);
  ASSERT_TRUE(mol().showAnimationFrame("vibration", 3));
  ASSERT_TRUE(useSource("trajectory"));
  EXPECT_EQ(mol().shownAnimationId(), QString("vibration"));
  EXPECT_EQ(mol().shownAnimationFrame(), 3);
}

TEST_F(PlayerToolSourceTest, RangeWidgetsFollowASourceSwitch)
{
  build(30);
  QWidget* widget = m_tool.toolWidget();
  const auto spins = widget->findChildren<QSpinBox*>();
  ASSERT_EQ(spins.size(), 4); // frame, start, end, frame rate
  QSpinBox* frame = spins[0];
  QSpinBox* first = spins[1];
  QSpinBox* last = spins[2];
  first->setValue(15);

  mol().setAnimationFrames("vibration", "V", frames(4));
  ASSERT_TRUE(useSource("vibration"));
  EXPECT_EQ(frame->minimum(), 1);
  EXPECT_EQ(frame->maximum(), 4);
  EXPECT_EQ(frame->value(), 1);
  EXPECT_EQ(first->value(), 1);
  EXPECT_EQ(last->value(), 4);
  EXPECT_EQ(m_outcome.result.value("frame").toInt(), 0);
  ASSERT_TRUE(run("coordinateSetCount"));
  EXPECT_EQ(m_outcome.result.value("frame").toInt(), 0);
}

TEST_F(PlayerToolSourceTest, TrajectoryIdIsReserved)
{
  build(3);
  mol().setAnimationFrames("trajectory", "Imposter", frames(4));
  ASSERT_TRUE(run("listAnimationSources"));
  const QVariantList sources = m_outcome.result.value("sources").toList();
  ASSERT_EQ(sources.size(), 1);
  EXPECT_EQ(sources[0].toMap().value("frames").toInt(), 3);
  ASSERT_TRUE(useSource("trajectory"));
  EXPECT_EQ(m_outcome.result.value("count").toInt(), 3);
}

TEST_F(PlayerToolSourceTest, NullMoleculeClearsTheSourceRow)
{
  build(3);
  mol().setAnimationFrames("vibration", "V", frames(4));
  auto* combo = m_tool.toolWidget()->findChild<QComboBox*>();
  ASSERT_NE(combo, nullptr);
  ASSERT_EQ(combo->count(), 2);
  m_tool.setMolecule(nullptr);
  EXPECT_EQ(combo->count(), 0);
  EXPECT_TRUE(combo->parentWidget()->isHidden());
}
