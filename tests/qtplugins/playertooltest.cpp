/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

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

// A molecule with two atoms and @p sets coordinate sets that sit at x = set.
class PlayerToolSourceTest : public testing::Test
{
protected:
  void build(int sets)
  {
    m_molecule.addAtom(6);
    m_molecule.addAtom(8);
    for (int i = 0; i < sets; ++i)
      m_molecule.setCoordinate3d(positionsAt(10.0 * i), i);
    if (sets > 0)
      m_molecule.setCoordinate3d(0);
    else
      m_molecule.setAtomPositions3d(positionsAt(0.0));
    connectCommands();
  }

  void connectCommands()
  {
    QObject::connect(&m_tool, &PlayerTool::commandFinished,
                     [this](const QString&, const QVariantMap& result) {
                       m_result = result;
                       m_failed = false;
                     });
    QObject::connect(&m_tool, &PlayerTool::commandFailed,
                     [this](const QString& message) {
                       m_message = message;
                       m_failed = true;
                     });
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

  bool run(const QString& command, const QVariantMap& options = QVariantMap())
  {
    m_failed = false;
    m_result.clear();
    EXPECT_TRUE(m_tool.handleCommand(command, options));
    return !m_failed;
  }

  bool useSource(const QString& id)
  {
    QVariantMap options;
    options.insert("source", id);
    return run("setAnimationSource", options);
  }

  QWidget m_parent;
  Molecule m_molecule;
  PlayerTool m_tool{ &m_parent };
  QVariantMap m_result;
  QString m_message;
  bool m_failed = false;
};

} // namespace

TEST_F(PlayerToolSourceTest, ListsTrajectoryFirst)
{
  build(3);
  m_tool.setMolecule(&m_molecule);
  m_molecule.setAnimationFrames("vibration", "Vibration: mode 1", frames(4));

  ASSERT_TRUE(run("listAnimationSources"));
  const QVariantList sources = m_result.value("sources").toList();
  ASSERT_EQ(sources.size(), 2);
  EXPECT_EQ(sources[0].toMap().value("id").toString(), QString("trajectory"));
  EXPECT_EQ(sources[0].toMap().value("frames").toInt(), 3);
  EXPECT_EQ(sources[1].toMap().value("id").toString(), QString("vibration"));
  EXPECT_EQ(sources[1].toMap().value("label").toString(),
            QString("Vibration: mode 1"));
  EXPECT_EQ(sources[1].toMap().value("frames").toInt(), 4);
  EXPECT_EQ(m_result.value("current").toString(), QString("trajectory"));
}

TEST_F(PlayerToolSourceTest, DefaultSource)
{
  // No coordinate sets, or just one: prefer the published frames.
  for (int sets : { 0, 1 }) {
    Molecule molecule;
    molecule.addAtom(6);
    molecule.addAtom(8);
    if (sets > 0)
      molecule.setCoordinate3d(positionsAt(0.0), 0);
    molecule.setAtomPositions3d(positionsAt(0.0));
    QWidget parent;
    PlayerTool tool(&parent);
    tool.setMolecule(&molecule);
    molecule.setAnimationFrames("vibration", "V", frames(4));
    QVariantMap result;
    QObject::connect(
      &tool, &PlayerTool::commandFinished,
      [&result](const QString&, const QVariantMap& r) { result = r; });
    tool.handleCommand("coordinateSetCount", QVariantMap());
    EXPECT_EQ(result.value("source").toString(), QString("vibration"))
      << sets << " sets";
    EXPECT_EQ(result.value("count").toInt(), 4);
  }

  // With a real trajectory the trajectory stays the default.
  build(3);
  m_tool.setMolecule(&m_molecule);
  m_molecule.setAnimationFrames("vibration", "V", frames(4));
  ASSERT_TRUE(run("coordinateSetCount"));
  EXPECT_EQ(m_result.value("source").toString(), QString("trajectory"));
  EXPECT_EQ(m_result.value("count").toInt(), 3);
}

TEST_F(PlayerToolSourceTest, SetAnimationSource)
{
  build(3);
  m_tool.setMolecule(&m_molecule);
  m_molecule.setAnimationFrames("vibration", "V", frames(4));

  ASSERT_TRUE(useSource("vibration"));
  EXPECT_EQ(m_result.value("source").toString(), QString("vibration"));
  EXPECT_EQ(m_result.value("count").toInt(), 4);

  EXPECT_FALSE(useSource("nonsense"));
  EXPECT_FALSE(run("setAnimationSource"));
  // The failed switch left the source alone.
  ASSERT_TRUE(run("coordinateSetCount"));
  EXPECT_EQ(m_result.value("source").toString(), QString("vibration"));
}

TEST_F(PlayerToolSourceTest, PublishedFramesWrapAndKeepActiveSet)
{
  build(3);
  m_molecule.setCoordinate3d(1);
  m_tool.setMolecule(&m_molecule);
  m_molecule.setAnimationFrames("vibration", "V", frames(4));
  ASSERT_TRUE(useSource("vibration"));

  const Array<Array<Vector3>> shown = frames(4);
  for (int step = 1; step <= 5; ++step) {
    ASSERT_TRUE(run("nextFrame"));
    const int expected = step % 4;
    EXPECT_EQ(m_result.value("frame").toInt(), expected);
    EXPECT_EQ(m_molecule.atomPositions3d(), shown[expected]);
    EXPECT_EQ(m_molecule.coordinate3d(), 1);
  }
  ASSERT_TRUE(run("previousFrame"));
  EXPECT_EQ(m_result.value("frame").toInt(), 0);
  ASSERT_TRUE(run("previousFrame"));
  EXPECT_EQ(m_result.value("frame").toInt(), 3);

  QVariantMap options;
  options.insert("index", 4);
  EXPECT_FALSE(run("setCoordinateSet", options));
  options.insert("index", 2);
  ASSERT_TRUE(run("setCoordinateSet", options));
  EXPECT_EQ(m_molecule.atomPositions3d(), shown[2]);
}

TEST_F(PlayerToolSourceTest, SwitchingBackRestoresRestGeometry)
{
  build(3);
  m_molecule.setCoordinate3d(1);
  m_tool.setMolecule(&m_molecule);
  m_molecule.setAnimationFrames("vibration", "V", frames(4));
  const Array<Vector3> rest = m_molecule.coordinate3d(1);
  ASSERT_TRUE(useSource("vibration"));
  ASSERT_TRUE(run("nextFrame"));
  EXPECT_NE(m_molecule.atomPositions3d(), rest);

  ASSERT_TRUE(useSource("trajectory"));
  EXPECT_EQ(m_molecule.atomPositions3d(), rest);
  EXPECT_EQ(m_molecule.coordinate3d(), 1);
}

TEST_F(PlayerToolSourceTest, RemovedSourceFallsBackAndRestores)
{
  build(3);
  m_tool.setMolecule(&m_molecule);
  m_molecule.setAnimationFrames("vibration", "V", frames(4));
  const Array<Vector3> rest = m_molecule.coordinate3d(0);
  ASSERT_TRUE(useSource("vibration"));
  ASSERT_TRUE(run("nextFrame"));

  m_molecule.removeAnimationFrames("vibration");
  EXPECT_EQ(m_molecule.atomPositions3d(), rest);
  ASSERT_TRUE(run("coordinateSetCount"));
  EXPECT_EQ(m_result.value("source").toString(), QString("trajectory"));
}

TEST_F(PlayerToolSourceTest, RepublishedFramesRedisplayCurrentIndex)
{
  build(3);
  m_tool.setMolecule(&m_molecule);
  m_molecule.setAnimationFrames("vibration", "V", frames(4));
  ASSERT_TRUE(useSource("vibration"));
  ASSERT_TRUE(run("nextFrame"));
  ASSERT_TRUE(run("nextFrame"));
  EXPECT_EQ(m_result.value("frame").toInt(), 2);

  const Array<Array<Vector3>> other = frames(6, 100.0);
  m_molecule.setAnimationFrames("vibration", "V2", other);
  EXPECT_EQ(m_molecule.atomPositions3d(), other[2]);
  ASSERT_TRUE(run("coordinateSetCount"));
  EXPECT_EQ(m_result.value("frame").toInt(), 2);
  EXPECT_EQ(m_result.value("count").toInt(), 6);
}

TEST_F(PlayerToolSourceTest, ConformerChangeElsewhereResetsFrame)
{
  build(3);
  m_tool.setMolecule(&m_molecule);
  m_molecule.setAnimationFrames("vibration", "V", frames(4));
  ASSERT_TRUE(useSource("vibration"));
  ASSERT_TRUE(run("nextFrame"));

  m_molecule.setCoordinate3d(2);
  m_molecule.emitChanged(Molecule::Atoms | Molecule::Moved |
                         Molecule::Conformer);
  ASSERT_TRUE(run("coordinateSetCount"));
  EXPECT_EQ(m_result.value("frame").toInt(), 0);
  // Nothing is displaced until the user steps.
  EXPECT_EQ(m_molecule.atomPositions3d(), m_molecule.coordinate3d(2));

  // Going back to the trajectory leaves the new set alone.
  ASSERT_TRUE(useSource("trajectory"));
  EXPECT_EQ(m_molecule.atomPositions3d(), m_molecule.coordinate3d(2));
}

TEST_F(PlayerToolSourceTest, ForeignClaimStopsPlayback)
{
  build(3);
  m_tool.setMolecule(&m_molecule);
  m_molecule.setAnimationFrames("vibration", "V", frames(4));
  ASSERT_TRUE(useSource("vibration"));

  auto* timer = m_tool.findChild<QTimer*>();
  ASSERT_NE(timer, nullptr);
  QMetaObject::invokeMethod(&m_tool, "play");
  EXPECT_TRUE(timer->isActive());

  m_molecule.claimAnimationPlayback(&m_tool); // our own claim: keep going
  EXPECT_TRUE(timer->isActive());

  QObject other;
  m_molecule.claimAnimationPlayback(&other);
  EXPECT_FALSE(timer->isActive());
}

TEST_F(PlayerToolSourceTest, SourceComboRowStaysOnceShown)
{
  build(3);
  m_tool.setMolecule(&m_molecule);
  auto* combo = m_tool.toolWidget()->findChild<QComboBox*>();
  ASSERT_NE(combo, nullptr);
  // Only the trajectory so far: the row is not shown.
  EXPECT_TRUE(combo->parentWidget()->isHidden());

  m_molecule.setAnimationFrames("vibration", "V", frames(4));
  EXPECT_FALSE(combo->parentWidget()->isHidden());
  EXPECT_EQ(combo->count(), 2);
  EXPECT_EQ(combo->itemData(0).toString(), QString("trajectory"));
  EXPECT_EQ(combo->itemData(1).toString(), QString("vibration"));

  m_molecule.removeAnimationFrames("vibration");
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
  build(3);
  m_molecule.setCoordinate3d(1);
  addVibrations(m_molecule, 1);
  m_tool.setMolecule(&m_molecule);
  m_molecule.setAnimationFrames("vibration", "V", frames(4));
  QWidget* widget = m_tool.toolWidget();
  QPushButton* keep = keepButton(widget);
  ASSERT_NE(keep, nullptr);
  // Only offered on a published source.
  EXPECT_TRUE(keep->isHidden());

  ASSERT_TRUE(useSource("vibration"));
  EXPECT_FALSE(keep->isHidden());
  EXPECT_TRUE(keep->isEnabled());
  ASSERT_TRUE(run("nextFrame"));
  ASSERT_TRUE(run("nextFrame"));
  const Array<Vector3> displayed = m_molecule.atomPositions3d();

  keep->click();
  ASSERT_EQ(m_molecule.coordinate3dCount(), 4u);
  EXPECT_EQ(m_molecule.coordinate3d(3), displayed);
  EXPECT_EQ(m_molecule.coordinate3d(), 1);
  EXPECT_TRUE(m_molecule.hasVibrations(1));
  EXPECT_FALSE(m_molecule.animationFrameIds().isEmpty());

  // Still on the published source, and the trajectory entry counts the set.
  ASSERT_TRUE(run("listAnimationSources"));
  EXPECT_EQ(m_result.value("current").toString(), QString("vibration"));
  EXPECT_EQ(m_result.value("sources").toList()[0].toMap().value("frames"), 4);
  EXPECT_EQ(m_molecule.atomPositions3d(), displayed);
}

TEST_F(PlayerToolSourceTest, KeepFrameStoresRestAsSetZero)
{
  build(0);
  addVibrations(m_molecule, 0);
  m_tool.setMolecule(&m_molecule);
  m_molecule.setAnimationFrames("vibration", "V", frames(4));
  ASSERT_TRUE(run("coordinateSetCount"));
  ASSERT_EQ(m_result.value("source").toString(), QString("vibration"));
  const Array<Vector3> rest = m_molecule.atomPositions3d();
  ASSERT_TRUE(run("nextFrame"));
  const Array<Vector3> displayed = m_molecule.atomPositions3d();

  keepButton(m_tool.toolWidget())->click();
  ASSERT_EQ(m_molecule.coordinate3dCount(), 2u);
  EXPECT_EQ(m_molecule.coordinate3d(0), rest);
  EXPECT_EQ(m_molecule.coordinate3d(1), displayed);
  EXPECT_EQ(m_molecule.coordinate3d(), 0);
  EXPECT_TRUE(m_molecule.hasVibrations(0));
  EXPECT_FALSE(m_molecule.animationFrameIds().isEmpty());
  ASSERT_TRUE(run("coordinateSetCount"));
  EXPECT_EQ(m_result.value("source").toString(), QString("vibration"));
  EXPECT_EQ(m_molecule.atomPositions3d(), displayed);
}

TEST_F(PlayerToolSourceTest, ReplacingFramesKeepsUserPickedSource)
{
  build(3);
  m_tool.setMolecule(&m_molecule);
  m_molecule.setAnimationFrames("vibration", "V", frames(4));
  ASSERT_TRUE(useSource("vibration"));

  // The set is replaced in place when the conformer moves between two frames
  // that both have modes.
  m_molecule.setCoordinate3d(1);
  m_molecule.setAnimationFrames("vibration", "V2", frames(5));
  m_molecule.emitChanged(Molecule::Atoms | Molecule::Moved |
                         Molecule::Conformer);
  ASSERT_TRUE(run("coordinateSetCount"));
  EXPECT_EQ(m_result.value("source").toString(), QString("vibration"));
  EXPECT_EQ(m_result.value("count").toInt(), 5);
  EXPECT_EQ(m_molecule.atomPositions3d(), m_molecule.coordinate3d(1));
}

TEST_F(PlayerToolSourceTest, RepublishBeforeConformerSignalDoesNotDisplace)
{
  build(3);
  m_tool.setMolecule(&m_molecule);
  m_molecule.setAnimationFrames("vibration", "V", frames(4));
  ASSERT_TRUE(useSource("vibration"));
  ASSERT_TRUE(run("nextFrame")); // a displaced frame is on screen

  // The plugin that owns the frames republishes before the Player hears
  // about the conformer change.
  m_molecule.setCoordinate3d(2);
  m_molecule.setAnimationFrames("vibration", "V2", frames(4, 50.0));
  EXPECT_EQ(m_molecule.atomPositions3d(), m_molecule.coordinate3d(2));
  m_molecule.emitChanged(Molecule::Atoms | Molecule::Moved |
                         Molecule::Conformer);
  EXPECT_EQ(m_molecule.atomPositions3d(), m_molecule.coordinate3d(2));
  ASSERT_TRUE(run("coordinateSetCount"));
  EXPECT_EQ(m_result.value("frame").toInt(), 0);

  ASSERT_TRUE(useSource("trajectory"));
  EXPECT_EQ(m_molecule.atomPositions3d(), m_molecule.coordinate3d(2));
}
