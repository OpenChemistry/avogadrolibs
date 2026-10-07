/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "commandtestharness.h"

#include "spacegroup.h"

#include <avogadro/core/spacegroups.h>
#include <avogadro/core/unitcell.h>

#include <QtCore/QCoreApplication>
#include <QtCore/QTimer>
#include <QtGui/QStandardItemModel>
#include <QtWidgets/QAbstractButton>
#include <QtWidgets/QApplication>
#include <QtWidgets/QDialog>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QMessageBox>
#include <QtWidgets/QTableView>

#include <gtest/gtest.h>

#include <set>

using Avogadro::Vector3;
using Avogadro::Core::SpaceGroups;
using Avogadro::Core::UnitCell;
using Avogadro::QtPlugins::SpaceGroup;
using Avogadro::QtPluginsTests::CommandOutcome;
using Avogadro::QtPluginsTests::CommandStatus;
using Avogadro::QtPluginsTests::CommandTestHarness;
using Avogadro::QtPluginsTests::describe;
using Avogadro::QtPluginsTests::MoleculeSnapshot;

namespace {

// NaCl in the conventional cell, space group F m -3 m (225, Hall number 523).
// Na on the fcc sites and Cl on the octahedral holes: 4 + 4 atoms per cell.
constexpr unsigned short NaClHall = 523;
constexpr double NaClA = 5.64;

// F -4 3 m (216, Hall symbol "F -4 2 3"), zinc blende type. checkPrimitiveCell
// looks at the first character of the Hall symbol, so it only recognizes
// the centered groups that are not centrosymmetric (those start with "-").
constexpr unsigned short ZincBlendeHall = 512;

// Fraction of the way to a dialog that must never appear: while a command
// runs, look for a modal widget and close it, so a bug fails the test
// instead of hanging it.
class DialogWatcher
{
public:
  DialogWatcher()
  {
    QObject::connect(&m_timer, &QTimer::timeout, [this] { check(); });
    m_timer.start(10);
  }

  ~DialogWatcher() { m_timer.stop(); }

  bool dialogSeen() const { return m_seen; }

protected:
  virtual void check()
  {
    QWidget* modal = QApplication::activeModalWidget();
    if (modal == nullptr) {
      for (QWidget* widget : QApplication::topLevelWidgets()) {
        if (qobject_cast<QDialog*>(widget) && widget->isVisible()) {
          modal = widget;
          break;
        }
      }
    }
    if (modal != nullptr) {
      m_seen = true;
      auto* box = qobject_cast<QMessageBox*>(modal);
      if (box != nullptr && box->button(QMessageBox::Cancel) != nullptr)
        box->button(QMessageBox::Cancel)->click();
      else if (auto* dialog = qobject_cast<QDialog*>(modal))
        dialog->reject();
      else
        modal->close();
    }
  }

  QTimer m_timer;
  bool m_seen = false;
};

// Sets the property avogadroapp sets for --skip-dialogs, restores it after
class SkipDialogs
{
public:
  explicit SkipDialogs(bool skip)
    : m_previous(QCoreApplication::instance()->property("avogadro.skipDialogs"))
  {
    QCoreApplication::instance()->setProperty("avogadro.skipDialogs", skip);
  }
  ~SkipDialogs()
  {
    QCoreApplication::instance()->setProperty("avogadro.skipDialogs",
                                              m_previous);
  }

private:
  QVariant m_previous;
};

class SpaceGroupCommandTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    m_harness.buildEmpty();
    m_harness.attach(&m_plugin);
    m_harness.registerCommands();
  }

  void buildNaCl(unsigned short hallNumber = 0)
  {
    m_harness.buildEmpty();
    auto* mol = m_harness.molecule();
    mol->setUnitCell(new UnitCell(Vector3(NaClA, 0.0, 0.0),
                                  Vector3(0.0, NaClA, 0.0),
                                  Vector3(0.0, 0.0, NaClA)));
    mol->addAtom(11, Vector3(0.0, 0.0, 0.0));
    mol->addAtom(17, Vector3(0.5 * NaClA, 0.5 * NaClA, 0.5 * NaClA));
    mol->setHallNumber(hallNumber);
  }

  // The fill actions, found by the menu priority they are registered with
  QAction* actionWithPriority(int priority)
  {
    for (QAction* action : m_plugin.actions()) {
      if (action->property("menu priority").toInt() == priority)
        return action;
    }
    return nullptr;
  }

  unsigned int atomCount() const { return m_harness.molecule()->atomCount(); }

  CommandOutcome runWatched(const QString& command, const QVariantMap& options,
                            bool* dialogSeen)
  {
    DialogWatcher watcher;
    CommandOutcome out = m_harness.run(command, options);
    *dialogSeen = watcher.dialogSeen();
    return out;
  }

  // Run a command that has to fail, without a dialog and without touching
  // the molecule.
  void expectFailure(const QString& command, const QVariantMap& options,
                     const QString& messagePart)
  {
    const MoleculeSnapshot before = m_harness.snapshot();
    const unsigned short hallBefore = m_harness.molecule()->hallNumber();
    bool dialogSeen = false;
    const CommandOutcome out = runWatched(command, options, &dialogSeen);
    EXPECT_FALSE(dialogSeen) << "a dialog was shown";
    EXPECT_TRUE(out.claimed) << describe(out);
    EXPECT_EQ(out.status, CommandStatus::Failed) << describe(out);
    EXPECT_TRUE(out.clean()) << describe(out);
    EXPECT_TRUE(out.message.contains(messagePart))
      << "message: " << out.message.toStdString();
    EXPECT_EQ(m_harness.snapshot().differences(before), QStringList());
    EXPECT_EQ(m_harness.molecule()->hallNumber(), hallBefore);
  }

  SpaceGroup m_plugin;
  CommandTestHarness m_harness;
};

} // namespace

TEST_F(SpaceGroupCommandTest, registersDocumentedCommands)
{
  const auto registered = m_harness.registerCommands();
  EXPECT_TRUE(m_harness.registrationViolations().isEmpty())
    << m_harness.registrationViolations().join("; ").toStdString();
  EXPECT_EQ(registered.keys(),
            QStringList({ "fillTranslationalCell", "fillUnitCell" }));
}

TEST_F(SpaceGroupCommandTest, unknownCommandIsNotClaimed)
{
  buildNaCl();
  const CommandOutcome out = m_harness.run("noSuchCommand");
  EXPECT_FALSE(out.claimed);
  EXPECT_EQ(out.status, CommandStatus::NotHandled);
}

TEST_F(SpaceGroupCommandTest, fillWithHallNumber)
{
  buildNaCl();
  EXPECT_EQ(SpaceGroups::internationalNumber(NaClHall), 225);

  bool dialogSeen = false;
  QVariantMap options;
  options["hallNumber"] = NaClHall;
  CommandOutcome out =
    runWatched("fillTranslationalCell", options, &dialogSeen);
  EXPECT_FALSE(dialogSeen);
  EXPECT_EQ(out.status, CommandStatus::Finished) << describe(out);
  EXPECT_TRUE(out.clean()) << describe(out);
  // 4 Na + 4 Cl: the fcc translations of each atom, nothing on the boundary
  EXPECT_EQ(atomCount(), 8u);
  EXPECT_EQ(m_harness.molecule()->hallNumber(), NaClHall);

  // fillUnitCell also copies the atoms on the cell boundary: Na (0,0,0) gets
  // 7 copies, the three Na at a face centre 1 each, the three Cl on an edge
  // centre 3 each, and Cl (1/2,1/2,1/2) none: 8 + 7 + 3 + 9 = 27.
  buildNaCl();
  out = runWatched("fillUnitCell", options, &dialogSeen);
  EXPECT_FALSE(dialogSeen);
  EXPECT_EQ(out.status, CommandStatus::Finished) << describe(out);
  EXPECT_TRUE(out.clean()) << describe(out);
  EXPECT_EQ(atomCount(), 27u);
  EXPECT_EQ(m_harness.molecule()->hallNumber(), NaClHall);

  // and it is one step on the undo stack
  EXPECT_TRUE(m_harness.undo().isEmpty());
  EXPECT_EQ(atomCount(), 2u);
}

TEST_F(SpaceGroupCommandTest, fillWithSpaceGroupSymbol)
{
  for (const char* symbol : { "F m -3 m", "F m 3 m", "Fm-3m", "225" }) {
    buildNaCl();
    bool dialogSeen = false;
    QVariantMap options;
    options["spaceGroup"] = QString(symbol);
    const CommandOutcome out =
      runWatched("fillTranslationalCell", options, &dialogSeen);
    EXPECT_FALSE(dialogSeen) << symbol;
    EXPECT_EQ(out.status, CommandStatus::Finished)
      << symbol << ": " << describe(out);
    EXPECT_EQ(atomCount(), 8u) << symbol;
    EXPECT_EQ(m_harness.molecule()->hallNumber(), NaClHall) << symbol;
  }
}

TEST_F(SpaceGroupCommandTest, storedHallNumberNeedsNoParameter)
{
  buildNaCl(NaClHall);
  bool dialogSeen = false;
  const CommandOutcome out =
    runWatched("fillTranslationalCell", QVariantMap(), &dialogSeen);
  EXPECT_FALSE(dialogSeen);
  EXPECT_EQ(out.status, CommandStatus::Finished) << describe(out);
  EXPECT_TRUE(out.clean()) << describe(out);
  EXPECT_EQ(atomCount(), 8u);

  buildNaCl(NaClHall);
  const CommandOutcome out2 =
    runWatched("fillUnitCell", QVariantMap(), &dialogSeen);
  EXPECT_FALSE(dialogSeen);
  EXPECT_EQ(out2.status, CommandStatus::Finished) << describe(out2);
  EXPECT_EQ(atomCount(), 27u);
}

TEST_F(SpaceGroupCommandTest, explicitParameterWinsOverStoredHallNumber)
{
  // P 1 (hall number 1) would add nothing at all
  buildNaCl(1);
  QVariantMap options;
  options["hallNumber"] = NaClHall;
  const CommandOutcome out = m_harness.run("fillTranslationalCell", options);
  EXPECT_EQ(out.status, CommandStatus::Finished) << describe(out);
  EXPECT_EQ(atomCount(), 8u);
  EXPECT_EQ(m_harness.molecule()->hallNumber(), NaClHall);

  buildNaCl(1);
  QVariantMap symbolOptions;
  symbolOptions["spaceGroup"] = QString("F m -3 m");
  const CommandOutcome out2 =
    m_harness.run("fillTranslationalCell", symbolOptions);
  EXPECT_EQ(out2.status, CommandStatus::Finished) << describe(out2);
  EXPECT_EQ(atomCount(), 8u);
}

TEST_F(SpaceGroupCommandTest, missingSpaceGroupFailsWithoutDialog)
{
  for (bool skip : { false, true }) {
    SkipDialogs skipDialogs(skip);
    for (const char* command : { "fillUnitCell", "fillTranslationalCell" }) {
      buildNaCl();
      EXPECT_EQ(m_harness.molecule()->hallNumber(), 0);
      expectFailure(command, QVariantMap(), "hallNumber");
      EXPECT_EQ(atomCount(), 2u);
    }
  }

  // also when a file reader kept the table number of an ambiguous setting:
  // a command does not ask which one.
  buildNaCl();
  m_harness.molecule()->setData(SpaceGroups::internationalNumberKey(), 225);
  expectFailure("fillUnitCell", QVariantMap(), "hallNumber");
}

TEST_F(SpaceGroupCommandTest, invalidHallNumberFails)
{
  // even when the molecule has a valid space group of its own
  for (unsigned short stored : { 0, 523 }) {
    buildNaCl(stored);
    for (const QVariant& value :
         { QVariant(0), QVariant(531), QVariant(-1), QVariant(1000),
           QVariant(523.5), QVariant(QString("abc")), QVariant(true),
           QVariant(QString("523")), QVariant() }) {
      QVariantMap options;
      options["hallNumber"] = value;
      expectFailure("fillTranslationalCell", options, "hallNumber");
    }
    EXPECT_EQ(atomCount(), 2u);
  }
}

TEST_F(SpaceGroupCommandTest, invalidSpaceGroupFails)
{
  for (unsigned short stored : { 0, 523 }) {
    buildNaCl(stored);
    // "74" is Imma, which has six settings: not a single Hall number
    for (const char* symbol : { "", "garbage", "74", "P 99 99", "C 1" }) {
      QVariantMap options;
      options["spaceGroup"] = QString(symbol);
      expectFailure("fillUnitCell", options, "spaceGroup");
    }
    QVariantMap options;
    options["spaceGroup"] = 225;
    expectFailure("fillUnitCell", options, "spaceGroup");
    EXPECT_EQ(atomCount(), 2u);
  }
}

TEST_F(SpaceGroupCommandTest, bothParametersFail)
{
  buildNaCl();
  QVariantMap options;
  options["hallNumber"] = NaClHall;
  options["spaceGroup"] = QString("F m -3 m");
  expectFailure("fillUnitCell", options, "not both");
}

TEST_F(SpaceGroupCommandTest, noUnitCellFails)
{
  m_harness.buildMethanol();
  QVariantMap options;
  options["hallNumber"] = NaClHall;
  expectFailure("fillUnitCell", options, "unit cell");
}

TEST_F(SpaceGroupCommandTest, primitiveCellDoesNotAskFromCommand)
{
  ASSERT_EQ(SpaceGroups::hallSymbol(ZincBlendeHall)[0], 'F');
  // fcc primitive cell (60 degree angles) with a centered space group
  auto buildPrimitive = [this](unsigned short hallNumber) {
    m_harness.buildEmpty();
    auto* mol = m_harness.molecule();
    const double h = 0.5 * NaClA;
    mol->setUnitCell(
      new UnitCell(Vector3(0.0, h, h), Vector3(h, 0.0, h), Vector3(h, h, 0.0)));
    mol->addAtom(30, Vector3(0.0, 0.0, 0.0));
    mol->setHallNumber(hallNumber);
  };

  // The menu action asks whether to conventionalize first (here the watcher
  // cancels it): that is the dialog a command must not show.
  buildPrimitive(ZincBlendeHall);
  QAction* action = actionWithPriority(185); // Fill Unit Cell...
  ASSERT_NE(action, nullptr);
  action->setEnabled(true);
  {
    DialogWatcher watcher;
    action->trigger();
    EXPECT_TRUE(watcher.dialogSeen());
  }
  EXPECT_EQ(atomCount(), 1u);

  buildPrimitive(ZincBlendeHall);
  bool dialogSeen = false;
  const CommandOutcome out =
    runWatched("fillUnitCell", QVariantMap(), &dialogSeen);
  EXPECT_FALSE(dialogSeen);
  EXPECT_EQ(out.status, CommandStatus::Finished) << describe(out);
  EXPECT_TRUE(out.clean()) << describe(out);
  // it filled, and the cell was not touched
  EXPECT_GT(atomCount(), 1u);
  EXPECT_NEAR(m_harness.molecule()->unitCell()->alpha(), M_PI / 3.0, 1e-9);
}

TEST_F(SpaceGroupCommandTest, noPromptWhenDialogsAreSkipped)
{
  SkipDialogs skipDialogs(true);

  // Loading a crystal whose space group is unknown used to open the
  // "Select Space Group" dialog: with dialogs skipped it only does not fill.
  buildNaCl();
  bool dialogSeen = false;
  {
    DialogWatcher watcher;
    m_harness.setPluginMolecule(nullptr);
    m_harness.setPluginMolecule(m_harness.molecule());
    dialogSeen = watcher.dialogSeen();
  }
  EXPECT_FALSE(dialogSeen);
  EXPECT_EQ(atomCount(), 2u);

  // With a known space group it still fills automatically
  buildNaCl(NaClHall);
  m_harness.setPluginMolecule(nullptr);
  m_harness.setPluginMolecule(m_harness.molecule());
  EXPECT_EQ(atomCount(), 27u);

  // A centered space group on what looks like a primitive cell would ask
  // whether to conventionalize: with dialogs skipped, nothing is filled.
  m_harness.buildEmpty();
  auto* mol = m_harness.molecule();
  const double h = 0.5 * NaClA;
  mol->setUnitCell(
    new UnitCell(Vector3(0.0, h, h), Vector3(h, 0.0, h), Vector3(h, h, 0.0)));
  mol->addAtom(30, Vector3(0.0, 0.0, 0.0));
  mol->setHallNumber(ZincBlendeHall);
  {
    DialogWatcher watcher;
    m_harness.setPluginMolecule(nullptr);
    m_harness.setPluginMolecule(mol);
    dialogSeen = watcher.dialogSeen();
  }
  EXPECT_FALSE(dialogSeen);
  EXPECT_EQ(atomCount(), 1u);
}

namespace {

// While the "Select Space Group" dialog is open, record the first column of
// the rows it lists, once as opened and once after text is typed.
class SelectDialogWatcher : public DialogWatcher
{
public:
  std::vector<int> initialRows;
  std::vector<int> typedRows;
  QString initialText;

protected:
  void check() override
  {
    QWidget* modal = QApplication::activeModalWidget();
    auto* dialog = qobject_cast<QDialog*>(modal);
    if (dialog == nullptr)
      return;
    m_seen = true;
    auto* view = dialog->findChild<QTableView*>();
    auto* search = dialog->findChild<QLineEdit*>();
    if (view == nullptr || search == nullptr) {
      dialog->reject();
      return;
    }
    auto rowsOf = [view]() {
      std::vector<int> rows;
      QAbstractItemModel* model = view->model();
      for (int i = 0; i < model->rowCount(); ++i)
        rows.push_back(model->index(i, 0).data().toInt());
      return rows;
    };
    initialText = search->text();
    initialRows = rowsOf();
    // typing resumes the normal search over all columns
    search->setText("17");
    typedRows = rowsOf();
    dialog->reject();
  }
};

} // namespace

TEST_F(SpaceGroupCommandTest, selectDialogListsOnlyTheKnownNumber)
{
  buildNaCl();
  QAction* action = actionWithPriority(185); // Fill Unit Cell...
  ASSERT_NE(action, nullptr);
  action->setEnabled(true);

  // Imma (74) has six settings
  m_harness.molecule()->setData(SpaceGroups::internationalNumberKey(), 74);
  {
    SelectDialogWatcher watcher;
    action->trigger();
    EXPECT_TRUE(watcher.dialogSeen());
    EXPECT_EQ(watcher.initialText, QString("74"));
    EXPECT_EQ(watcher.initialRows, std::vector<int>(6, 74));
    // "17" is found anywhere (174, 17, 117, hall symbols...), not only as 74
    EXPECT_GT(watcher.typedRows.size(), 6u);
    EXPECT_NE(watcher.typedRows, watcher.initialRows);
  }
  // cancelled: nothing was filled
  EXPECT_EQ(atomCount(), 2u);
  EXPECT_EQ(m_harness.molecule()->hallNumber(), 0);

  // Without a known number, the crystal system search of the cell is used
  buildNaCl();
  action->setEnabled(true);
  {
    SelectDialogWatcher watcher;
    action->trigger();
    EXPECT_TRUE(watcher.dialogSeen());
    // the set of rows is a few dozen cubic groups
    EXPECT_GT(watcher.initialRows.size(), 6u);
  }
  EXPECT_EQ(atomCount(), 2u);
}
