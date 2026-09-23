/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/moleculemodel.h>

#include <QCoreApplication>
#include <QEventLoop>
#include <QFont>
#include <QModelIndex>
#include <QPointer>
#include <QSignalSpy>
#include <QTimer>

using Avogadro::QtGui::Molecule;
using Avogadro::QtGui::MoleculeModel;

namespace {

// Ensure a QCoreApplication exists. The test binary uses gtest_main, which
// does not create one, but MoleculeModel's constructor unconditionally
// loads icons (loadIcons(), moleculemodel.cpp:31-41), and constructing a
// QIcon from a file path touches QPixmap, which qFatal()s ("QPixmap: Must
// construct a QGuiApplication before a QPixmap") if no QCoreApplication
// instance exists at all -- despite the message text, a plain
// QCoreApplication (not QGuiApplication/QApplication, which this file must
// not create) is sufficient in practice; verified with an isolated
// `QIcon icon(":whatever");` reproducer both with and without a prior
// QCoreApplication.
QCoreApplication* ensureApp()
{
  if (QCoreApplication::instance())
    return QCoreApplication::instance();
  static int argc = 1;
  static char name[] = "MoleculeModelTest";
  static char* argv[] = { name, nullptr };
  static QCoreApplication app(argc, argv);
  return &app;
}

} // namespace

class MoleculeModelTest : public ::testing::Test
{
protected:
  void SetUp() override { ensureApp(); }
};

TEST_F(MoleculeModelTest, AddItem_AddsToRowCountAndLists)
{
  MoleculeModel model;
  auto* mol = new Molecule;

  model.addItem(mol);

  // One row for the molecule, plus the trailing "add molecule" row.
  EXPECT_EQ(model.rowCount(QModelIndex()), 2);
  EXPECT_EQ(model.molecules().size(), 1);
  EXPECT_EQ(model.molecules().first(), mol);
  EXPECT_EQ(model.activeMolecules().size(), 1);
}

TEST_F(MoleculeModelTest, AddItem_Duplicate_IsNoOp)
{
  MoleculeModel model;
  auto* mol = new Molecule;

  model.addItem(mol);
  model.addItem(mol);

  EXPECT_EQ(model.molecules().size(), 1);
  EXPECT_EQ(model.rowCount(QModelIndex()), 2);
}

TEST_F(MoleculeModelTest, RemoveItem_RemovesFromRowCountAndLists)
{
  MoleculeModel model;
  auto* m1 = new Molecule;
  auto* m2 = new Molecule;
  model.addItem(m1);
  model.addItem(m2);

  model.removeItem(m1);

  EXPECT_EQ(model.molecules().size(), 1);
  EXPECT_EQ(model.molecules().first(), m2);
  EXPECT_EQ(model.rowCount(QModelIndex()), 2); // m2 + trailing row
}

TEST_F(MoleculeModelTest, RemoveItem_NotInModel_IsNoOp)
{
  MoleculeModel model;
  auto* mol = new Molecule;
  model.addItem(mol);

  // A stack object never given to the model: if removeItem() mishandled
  // "not found" and called deleteLater()/delete on it anyway, this would
  // crash at scope exit.
  Molecule notAdded;
  model.removeItem(&notAdded);

  EXPECT_EQ(model.molecules().size(), 1);
  EXPECT_EQ(model.molecules().first(), mol);
}

TEST_F(MoleculeModelTest, Clear_EmptiesMolecules)
{
  MoleculeModel model;
  auto* m1 = new Molecule;
  auto* m2 = new Molecule;
  model.addItem(m1);
  model.addItem(m2);

  model.clear();

  EXPECT_TRUE(model.molecules().isEmpty());
  EXPECT_EQ(model.rowCount(QModelIndex()), 1); // just the trailing row
}

// clear() must tell attached views (a model reset) and, like removeItem(),
// delete the molecules it owns rather than orphan them.
TEST_F(MoleculeModelTest, Clear_ResetsViewsAndDeletesMolecules)
{
  MoleculeModel model;
  QPointer<Molecule> m1 = new Molecule;
  QPointer<Molecule> m2 = new Molecule;
  model.addItem(m1);
  model.addItem(m2);
  model.setActiveMolecule(m1);
  QSignalSpy resetSpy(&model, &QAbstractItemModel::modelReset);

  model.clear();
  EXPECT_EQ(resetSpy.count(), 1);

  QEventLoop loop;
  QTimer::singleShot(0, &loop, &QEventLoop::quit);
  loop.exec();

  EXPECT_TRUE(m1.isNull());
  EXPECT_TRUE(m2.isNull());
  EXPECT_EQ(model.activeMolecule(), nullptr);
}

TEST_F(MoleculeModelTest, ActiveMolecules_CurrentlyReturnsAllMolecules)
{
  // MoleculeModel::activeMolecules() (moleculemodel.cpp:186-194) loops over
  // m_molecules with an unconditional `if (true)`. The MoleculeSystem struct
  // declared in the header (with its m_active flag) is never actually used
  // by this class -- m_molecules is QList<Molecule*>, not
  // QList<MoleculeSystem>. So today activeMolecules() is indistinguishable
  // from molecules(); this documents the real behavior rather than what the
  // name implies.
  MoleculeModel model;
  auto* m1 = new Molecule;
  auto* m2 = new Molecule;
  model.addItem(m1);
  model.addItem(m2);
  model.setActiveMolecule(m1);

  EXPECT_EQ(model.activeMolecules().size(), 2);
  EXPECT_TRUE(model.activeMolecules().contains(m2));
}

TEST_F(MoleculeModelTest, SetActiveMolecule_UpdatesActiveMoleculeAndBoldFont)
{
  MoleculeModel model;
  auto* m1 = new Molecule;
  auto* m2 = new Molecule;
  model.addItem(m1);
  model.addItem(m2);

  model.setActiveMolecule(m1);
  EXPECT_EQ(model.activeMolecule(), static_cast<QObject*>(m1));

  QVariant font0 = model.data(model.index(0, 0), Qt::FontRole);
  QVariant font1 = model.data(model.index(1, 0), Qt::FontRole);
  ASSERT_TRUE(font0.isValid());
  EXPECT_TRUE(font0.value<QFont>().bold());
  EXPECT_FALSE(font1.isValid()); // non-active molecule: no font override
}

TEST_F(MoleculeModelTest, SetActiveMolecule_SameValueTwice_EmitsDataChangedOnce)
{
  MoleculeModel model;
  auto* m1 = new Molecule;
  model.addItem(m1);

  QSignalSpy spy(&model, &QAbstractItemModel::dataChanged);
  model.setActiveMolecule(m1);
  EXPECT_EQ(spy.count(), 1);

  model.setActiveMolecule(m1); // same object: early return, no signal
  EXPECT_EQ(spy.count(), 1);
}

TEST_F(MoleculeModelTest, SetActiveMolecule_EmptyModel_EmitsNoSignal)
{
  // With no molecules, createIndex(0, 0) would build an index into a row
  // that does not exist; setActiveMolecule() must skip the emit entirely
  // rather than hand out a bogus index.
  MoleculeModel model;
  auto* mol = new Molecule; // never added to the model

  QSignalSpy spy(&model, &QAbstractItemModel::dataChanged);
  model.setActiveMolecule(mol);

  EXPECT_EQ(model.activeMolecule(), static_cast<QObject*>(mol));
  EXPECT_EQ(spy.count(), 0);
  delete mol;
}

TEST_F(MoleculeModelTest,
       RemoveActiveMolecule_PointerSurvivesUntilDeferredDeleteRuns)
{
  // removeItem() only schedules the removed molecule's deletion
  // (deleteLater()); the object itself is still alive until the event loop
  // actually runs the deferred delete. We do not spin the event loop here,
  // so m_activeMolecule (now a QPointer) still legitimately points at the
  // not-yet-destroyed molecule. See the test below for what happens once
  // the deferred delete actually executes.
  MoleculeModel model;
  auto* mol = new Molecule;
  model.addItem(mol);
  model.setActiveMolecule(mol);

  model.removeItem(mol);

  EXPECT_TRUE(model.molecules().isEmpty());
  EXPECT_EQ(model.activeMolecule(), static_cast<QObject*>(mol));
}

// MoleculeModel::removeItem() (moleculemodel.cpp) calls item->deleteLater()
// without ever clearing m_activeMolecule if the removed item is the active
// one. m_activeMolecule is now a QPointer<QObject> (moleculemodel.h), which
// self-clears when the object it points to is actually destroyed, however
// that happens -- so once the deferred delete really runs (a real app event
// loop will do this; a flat processEvents()/sendPostedEvents() outside any
// running loop is NOT enough -- Qt only honors deleteLater() at a loop level
// matching where it was posted; a nested QEventLoop::exec() is), a stale
// query of activeMolecule() safely returns nullptr instead of a dangling
// pointer. Relevant to avogadroapp#634 (removing the empty startup
// molecule): a remove-then-query of the active molecule is now safe.
TEST_F(MoleculeModelTest,
       RemoveActiveMolecule_ActiveMoleculeClearsAfterDeferredDelete)
{
  MoleculeModel model;
  auto* mol = new Molecule;
  model.addItem(mol);
  model.setActiveMolecule(mol);

  model.removeItem(mol);
  // Actually run the deferred delete.
  QEventLoop loop;
  QTimer::singleShot(0, &loop, &QEventLoop::quit);
  loop.exec();

  EXPECT_EQ(model.activeMolecule(), nullptr);
}

TEST_F(MoleculeModelTest, ItemChanged_EmitsDataChangedForSenderRow)
{
  MoleculeModel model;
  auto* m1 = new Molecule;
  auto* m2 = new Molecule;
  model.addItem(m1);
  model.addItem(m2);

  // itemChanged() dispatches via sender(), the way the app wires it up
  // (connected to Molecule::changed for each molecule it owns).
  QObject::connect(m2, &Molecule::changed, &model, &MoleculeModel::itemChanged);

  QSignalSpy spy(&model, &QAbstractItemModel::dataChanged);
  m2->emitChanged(Molecule::Atoms);

  ASSERT_EQ(spy.count(), 1);
  QList<QVariant> args = spy.takeFirst();
  EXPECT_EQ(args.at(0).value<QModelIndex>().row(), 1);
  EXPECT_EQ(args.at(1).value<QModelIndex>().row(), 1);
}

TEST_F(MoleculeModelTest, SetData_CheckStateRole_EmitsMoleculeStateChanged)
{
  MoleculeModel model;
  auto* m1 = new Molecule;
  model.addItem(m1);

  QModelIndex idx = model.index(0, 0);
  QSignalSpy spy(&model, &MoleculeModel::moleculeStateChanged);
  EXPECT_TRUE(model.setData(idx, Qt::Checked, Qt::CheckStateRole));

  ASSERT_EQ(spy.count(), 1);
  EXPECT_EQ(model.activeMolecule(), static_cast<QObject*>(m1));
}

TEST_F(MoleculeModelTest, Data_Column0_DisplayEditToolTipWhatsThis)
{
  MoleculeModel model;
  auto* mol = new Molecule;
  mol->addAtom(18); // single Argon atom: deterministic formula "Ar"
  model.addItem(mol);

  QModelIndex idx = model.index(0, 0);

  EXPECT_EQ(model.data(idx, Qt::DisplayRole).toString(),
            QStringLiteral("Untitled (Ar)"));
  EXPECT_EQ(model.data(idx, Qt::EditRole).toString(), QString());
  EXPECT_EQ(model.data(idx, Qt::ToolTipRole).toString(),
            QStringLiteral("Not saved"));
  EXPECT_EQ(model.data(idx, Qt::WhatsThisRole).toString(),
            QStringLiteral("Ar"));

  mol->setData("name", std::string("MyArgon"));
  EXPECT_EQ(model.data(idx, Qt::DisplayRole).toString(),
            QStringLiteral("MyArgon (Ar)"));
  EXPECT_EQ(model.data(idx, Qt::EditRole).toString(),
            QStringLiteral("MyArgon"));

  mol->setData("fileName", std::string("/tmp/argon.xyz"));
  EXPECT_EQ(model.data(idx, Qt::ToolTipRole).toString(),
            QStringLiteral("/tmp/argon.xyz"));
}

TEST_F(MoleculeModelTest, Data_Column1_OnlyDecorationHandled)
{
  MoleculeModel model;
  auto* mol = new Molecule;
  model.addItem(mol);

  QModelIndex idx1 = model.index(0, 1);
  EXPECT_FALSE(model.data(idx1, Qt::DisplayRole).isValid());
  EXPECT_FALSE(model.data(idx1, Qt::ToolTipRole).isValid());
}

TEST_F(MoleculeModelTest, Flags_Column0EditableColumn1NotEditable)
{
  MoleculeModel model;
  auto* mol = new Molecule;
  model.addItem(mol);

  QModelIndex idx0 = model.index(0, 0);
  QModelIndex idx1 = model.index(0, 1);
  EXPECT_TRUE(model.flags(idx0) & Qt::ItemIsEditable);
  EXPECT_FALSE(model.flags(idx1) & Qt::ItemIsEditable);
  EXPECT_TRUE(model.flags(idx1) & Qt::ItemIsEnabled);
}

TEST_F(MoleculeModelTest, Data_PlusRow_OnlyDecorationRoleValid)
{
  MoleculeModel model;
  auto* mol = new Molecule;
  model.addItem(mol);

  QModelIndex plusRow = model.index(1, 0); // one past the last molecule
  ASSERT_TRUE(plusRow.isValid());
  EXPECT_FALSE(model.data(plusRow, Qt::DisplayRole).isValid());
  EXPECT_FALSE(model.data(plusRow, Qt::EditRole).isValid());

  QModelIndex plusRowCol1 = model.index(1, 1);
  EXPECT_FALSE(model.data(plusRowCol1, Qt::DisplayRole).isValid());

  EXPECT_EQ(model.flags(plusRow), Qt::ItemIsEnabled | Qt::ItemIsSelectable);
}

TEST_F(MoleculeModelTest, Parent_AlwaysInvalid)
{
  MoleculeModel model;
  EXPECT_FALSE(model.parent(QModelIndex()).isValid());

  auto* mol = new Molecule;
  model.addItem(mol);
  EXPECT_FALSE(model.parent(model.index(0, 0)).isValid());
}

TEST_F(MoleculeModelTest, Index_OutOfRange_ReturnsInvalid)
{
  MoleculeModel model;
  auto* mol = new Molecule;
  model.addItem(mol);

  EXPECT_FALSE(model.index(-1, 0).isValid());
  EXPECT_FALSE(model.index(5, 0).isValid());
  EXPECT_TRUE(model.index(0, 0).isValid()); // the molecule
  EXPECT_TRUE(model.index(1, 0).isValid()); // the trailing "+" row
  EXPECT_FALSE(model.index(2, 0).isValid());
}

TEST_F(MoleculeModelTest, DataAndFlags_InvalidAndOutOfRangeIndex)
{
  MoleculeModel model;
  auto* mol = new Molecule;
  model.addItem(mol);

  QModelIndex invalidIdx;
  EXPECT_FALSE(model.data(invalidIdx, Qt::DisplayRole).isValid());
  // flags() never touches internalPointer(), so a default-constructed index
  // does not crash, though it isn't explicitly guarded by isValid() either.
  EXPECT_NO_FATAL_FAILURE(model.flags(invalidIdx));

  QModelIndex outOfRange = model.index(99, 0); // clamped to invalid by index()
  EXPECT_FALSE(outOfRange.isValid());
  EXPECT_FALSE(model.data(outOfRange, Qt::DisplayRole).isValid());
}
