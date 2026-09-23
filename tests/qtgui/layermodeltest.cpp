/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/layermanager.h>
#include <avogadro/qtgui/layermodel.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/rwmolecule.h>

#include <QtCore/QCoreApplication>
#include <QtGui/QGuiApplication>

using Avogadro::Core::LayerManager;
using Avogadro::QtGui::LayerModel;
using Avogadro::QtGui::Molecule;
using Avogadro::QtGui::RWMolecule;

namespace {

// LayerModel loads icons in its constructor, and QIcon needs a
// QGuiApplication. Same pattern as timedprogressdialogtest.cpp: create one on
// the offscreen platform so this runs headless, and skip only if another test
// in this process already made a plain QCoreApplication that can't be
// upgraded.
QGuiApplication* ensureApp()
{
  if (QCoreApplication::instance() != nullptr)
    return qobject_cast<QGuiApplication*>(QCoreApplication::instance());

  static int argc = 1;
  static char arg0[] = "layermodeltest";
  static char* argv[] = { arg0, nullptr };
  if (qEnvironmentVariableIsEmpty("QT_QPA_PLATFORM"))
    qputenv("QT_QPA_PLATFORM", "offscreen");
  static QGuiApplication app(argc, argv);
  return &app;
}

class LayerModelTest : public ::testing::Test, protected LayerManager
{
protected:
  void SetUp() override
  {
    m_activeInfo.reset();
    if (ensureApp() == nullptr)
      GTEST_SKIP() << "a non-GUI QCoreApplication already exists";
  }
};

// 3 layers (ids 0,1,2); "Plugin" is enabled only on layer 0. So
// activeMoleculeNames() -- and therefore the model's rows -- are:
//   row 0: (layer 0, "Layer")
//   row 1: (layer 0, "Plugin")
//   row 2: (layer 1, "Layer")
//   row 3: (layer 2, "Layer")
//   row 4: synthetic "+" row (no backing layer; see data()'s
//          idx.row() == names.size() special case)
// Row index and layer id therefore diverge from row 2 onward: this is what
// lets the tests below actually prove that flipVisible()/flipLocked()/
// setActiveLayer()/removeItem() translate a row through
// activeMoleculeNames()[row].first rather than using the row number as a
// layer id directly.
void buildThreeLayerMoleculeWithPluginRow(LayerModel& model, Molecule& molecule)
{
  molecule.addAtom(1);
  model.addMolecule(&molecule);
  auto* rwmol = molecule.undoMolecule();
  model.addLayer(rwmol);
  model.addLayer(rwmol);

  auto info = LayerManager::getMoleculeInfo(&molecule);
  info->enable["Plugin"] = { true, false, false };
  // Nothing signals Molecule::changed for a direct MoleculeInfo edit like
  // this one (real plugin code goes through PluginLayerManager::setEnabled(),
  // which is just as quiet), so m_item would otherwise stay stale; refresh it
  // explicitly the way updateRows()'s own doc comment expects a caller to.
  model.updateRows();
}

} // namespace

// See the row <-> layer mapping documented on
// buildThreeLayerMoleculeWithPluginRow above. Without any plugin rows,
// activeMoleculeNames() has one "Layer" entry per layer, so for L layers:
// items()/rowCount() == L + 1 (the extra row is the "+" add-layer row from
// updateRows()) and layerCount() == L.
TEST_F(LayerModelTest, RowCountTracksAddAndRemove)
{
  Molecule molecule;
  molecule.addAtom(1);
  LayerModel model;
  model.addMolecule(&molecule);
  auto* rwmol = molecule.undoMolecule();

  EXPECT_EQ(model.layerCount(), 1u);
  EXPECT_EQ(model.items(), 2u);
  EXPECT_EQ(model.rowCount(QModelIndex()), 2);

  model.addLayer(rwmol);
  EXPECT_EQ(model.layerCount(), 2u);
  EXPECT_EQ(model.items(), 3u);
  EXPECT_EQ(model.rowCount(QModelIndex()), 3);

  model.removeItem(0, rwmol); // row 0 is layer 0's header row
  EXPECT_EQ(model.layerCount(), 1u);
  EXPECT_EQ(model.items(), 2u);
  EXPECT_EQ(model.rowCount(QModelIndex()), 2);
}

TEST_F(LayerModelTest, SetActiveLayerUsesLayerIdNotRowIndex)
{
  Molecule molecule;
  LayerModel model;
  buildThreeLayerMoleculeWithPluginRow(model, molecule);
  auto* rwmol = molecule.undoMolecule();
  ASSERT_EQ(model.items(), 5u);

  // Row 3 is layer 2's header row (see the mapping comment above). A bug
  // that used the row index as the layer id would instead point the active
  // layer at the not-yet-existing layer 3.
  model.setActiveLayer(3, rwmol);
  EXPECT_EQ(LayerManager::getMoleculeLayer(&molecule).activeLayer(), 2u);
}

TEST_F(LayerModelTest, RemoveItemUsesLayerIdNotRowIndex)
{
  Molecule molecule;
  LayerModel model;
  buildThreeLayerMoleculeWithPluginRow(model, molecule);
  auto* rwmol = molecule.undoMolecule();
  ASSERT_EQ(model.items(), 5u);

  model.removeItem(3, rwmol); // layer 2's header row -> removes layer id 2
  EXPECT_EQ(model.layerCount(), 2u);
  EXPECT_EQ(model.items(), 4u);
}

// BUG: LayerModel::removeItem() (layermodel.cpp:261) guards with
// `row <= static_cast<int>(m_item)`, but the valid indices into the local
// `names` array (size m_item - 1; see the row-mapping comment above) are
// 0..m_item-2. Both row == m_item-1 (the "+" row) and row == m_item (one
// further) pass that guard and then index `names[row]` past its end.
// Confirmed with lldb on this exact scenario (2 layers, m_item == 3,
// removeItem(3, rwmol)): libc++ hardening traps inside
// Core::Array<...>::operator[] at array.h:300, called from
// LayerModel::removeItem() at layermodel.cpp:263, with the vector's actual
// size() == 2 and __n == 3 -- i.e. it does index past the end, exactly as
// suspected, and aborts the whole process (SIGTRAP), not just this test.
TEST_F(LayerModelTest, DISABLED_RemoveItemRowEqualToItemsIndexesPastEnd)
{
  Molecule molecule;
  molecule.addAtom(1);
  LayerModel model;
  model.addMolecule(&molecule);
  auto* rwmol = molecule.undoMolecule();
  model.addLayer(rwmol); // 2 layers; m_item == 3 (2 header rows + "+")
  ASSERT_EQ(model.items(), 3u);

  model.removeItem(static_cast<int>(model.items()), rwmol); // aborts here
  SUCCEED() << "did not crash (unexpected)";
}

TEST_F(LayerModelTest, FlipVisibleTogglesCorrectLayer)
{
  Molecule molecule;
  molecule.addAtom(1);
  LayerModel model;
  model.addMolecule(&molecule);
  auto* rwmol = molecule.undoMolecule();
  model.addLayer(rwmol); // layer 1; no plugin rows, so row N == layer N

  ASSERT_TRUE(model.visible(0));
  ASSERT_TRUE(model.visible(1));

  model.flipVisible(1);
  EXPECT_TRUE(model.visible(0));
  EXPECT_FALSE(model.visible(1));
}

TEST_F(LayerModelTest, FlipLockedTogglesCorrectLayer)
{
  Molecule molecule;
  molecule.addAtom(1);
  LayerModel model;
  model.addMolecule(&molecule);
  auto* rwmol = molecule.undoMolecule();
  model.addLayer(rwmol); // layer 1; no plugin rows, so row N == layer N

  model.flipLocked(0);

  // locked() is protected on RWLayerManager (and so on LayerModel), so read
  // the bookkeeping directly.
  auto info = LayerManager::getMoleculeInfo(&molecule);
  ASSERT_EQ(info->locked.size(), 2u);
  EXPECT_TRUE(info->locked[0]);
  EXPECT_FALSE(info->locked[1]);
}

TEST_F(LayerModelTest, SwitchingMoleculesShowsRightLayers)
{
  Molecule molA;
  molA.addAtom(1);
  Molecule molB;
  molB.addAtom(1);

  LayerModel model;
  model.addMolecule(&molA);
  auto* rwA = molA.undoMolecule();
  model.addLayer(rwA); // molA: 2 layers

  model.addMolecule(&molB); // switch to molB
  auto* rwB = molB.undoMolecule();
  EXPECT_EQ(model.layerCount(), 1u); // molB starts with a single layer
  EXPECT_EQ(model.items(), 2u);

  model.addLayer(rwB);
  model.addLayer(rwB); // molB: 3 layers
  EXPECT_EQ(model.layerCount(), 3u);

  model.addMolecule(&molA);          // switch back
  EXPECT_EQ(model.layerCount(), 2u); // molA's own state, not molB's
  EXPECT_EQ(model.items(), 3u);
}

TEST_F(LayerModelTest, DataDisplayRoleForLayerNameColumn)
{
  Molecule molecule;
  molecule.addAtom(1);
  LayerModel model;
  model.addMolecule(&molecule);
  auto* rwmol = molecule.undoMolecule();
  model.addLayer(rwmol); // 2 layers: rows 0,1 are headers, row 2 is "+"

  QModelIndex idx0 = model.index(0, LayerModel::Name);
  EXPECT_EQ(model.data(idx0, Qt::DisplayRole).toString().toStdString(),
            "Layer 1"); // 1-based display, 0-based internally
  QModelIndex idx1 = model.index(1, LayerModel::Name);
  EXPECT_EQ(model.data(idx1, Qt::DisplayRole).toString().toStdString(),
            "Layer 2");
}

// Every column except Name only ever returns something for
// Qt::DecorationRole (an icon), which these tests deliberately never request
// (see the qtgui test rules). Any other role must come back empty.
TEST_F(LayerModelTest, DataNonNameColumnsHaveNoDisplayOrEditContent)
{
  Molecule molecule;
  molecule.addAtom(1);
  LayerModel model;
  model.addMolecule(&molecule);

  for (int col : { LayerModel::Menu, LayerModel::Visible, LayerModel::Lock,
                   LayerModel::Remove }) {
    QModelIndex idx = model.index(0, col);
    SCOPED_TRACE(col);
    EXPECT_FALSE(model.data(idx, Qt::DisplayRole).isValid());
    EXPECT_FALSE(model.data(idx, Qt::EditRole).isValid());
  }
}

TEST_F(LayerModelTest, DataInvalidIndexReturnsInvalidVariant)
{
  LayerModel model;
  EXPECT_FALSE(model.data(QModelIndex(), Qt::DisplayRole).isValid());
}

TEST_F(LayerModelTest, FlagsAreAlwaysItemIsEnabled)
{
  LayerModel model;
  for (int col = 0; col < 6; ++col) {
    SCOPED_TRACE(col);
    EXPECT_EQ(model.flags(model.index(0, col)), Qt::ItemIsEnabled);
  }
  EXPECT_EQ(model.flags(QModelIndex()), Qt::ItemIsEnabled);
}
