/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/layermanager.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/rwlayermanager.h>
#include <avogadro/qtgui/rwmolecule.h>

#include <QtCore/QObject>

#include <map>
#include <memory>
#include <string>
#include <vector>

using Avogadro::Index;
using Avogadro::Core::LayerData;
using Avogadro::Core::LayerDataPtr;
using Avogadro::Core::LayerManager;
using Avogadro::Core::MoleculeInfo;
using Avogadro::QtGui::Molecule;
using Avogadro::QtGui::RWLayerManager;
using Avogadro::QtGui::RWMolecule;

namespace {

// addMolecule/addLayer are protected on RWLayerManager; the GUI reaches them
// through LayerModel. Expose them for the test.
class TestLayerManager : public RWLayerManager
{
public:
  using RWLayerManager::addLayer;
  using RWLayerManager::addMolecule;
};

class RWLayerManagerTest : public ::testing::Test, protected LayerManager
{
protected:
  void SetUp() override { m_activeInfo.reset(); }
};

} // namespace

// Reproduces Select::createLayerFromSelection(): build a molecule, register it
// with the layer manager the way the Layers panel does, then add a layer.
TEST_F(RWLayerManagerTest, AddLayerFromSelection)
{
  Molecule molecule;
  for (Index i = 0; i < 4; ++i)
    molecule.addAtom(1);

  TestLayerManager manager;
  manager.addMolecule(&molecule);

  auto* rwmol = molecule.undoMolecule();
  ASSERT_TRUE(rwmol != nullptr);

  manager.addLayer(rwmol);

  EXPECT_EQ(LayerManager::getMoleculeInfo(&molecule)->layer.maxLayer(), 1u);
}

// The same, but with a plugin having registered per-layer enable flags first.
// AddLayerCommand indexes enable[name][activeLayer] with no bounds check, and
// the flag vectors are grown separately from Core::Layer.
TEST_F(RWLayerManagerTest, AddLayerWithShortEnableVector)
{
  Molecule molecule;
  for (Index i = 0; i < 4; ++i)
    molecule.addAtom(1);

  TestLayerManager manager;
  manager.addMolecule(&molecule);

  auto info = LayerManager::getMoleculeInfo(&molecule);
  // A plugin that registered its name but whose vector is shorter than the
  // active layer index -- exactly what happens after a layer is added without
  // the plugin being asked to resize.
  info->enable["TestPlugin"] = std::vector<bool>();
  info->layer.addLayer();
  info->layer.setActiveLayer(1);

  auto* rwmol = molecule.undoMolecule();
  manager.addLayer(rwmol);

  SUCCEED() << "did not crash";
}

// RemoveLayerCommand::redo() used to erase the visible/locked/enable/settings
// metadata for a layer and only then call Core::Layer::removeLayer(), which
// is a no-op when maxLayer() is 0 (the only layer there is -- see the
// comment on it in layer.cpp). A fresh MoleculeInfo already has one
// visible/locked entry for its default layer (see MoleculeInfo's
// constructor), so removeLayer(0, ...) on an otherwise untouched molecule
// used to pass the existing size check, erase that entry, and then find the
// core layer declining to remove anything -- leaving the metadata one layer
// short of what the core layer still had.
TEST_F(RWLayerManagerTest, RemoveLayerLeavesMetadataInSyncWhenCoreLayerDeclines)
{
  Molecule molecule;
  for (Index i = 0; i < 4; ++i)
    molecule.addAtom(1);

  TestLayerManager manager;
  manager.addMolecule(&molecule);

  auto info = LayerManager::getMoleculeInfo(&molecule);
  ASSERT_EQ(info->visible.size(), 1u);
  ASSERT_EQ(info->locked.size(), 1u);
  ASSERT_EQ(info->layer.maxLayer(), 0u);

  auto* rwmol = molecule.undoMolecule();
  ASSERT_TRUE(rwmol != nullptr);

  manager.removeLayer(0, rwmol);

  EXPECT_EQ(info->visible.size(), 1u);
  EXPECT_EQ(info->locked.size(), 1u);
  EXPECT_EQ(info->layer.maxLayer(), 0u);
}

namespace {

// Everything a layer remove/undo/redo is expected to reproduce exactly:
// which layer each atom is in, the per-layer visible/locked/enable/settings
// bookkeeping, and the active/max layer ids.
struct LayerSnapshot
{
  std::vector<size_t> atomLayers;
  std::vector<bool> visible;
  std::vector<bool> locked;
  std::map<std::string, std::vector<bool>> enable;
  // LayerData has no operator==; compare serialized payloads instead. A null
  // slot (a layer with no settings for this plugin) is recorded as "<null>".
  std::map<std::string, std::vector<std::string>> settings;
  size_t activeLayer;
  size_t maxLayer;
};

LayerSnapshot captureSnapshot(const std::shared_ptr<MoleculeInfo>& info,
                              Index atomCount)
{
  LayerSnapshot snap;
  for (Index i = 0; i < atomCount; ++i)
    snap.atomLayers.push_back(info->layer.getLayerID(i));
  snap.visible = info->visible;
  snap.locked = info->locked;
  for (const auto& e : info->enable)
    snap.enable[e.first] = e.second;
  for (const auto& s : info->settings) {
    std::vector<std::string> values;
    for (const auto& ptr : s.second)
      values.push_back(ptr ? ptr->getSave() : "<null>");
    snap.settings[s.first] = values;
  }
  snap.activeLayer = info->layer.activeLayer();
  snap.maxLayer = info->layer.maxLayer();
  return snap;
}

void expectSnapshotsEqual(const LayerSnapshot& expected,
                          const LayerSnapshot& actual)
{
  EXPECT_EQ(expected.atomLayers, actual.atomLayers);
  EXPECT_EQ(expected.visible, actual.visible);
  EXPECT_EQ(expected.locked, actual.locked);
  EXPECT_EQ(expected.enable, actual.enable);
  EXPECT_EQ(expected.settings, actual.settings);
  EXPECT_EQ(expected.activeLayer, actual.activeLayer);
  EXPECT_EQ(expected.maxLayer, actual.maxLayer);
}

// 4 atoms in 2 layers (0: atoms 0,1; 1: atoms 2,3; layer 1 is active), plus a
// "Plugin" enable flag and settings entry per layer, so a remove/undo round
// trip is actually exercising every field a snapshot compares, not just the
// atoms.
RWMolecule* buildTwoLayerMolecule(TestLayerManager& manager, Molecule& molecule)
{
  molecule.addAtom(1);
  molecule.addAtom(1); // atoms 0,1 -> layer 0 (the initial active layer)

  manager.addMolecule(&molecule);
  auto* rwmol = molecule.undoMolecule();
  manager.addLayer(rwmol);          // layer 1 created; active layer stays 0
  manager.setActiveLayer(1, rwmol); // layer 1 becomes active

  molecule.addAtom(1);
  molecule.addAtom(1); // atoms 2,3 -> layer 1

  auto info = LayerManager::getMoleculeInfo(&molecule);
  info->enable["Plugin"] = { true, false };
  Avogadro::Core::Array<LayerDataPtr> settings;
  settings.push_back(std::make_shared<LayerData>("layer0-data"));
  settings.push_back(std::make_shared<LayerData>("layer1-data"));
  info->settings["Plugin"] = settings;

  return rwmol;
}

} // namespace

// Layer::removeLayer() moves a removed layer's atoms into the active layer
// rather than deleting them (see layer.cpp/moleculeinfo.h on this branch).
TEST_F(RWLayerManagerTest, RemoveLayerKeepsAtomsMovesToActiveLayer)
{
  Molecule molecule;
  TestLayerManager manager;
  auto* rwmol = buildTwoLayerMolecule(manager, molecule);

  manager.removeLayer(1, rwmol); // removes the active layer (1)

  EXPECT_EQ(molecule.atomCount(), 4u);
  auto& layer = LayerManager::getMoleculeLayer(&molecule);
  EXPECT_EQ(layer.maxLayer(), 0u);
  EXPECT_EQ(layer.activeLayer(), 0u);
  for (Index i = 0; i < 4; ++i)
    EXPECT_EQ(layer.getLayerID(i), 0u) << "atom " << i;
}

// Removing the active layer, then undoing, must restore every field exactly.
TEST_F(RWLayerManagerTest, RemoveActiveLayerThenUndoRestoresExactState)
{
  Molecule molecule;
  TestLayerManager manager;
  auto* rwmol = buildTwoLayerMolecule(manager, molecule);
  auto info = LayerManager::getMoleculeInfo(&molecule);
  LayerSnapshot before = captureSnapshot(info, 4);

  manager.removeLayer(1, rwmol);
  rwmol->undoStack().undo();

  expectSnapshotsEqual(before, captureSnapshot(info, 4));
}

// Same, but removing layer 0 while a different layer (1) is active -- the
// "active layer above the removed one shifts down" path in
// Layer::removeLayer().
TEST_F(RWLayerManagerTest, RemoveLayerZeroNotActiveThenUndoRestoresExactState)
{
  Molecule molecule;
  TestLayerManager manager;
  auto* rwmol = buildTwoLayerMolecule(manager, molecule);
  auto info = LayerManager::getMoleculeInfo(&molecule);
  ASSERT_EQ(info->layer.activeLayer(), 1u);
  LayerSnapshot before = captureSnapshot(info, 4);

  manager.removeLayer(0, rwmol);
  rwmol->undoStack().undo();

  expectSnapshotsEqual(before, captureSnapshot(info, 4));
}

// Removing layer 0 while it is ALSO the active layer -- the "layer == 0"
// special case in Layer::removeLayer() (the active layer stays 0, now
// naming what used to be layer 1).
TEST_F(RWLayerManagerTest, RemoveActiveLayerZeroThenUndoRestoresExactState)
{
  Molecule molecule;
  molecule.addAtom(1);
  molecule.addAtom(1); // atoms 0,1 -> layer 0, which stays active

  TestLayerManager manager;
  manager.addMolecule(&molecule);
  auto* rwmol = molecule.undoMolecule();
  manager.addLayer(rwmol); // layer 1, empty; active layer stays 0

  auto info = LayerManager::getMoleculeInfo(&molecule);
  ASSERT_EQ(info->layer.activeLayer(), 0u);
  LayerSnapshot before = captureSnapshot(info, 2);

  manager.removeLayer(0, rwmol);
  rwmol->undoStack().undo();

  expectSnapshotsEqual(before, captureSnapshot(info, 2));
}

// Remove, undo, redo: the state after redo must match the state right after
// the first remove (not just the pre-remove state via undo).
TEST_F(RWLayerManagerTest, RemoveUndoRedoMatchesFirstRemove)
{
  Molecule molecule;
  TestLayerManager manager;
  auto* rwmol = buildTwoLayerMolecule(manager, molecule);
  auto info = LayerManager::getMoleculeInfo(&molecule);

  manager.removeLayer(1, rwmol);
  LayerSnapshot afterFirstRemove = captureSnapshot(info, 4);

  rwmol->undoStack().undo();
  rwmol->undoStack().redo();

  expectSnapshotsEqual(afterFirstRemove, captureSnapshot(info, 4));
}

// removeLayer() pushes everything inside one beginMacro()/endMacro() pair, so
// the GUI's Undo action should see exactly one step, and a single undo()
// reverses the whole operation.
TEST_F(RWLayerManagerTest, RemoveLayerIsSingleUndoStep)
{
  Molecule molecule;
  TestLayerManager manager;
  // buildTwoLayerMolecule() itself pushes an addLayer and a setActiveLayer
  // macro, so compare against the count/index before removeLayer() rather
  // than assuming the stack starts empty.
  auto* rwmol = buildTwoLayerMolecule(manager, molecule);
  auto info = LayerManager::getMoleculeInfo(&molecule);
  LayerSnapshot before = captureSnapshot(info, 4);
  int countBefore = rwmol->undoStack().count();
  int indexBefore = rwmol->undoStack().index();

  manager.removeLayer(1, rwmol);
  EXPECT_EQ(rwmol->undoStack().count(), countBefore + 1);
  ASSERT_TRUE(rwmol->undoStack().canUndo());

  rwmol->undoStack().undo(); // a single undo() must fully reverse the remove
  EXPECT_EQ(rwmol->undoStack().index(), indexBefore);
  expectSnapshotsEqual(before, captureSnapshot(info, 4));
}

// Regression for the Undo menu: RemoveLayerCommand's own change notice fires
// while the macro is still open, when QUndoStack::canUndo() is still false
// (see the comment in RWLayerManager::removeLayer()). A listener that
// updates an Undo action from Molecule::changed must see canUndo() == true
// by the time removeLayer() returns, or the menu item is left disabled after
// a real removal.
TEST_F(RWLayerManagerTest, RemoveLayerLastChangeNotificationSeesCanUndoTrue)
{
  Molecule molecule;
  TestLayerManager manager;
  auto* rwmol = buildTwoLayerMolecule(manager, molecule);

  std::vector<bool> canUndoAtNotify;
  QObject::connect(&molecule, &Molecule::changed, [&](unsigned int) {
    canUndoAtNotify.push_back(rwmol->undoStack().canUndo());
  });

  manager.removeLayer(1, rwmol);

  ASSERT_FALSE(canUndoAtNotify.empty());
  EXPECT_TRUE(canUndoAtNotify.back());
}

TEST_F(RWLayerManagerTest, AddLayerThenUndoRedo)
{
  Molecule molecule;
  molecule.addAtom(1);
  TestLayerManager manager;
  manager.addMolecule(&molecule);
  auto* rwmol = molecule.undoMolecule();
  auto info = LayerManager::getMoleculeInfo(&molecule);
  LayerSnapshot before = captureSnapshot(info, 1);

  manager.addLayer(rwmol);
  EXPECT_EQ(info->layer.maxLayer(), 1u);
  EXPECT_EQ(info->visible.size(), 2u);
  EXPECT_EQ(info->locked.size(), 2u);

  rwmol->undoStack().undo();
  expectSnapshotsEqual(before, captureSnapshot(info, 1));

  rwmol->undoStack().redo();
  EXPECT_EQ(info->layer.maxLayer(), 1u);
  EXPECT_EQ(info->visible.size(), 2u);
  EXPECT_EQ(info->locked.size(), 2u);
}

TEST_F(RWLayerManagerTest, SetActiveLayerThenUndoRedo)
{
  Molecule molecule;
  molecule.addAtom(1);
  TestLayerManager manager;
  manager.addMolecule(&molecule);
  auto* rwmol = molecule.undoMolecule();
  manager.addLayer(rwmol);
  auto info = LayerManager::getMoleculeInfo(&molecule);
  ASSERT_EQ(info->layer.activeLayer(), 0u);

  manager.setActiveLayer(1, rwmol);
  EXPECT_EQ(info->layer.activeLayer(), 1u);

  rwmol->undoStack().undo();
  EXPECT_EQ(info->layer.activeLayer(), 0u);

  rwmol->undoStack().redo();
  EXPECT_EQ(info->layer.activeLayer(), 1u);
}

TEST_F(RWLayerManagerTest, RemoveLayerNoActiveMoleculeIsNoop)
{
  Molecule molecule;
  molecule.addAtom(1);
  auto* rwmol = molecule.undoMolecule();

  // No addMolecule() call: SetUp() already reset the active-molecule cursor,
  // so RWLayerManager has no active molecule to act on.
  RWLayerManager manager;
  manager.removeLayer(0, rwmol);

  SUCCEED() << "did not crash with no active molecule";
  EXPECT_EQ(molecule.atomCount(), 1u);

  // Qt does not special-case an empty QUndoStack macro: beginMacro()/
  // endMacro() with nothing pushed between them still becomes a (childless)
  // undo step, so canUndo() is true here. What matters is that undoing it is
  // harmless.
  ASSERT_TRUE(rwmol->undoStack().canUndo());
  rwmol->undoStack().undo();
  EXPECT_EQ(molecule.atomCount(), 1u);
}

// Layer::removeLayer() never leaves a molecule with zero layers -- removing
// the one and only layer is a no-op. RemoveLayerCommand::redo() must check
// for that itself before erasing any bookkeeping (visible/locked/enable/
// settings), since the underlying void call gives it no other way to learn
// the removal was refused; undo() must likewise leave m_applied false so it
// does nothing either.
TEST_F(RWLayerManagerTest, RemoveOnlyLayerIsNoop)
{
  Molecule molecule;
  molecule.addAtom(1);
  molecule.addAtom(1);
  TestLayerManager manager;
  manager.addMolecule(&molecule);
  auto* rwmol = molecule.undoMolecule();
  auto info = LayerManager::getMoleculeInfo(&molecule);
  ASSERT_EQ(info->layer.maxLayer(), 0u) << "only one layer exists";
  LayerSnapshot before = captureSnapshot(info, 2);

  manager.removeLayer(0, rwmol); // the only layer: must be a no-op

  {
    SCOPED_TRACE("right after removeLayer(0)");
    expectSnapshotsEqual(before, captureSnapshot(info, 2));
  }

  rwmol->undoStack().undo();
  {
    SCOPED_TRACE("after undo()");
    expectSnapshotsEqual(before, captureSnapshot(info, 2));
  }
}
