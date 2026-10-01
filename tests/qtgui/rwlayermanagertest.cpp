/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/layermanager.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/pluginlayermanager.h>
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
using Avogadro::QtGui::PluginLayerManager;
using Avogadro::QtGui::RWLayerManager;
using Avogadro::QtGui::RWMolecule;

namespace {

// addMolecule/addLayer are protected on RWLayerManager; the GUI reaches them
// through LayerModel. Expose them for the test.
class TestLayerManager : public RWLayerManager
{
public:
  using RWLayerManager::activeMoleculeNames;
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

// Select::createLayerFromSelection() and SelectionTool push the command on
// their own molecule's undo stack; the layer used to be added to whichever
// molecule was active instead, so the selected atoms were then moved into a
// layer their molecule did not have. The plugin's molecule must be made
// active and receive the layer.
TEST_F(RWLayerManagerTest, AddLayerActsOnTheGivenMoleculeNotTheActiveOne)
{
  Molecule active;
  active.addAtom(1);
  Molecule other;
  for (Index i = 0; i < 3; ++i)
    other.addAtom(6);

  TestLayerManager manager;
  manager.addMolecule(&active);
  ASSERT_EQ(LayerManager::getMoleculeInfo(), active.layerInfo());

  auto* rwOther = other.undoMolecule();
  const int activeUndo = active.undoMolecule()->undoStack().count();
  // Reproduce createLayerFromSelection(): atom 1 is selected and moved.
  rwOther->setAtomSelected(1, true);
  rwOther->beginMergeMode("Change Layer");
  manager.addLayer(rwOther);
  const size_t layer = LayerManager::getMoleculeInfo(&other)->layer.maxLayer();
  for (Index i = 0; i < rwOther->atomCount(); ++i)
    if (rwOther->atomSelected(i))
      rwOther->setLayer(i, layer);
  rwOther->endMergeMode();

  // `other` got the layer and became the active molecule; `active` is
  // untouched, including its undo stack.
  EXPECT_EQ(LayerManager::getMoleculeInfo(), other.layerInfo());
  EXPECT_EQ(1u, layer);
  EXPECT_EQ(1u, other.layer().maxLayer());
  EXPECT_EQ(1u, other.layer().getLayerID(1));
  EXPECT_EQ(0u, other.layer().getLayerID(0));
  EXPECT_EQ(0u, active.layer().maxLayer());
  EXPECT_EQ(2u, LayerManager::getMoleculeInfo(&other)->visible.size());
  EXPECT_EQ(1u, LayerManager::getMoleculeInfo(&active)->visible.size());
  EXPECT_EQ(activeUndo, active.undoMolecule()->undoStack().count());

  // Undoing on `other`'s stack removes `other`'s layer again.
  rwOther->undoStack().undo();
  EXPECT_EQ(0u, other.layer().maxLayer());
  EXPECT_EQ(0u, other.layer().getLayerID(1));
  EXPECT_EQ(0u, active.layer().maxLayer());
}

// With no active molecule at all, addLayer() used to be a silent no-op (an
// empty macro on the undo stack); it now activates the given molecule.
TEST_F(RWLayerManagerTest, AddLayerWithNoActiveMoleculeActivatesIt)
{
  Molecule molecule;
  molecule.addAtom(1);
  ASSERT_EQ(nullptr, LayerManager::getMoleculeInfo());

  TestLayerManager manager;
  manager.addLayer(molecule.undoMolecule());

  EXPECT_EQ(LayerManager::getMoleculeInfo(), molecule.layerInfo());
  EXPECT_EQ(1u, molecule.layer().maxLayer());
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

// activeMoleculeNames() used to index active[i] for every element of a
// plugin's enable vector with no check against the (shorter) layer count --
// out of bounds once i reaches layerCount(). A vector left oversized by a
// layer removal that trimmed Core::Layer but not every plugin's vector
// reproduces it.
TEST_F(RWLayerManagerTest,
       ActiveMoleculeNamesBoundsPluginVectorLongerThanLayerCount)
{
  Molecule molecule;
  for (Index i = 0; i < 4; ++i)
    molecule.addAtom(1);

  TestLayerManager manager;
  manager.addMolecule(&molecule);

  auto info = LayerManager::getMoleculeInfo(&molecule);
  info->enable["TestPlugin"] = { true, true, true };
  ASSERT_EQ(info->layer.layerCount(), 1u);

  const auto names = manager.activeMoleculeNames();
  // Only layer 0 exists, so only its header + "TestPlugin" row should come
  // back -- not one entry per element of the oversized vector.
  ASSERT_EQ(names.size(), 2u);
  EXPECT_EQ(names[0].first, 0u);
  EXPECT_EQ(names[0].second, "Layer");
  EXPECT_EQ(names[1].first, 0u);
  EXPECT_EQ(names[1].second, "TestPlugin");
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

// RemoveLayerCommand used to keep the per-plugin settings (and enable flags)
// an earlier redo() had taken out. Plugin settings are created lazily and are
// not on the undo stack, so a later redo() can find the array too short to
// take anything out -- and undo() then put the stale entry back anyway. Here
// that makes layers 1 and 2 share one settings object.
TEST_F(RWLayerManagerTest, RemoveLayerUndoRestoresOnlyWhatItsRedoRemoved)
{
  Molecule molecule;
  molecule.addAtom(1);
  TestLayerManager manager;
  manager.addMolecule(&molecule);
  auto* rwmol = molecule.undoMolecule();
  auto& stack = rwmol->undoStack();
  auto info = LayerManager::getMoleculeInfo(&molecule);

  // Layers 0-3, index 3.
  for (int i = 0; i < 3; ++i)
    manager.addLayer(rwmol);
  manager.removeLayer(1, rwmol);    // layers 0-2
  manager.setActiveLayer(2, rwmol); // index 5
  PluginLayerManager plugin("TestPlugin");
  ASSERT_NE(plugin.getSetting<LayerData>(), nullptr); // one entry per layer
  manager.removeLayer(2, rwmol); // takes layer 2's entry out, index 6

  stack.setIndex(3); // layers 0-3 are back; the three entries stay
  stack.setIndex(6); // removing layer 1 leaves two; nothing to take for 2
  stack.setIndex(5); // so undoing the second removal has nothing to put back

  const auto& settings = info->settings["TestPlugin"];
  EXPECT_LE(settings.size(), info->layer.layerCount());
  for (size_t i = 0; i < settings.size(); ++i) {
    for (size_t j = i + 1; j < settings.size(); ++j) {
      if (settings[i] != nullptr)
        EXPECT_NE(settings[i].get(), settings[j].get())
          << "layers " << i << " and " << j << " share settings";
    }
  }
}

// The same stale entry, but now the array is shorter than the layer it was
// put back at: undo() inserted past the end of the vector, corrupting the
// heap and leaking the settings object (found by fuzz-layermanager under
// LeakSanitizer).
TEST_F(RWLayerManagerTest, RemoveLayerUndoNeverInsertsPastSettingsEnd)
{
  std::vector<std::weak_ptr<LayerData>> created;
  {
    Molecule molecule;
    molecule.addAtom(1);
    TestLayerManager manager;
    manager.addMolecule(&molecule);
    auto* rwmol = molecule.undoMolecule();
    auto& stack = rwmol->undoStack();
    auto info = LayerManager::getMoleculeInfo(&molecule);

    for (int i = 0; i < 5; ++i)
      manager.addLayer(rwmol); // layers 0-5, index 5
    manager.removeLayer(1, rwmol);
    manager.removeLayer(1, rwmol);    // layers 0-3
    manager.setActiveLayer(3, rwmol); // index 8
    PluginLayerManager plugin("TestPlugin");
    ASSERT_NE(plugin.getSetting<LayerData>(), nullptr);
    for (const auto& data : info->settings["TestPlugin"])
      created.push_back(data);
    ASSERT_EQ(created.size(), 4u);
    manager.removeLayer(3, rwmol); // index 9

    stack.setIndex(5); // four settings entries, six layers
    stack.setIndex(9); // both removals of layer 1 leave two entries
    stack.setIndex(8); // must not insert at 3

    const auto& settings = info->settings["TestPlugin"];
    EXPECT_LE(settings.size(), info->layer.layerCount());

    // The whole stack still round trips.
    stack.setIndex(0);
    stack.setIndex(stack.count());
    EXPECT_LE(info->settings["TestPlugin"].size(), info->layer.layerCount());
  }
  // The molecule and its undo stack are gone, so nothing may own these.
  for (const auto& data : created)
    EXPECT_TRUE(data.expired());
}

namespace {

// Layers 0-2 with layer 0 active, and per-plugin arrays out of step with the
// layer count, the way lazily grown ones are. "Short" has a flag and settings
// for layer 0 only. "Long" already has entries for layer 3, which does not
// exist yet (getSetting() with the active layer one past the last one makes
// such an entry).
RWMolecule* buildUnevenPluginArrays(TestLayerManager& manager,
                                    Molecule& molecule)
{
  molecule.addAtom(1);
  manager.addMolecule(&molecule);
  auto* rwmol = molecule.undoMolecule();
  manager.addLayer(rwmol);
  manager.addLayer(rwmol);

  auto info = LayerManager::getMoleculeInfo(&molecule);
  info->enable["Short"] = { true };
  info->enable["Long"] = { false, false, false, true };
  Avogadro::Core::Array<LayerDataPtr> shortSettings;
  shortSettings.push_back(std::make_shared<LayerData>("short0"));
  info->settings["Short"] = shortSettings;
  Avogadro::Core::Array<LayerDataPtr> longSettings;
  for (int i = 0; i < 4; ++i)
    longSettings.push_back(
      std::make_shared<LayerData>("long" + std::to_string(i)));
  info->settings["Long"] = longSettings;
  return rwmol;
}

// Every plugin's flags, and which settings object sits in each slot.
struct PluginArrays
{
  std::map<std::string, std::vector<bool>> enable;
  std::map<std::string, std::vector<const LayerData*>> settings;

  bool operator==(const PluginArrays& other) const
  {
    return enable == other.enable && settings == other.settings;
  }
};

PluginArrays capturePluginArrays(const MoleculeInfo& info)
{
  PluginArrays arrays;
  arrays.enable = info.enable;
  for (const auto& entry : info.settings) {
    auto& layers = arrays.settings[entry.first];
    for (const auto& data : entry.second)
      layers.push_back(data.get());
  }
  return arrays;
}

} // namespace

// AddLayerCommand used to push_back() the new layer's copy of the active
// layer's flags and settings. The new layer's id is layerCount(), so on an
// array that had not grown that far yet, the copy landed on some earlier
// layer's slot.
TEST_F(RWLayerManagerTest, AddLayerPutsCopiedSettingsAtTheNewLayer)
{
  Molecule molecule;
  TestLayerManager manager;
  auto* rwmol = buildUnevenPluginArrays(manager, molecule);
  auto info = LayerManager::getMoleculeInfo(&molecule);
  const LayerData* oldLong3 = info->settings["Long"][3].get();

  manager.addLayer(rwmol); // layer 3

  ASSERT_EQ(info->layer.maxLayer(), 3u);
  const auto& shortSettings = info->settings["Short"];
  ASSERT_EQ(shortSettings.size(), 4u);
  EXPECT_EQ(shortSettings[1], nullptr);
  EXPECT_EQ(shortSettings[2], nullptr);
  ASSERT_NE(shortSettings[3], nullptr);
  EXPECT_NE(shortSettings[3].get(), shortSettings[0].get());
  EXPECT_EQ(info->enable["Short"],
            (std::vector<bool>{ true, false, false, true }));

  // "Long" already had a slot for layer 3; it now holds the new layer's own
  // copy of layer 0's settings, and a copy of layer 0's flag.
  const auto& longSettings = info->settings["Long"];
  ASSERT_EQ(longSettings.size(), 4u);
  ASSERT_NE(longSettings[3], nullptr);
  EXPECT_NE(longSettings[3].get(), longSettings[0].get());
  EXPECT_NE(longSettings[3].get(), oldLong3);
  EXPECT_EQ(info->enable["Long"],
            (std::vector<bool>{ false, false, false, false }));
}

// undo() used to pop the last entry of any array exactly layerCount() long,
// whatever redo() had done to it, so arrays redo() had appended to out of
// step never shrank again, and grew by one every undo/redo cycle.
TEST_F(RWLayerManagerTest, AddLayerUndoRedoCyclesLeavePluginArraysUnchanged)
{
  Molecule molecule;
  TestLayerManager manager;
  auto* rwmol = buildUnevenPluginArrays(manager, molecule);
  auto info = LayerManager::getMoleculeInfo(&molecule);

  const PluginArrays before = capturePluginArrays(*info);
  manager.addLayer(rwmol);
  const PluginArrays after = capturePluginArrays(*info);

  for (int cycle = 0; cycle < 3; ++cycle) {
    SCOPED_TRACE(cycle);
    rwmol->undoStack().undo();
    EXPECT_TRUE(capturePluginArrays(*info) == before);
    rwmol->undoStack().redo();
    EXPECT_TRUE(capturePluginArrays(*info) == after);
  }
}

// The copies redo() makes are owned by the molecule while the layer exists
// and by the undo command while it does not; nothing may outlive both.
TEST_F(RWLayerManagerTest, AddLayerSettingsDoNotOutliveTheMolecule)
{
  std::vector<std::weak_ptr<LayerData>> created;
  {
    Molecule molecule;
    TestLayerManager manager;
    auto* rwmol = buildUnevenPluginArrays(manager, molecule);
    auto info = LayerManager::getMoleculeInfo(&molecule);

    manager.addLayer(rwmol);
    for (int cycle = 0; cycle < 3; ++cycle) {
      for (const auto& entry : info->settings)
        for (const auto& data : entry.second)
          created.push_back(data);
      rwmol->undoStack().undo();
      rwmol->undoStack().redo();
    }
  }
  for (const auto& data : created)
    EXPECT_TRUE(data.expired());
}
