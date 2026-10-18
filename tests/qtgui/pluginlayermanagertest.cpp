/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/layermanager.h>
#include <avogadro/core/moleculeinfo.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/pluginlayermanager.h>

#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

using Avogadro::Index;
using Avogadro::MaxIndex;
using Avogadro::Core::LayerData;
using Avogadro::Core::LayerDataPtr;
using Avogadro::Core::LayerManager;
using Avogadro::Core::MoleculeInfo;
using Avogadro::QtGui::Molecule;
using Avogadro::QtGui::PluginLayerManager;

namespace {

// A tiny Core::LayerData subclass with an actual payload, so clone() (used
// whenever a MoleculeInfo is copied) can be checked for a real
// serialize()/deserialize() round trip rather than just an empty string.
class TestLayerData : public LayerData
{
public:
  std::string serialize() override { return std::to_string(m_value); }

  void deserialize(std::string save) override
  {
    m_save = save;
    m_value = save.empty() ? 0 : std::stoi(save);
  }

  LayerData* clone() override
  {
    auto* copy = new TestLayerData();
    copy->deserialize(serialize());
    return copy;
  }

  int value() const { return m_value; }
  void setValue(int v) { m_value = v; }

private:
  int m_value = 0;
};

class PluginLayerManagerTest : public ::testing::Test, protected LayerManager
{
protected:
  void SetUp() override { m_activeInfo.reset(); }
};

} // namespace

TEST_F(PluginLayerManagerTest, IsEnabledAndSetEnabled)
{
  Molecule molecule;
  molecule.addAtom(1);
  setActiveMolecule(&molecule);

  PluginLayerManager plugin("PluginA");
  EXPECT_FALSE(plugin.isEnabled());
  EXPECT_FALSE(plugin.isActiveLayerEnabled());

  plugin.setEnabled(true);
  EXPECT_TRUE(plugin.isEnabled());
  EXPECT_TRUE(plugin.isActiveLayerEnabled());
}

// 2 layers; atoms 0,1 in layer 0, atoms 2,3 in layer 1. "Plugin" is enabled
// only for layer 1, so atomEnabled()/bondEnabled() must track the atom's
// layer, not just whether the plugin is enabled anywhere.
TEST_F(PluginLayerManagerTest, AtomEnabledAndBondEnabledTrackLayer)
{
  Molecule molecule;
  molecule.addAtom(1);
  molecule.addAtom(1); // atoms 0,1 -> layer 0
  setActiveMolecule(&molecule);

  auto info = LayerManager::getMoleculeInfo(&molecule);
  info->layer.addLayer();
  info->layer.setActiveLayer(1);
  info->visible.push_back(true);
  info->locked.push_back(false);
  molecule.addAtom(1);
  molecule.addAtom(1); // atoms 2,3 -> layer 1

  PluginLayerManager plugin("Plugin");
  plugin.setEnabled(true); // enables the active layer, which is 1

  EXPECT_FALSE(plugin.atomEnabled(0));
  EXPECT_FALSE(plugin.atomEnabled(1));
  EXPECT_TRUE(plugin.atomEnabled(2));
  EXPECT_TRUE(plugin.atomEnabled(3));

  EXPECT_FALSE(plugin.bondEnabled(0, 1)); // neither atom enabled
  EXPECT_TRUE(plugin.bondEnabled(1, 2));  // one atom (2) enabled
  EXPECT_TRUE(plugin.bondEnabled(2, 3));  // both atoms enabled

  // atomEnabled(layer, atom) additionally filters by layer.
  EXPECT_TRUE(plugin.atomEnabled(1, 2));
  EXPECT_FALSE(plugin.atomEnabled(0, 2)); // atom 2 is in layer 1, not 0
}

TEST_F(PluginLayerManagerTest, AtomEnabledFalseWhenLayerNotVisible)
{
  Molecule molecule;
  molecule.addAtom(1);
  setActiveMolecule(&molecule);

  PluginLayerManager plugin("Plugin");
  plugin.setEnabled(true);
  ASSERT_TRUE(plugin.atomEnabled(0));

  auto info = LayerManager::getMoleculeInfo(&molecule);
  info->visible[0] = false;
  EXPECT_FALSE(plugin.atomEnabled(0));
}

// An atom the Layer has never heard about (its index is past
// Layer::atomCount()) reads back as MaxIndex, i.e. "in no layer".
TEST_F(PluginLayerManagerTest, AtomInNoLayerIsNotEnabledOrLocked)
{
  Molecule molecule;
  molecule.addAtom(1);
  molecule.addAtom(1);
  molecule.addAtom(1); // 3 atoms, all auto-registered into layer 0
  setActiveMolecule(&molecule);

  auto info = LayerManager::getMoleculeInfo(&molecule);
  info->layer.resize(2); // atom 2 is no longer registered in the Layer
  ASSERT_EQ(info->layer.getLayerID(2), MaxIndex);

  PluginLayerManager plugin("Plugin");
  plugin.setEnabled(true);
  info->locked[0] = true;

  EXPECT_FALSE(plugin.atomEnabled(2));
  EXPECT_FALSE(plugin.atomLocked(2));
  EXPECT_EQ(plugin.getLayerID(2), MaxIndex);
}

TEST_F(PluginLayerManagerTest, ActiveLayerLockedAndLayerCount)
{
  Molecule molecule;
  molecule.addAtom(1);
  setActiveMolecule(&molecule);

  auto info = LayerManager::getMoleculeInfo(&molecule);
  info->layer.addLayer(); // layer 1
  info->visible.push_back(true);
  info->locked.push_back(true); // layer 1 is locked

  PluginLayerManager plugin("Plugin");
  EXPECT_EQ(plugin.layerCount(), 2u);

  info->layer.setActiveLayer(0);
  EXPECT_FALSE(plugin.activeLayerLocked());

  info->layer.setActiveLayer(1);
  EXPECT_TRUE(plugin.activeLayerLocked());
}

// The `enable`/`locked` vectors are grown lazily and independently of
// Core::Layer (see Layer::addAtom()'s comment); a vector shorter than the
// current layer count must make readers fall back to a default rather than
// index past the end.
TEST_F(PluginLayerManagerTest, ShortEnableAndLockedVectorsFallBackSafely)
{
  Molecule molecule;
  molecule.addAtom(1);
  setActiveMolecule(&molecule);

  auto info = LayerManager::getMoleculeInfo(&molecule);
  // Grow the Layer to 3 layers directly, without ever touching
  // visible/locked/enable -- exactly what Layer::addAtom() documents can
  // happen when an atom lands in a layer past the last one anyone has told
  // the bookkeeping vectors about.
  info->layer.addLayer();
  info->layer.addLayer();
  ASSERT_EQ(info->layer.layerCount(), 3u);
  ASSERT_EQ(info->locked.size(), 1u); // still just the MoleculeInfo default
  info->enable["Plugin"] = { true };  // shorter than layerCount() too

  PluginLayerManager plugin("Plugin");

  info->layer.setActiveLayer(2);
  EXPECT_FALSE(plugin.activeLayerLocked());
  EXPECT_FALSE(plugin.isActiveLayerEnabled());

  // atom 0 is still in layer 0 (only the layer count grew, not its
  // membership); add a second atom while layer 2 is active so it lands
  // there (see Core::Molecule::addAtom() -> addAtomToActiveLayer()).
  molecule.addAtom(1);
  ASSERT_EQ(info->layer.getLayerID(1), 2u);
  EXPECT_FALSE(plugin.atomLocked(1));
  EXPECT_FALSE(plugin.atomEnabled(1));
}

TEST_F(PluginLayerManagerTest, TwoPluginsKeepIndependentState)
{
  Molecule molecule;
  molecule.addAtom(1);
  setActiveMolecule(&molecule);

  PluginLayerManager pluginA("A");
  PluginLayerManager pluginB("B");

  pluginA.setEnabled(true);
  EXPECT_TRUE(pluginA.isEnabled());
  EXPECT_FALSE(pluginB.isEnabled());

  pluginA.getSetting<TestLayerData>()->setValue(5);
  pluginB.getSetting<TestLayerData>()->setValue(9);
  EXPECT_EQ(pluginA.getSetting<TestLayerData>()->value(), 5);
  EXPECT_EQ(pluginB.getSetting<TestLayerData>()->value(), 9);
}

TEST_F(PluginLayerManagerTest, GetSettingCreatesDefaultAndPersists)
{
  Molecule molecule;
  molecule.addAtom(1);
  setActiveMolecule(&molecule);

  PluginLayerManager plugin("Plugin");
  auto* first = plugin.getSetting<TestLayerData>(); // MaxIndex -> active (0)
  ASSERT_NE(first, nullptr);
  EXPECT_EQ(first->value(), 0); // default-constructed

  first->setValue(7);
  auto* second = plugin.getSetting<TestLayerData>(0);
  EXPECT_EQ(second, first); // same stored object, not recreated
  EXPECT_EQ(second->value(), 7);
}

// Cloning happens whenever a MoleculeInfo is copied (see
// MoleculeInfo::cloneSettings()); a plugin's setting must come along as an
// independent copy, not a shared pointer to the original.
TEST_F(PluginLayerManagerTest, SettingsClonedNotSharedThroughMoleculeInfoCopy)
{
  Molecule molecule;
  molecule.addAtom(1);
  setActiveMolecule(&molecule);

  PluginLayerManager plugin("Plugin");
  plugin.getSetting<TestLayerData>(0)->setValue(42);

  auto info = LayerManager::getMoleculeInfo(&molecule);
  MoleculeInfo copy(*info); // exercises LayerData::clone() via cloneSettings()

  LayerDataPtr originalPtr = info->settings["Plugin"][0];
  LayerDataPtr copyPtr = copy.settings["Plugin"][0];
  ASSERT_NE(copyPtr, nullptr);
  EXPECT_NE(originalPtr.get(), copyPtr.get()); // distinct objects
  EXPECT_EQ(static_cast<TestLayerData*>(copyPtr.get())->value(), 42);

  // Mutating the original after the copy must not reach the clone.
  plugin.getSetting<TestLayerData>(0)->setValue(99);
  EXPECT_EQ(static_cast<TestLayerData*>(copyPtr.get())->value(), 42);
  EXPECT_EQ(static_cast<TestLayerData*>(originalPtr.get())->value(), 99);
}

// The Snapshot must answer exactly what the per-call API answers, including
// for layer state that is ragged: `enable`/`visible` shorter than the layer
// count, disabled and invisible layers, atoms the Layer has never heard of,
// null settings slots, a missing settings entry, and an active layer that is
// not layer 0.
namespace {

struct SnapshotConfig
{
  const char* name;
  std::vector<size_t> atomLayers; // layer id of atoms 0..n-1
  size_t layerCount;              // layers 0..layerCount-1 exist
  size_t active;
  bool hasEnable;                // plugin has an `enable` entry at all
  std::vector<bool> enable;      // possibly shorter than layerCount
  std::vector<bool> visible;     // possibly shorter than layerCount
  bool hasSettings;              // plugin has a `settings` entry at all
  std::vector<size_t> nullSlots; // slots left null in that entry
  size_t settingsSize;           // initial settings array length
};

void setupSnapshotConfig(const SnapshotConfig& c, Molecule& molecule)
{
  auto info = LayerManager::getMoleculeInfo(&molecule);
  for (size_t i = 0; i < c.atomLayers.size(); ++i)
    info->layer.addAtom(c.atomLayers[i], i);
  while (info->layer.layerCount() < c.layerCount)
    info->layer.addLayer();
  info->layer.setActiveLayer(c.active);
  info->visible = c.visible;
  info->locked.assign(c.layerCount, false);
  if (c.hasEnable)
    info->enable["Plugin"] = c.enable;
  if (c.hasSettings) {
    Avogadro::Core::Array<LayerDataPtr> settings;
    for (size_t i = 0; i < c.settingsSize; ++i) {
      auto d = std::make_shared<TestLayerData>();
      d->setValue(static_cast<int>(i) + 100);
      settings.push_back(d);
    }
    for (size_t i : c.nullSlots)
      if (i < settings.size())
        settings[i] = nullptr;
    info->settings["Plugin"] = settings;
  }
}

// null / non-null of each slot, and whether the entry exists at all
std::pair<bool, std::vector<bool>> settingsShape(Molecule& molecule)
{
  auto info = LayerManager::getMoleculeInfo(&molecule);
  auto it = info->settings.find("Plugin");
  if (it == info->settings.end())
    return { false, {} };
  std::vector<bool> shape;
  for (size_t i = 0; i < it->second.size(); ++i)
    shape.push_back(it->second[i] != nullptr);
  return { true, shape };
}

void checkSnapshot(const SnapshotConfig& c,
                   const std::function<void(const Molecule*)>& activate)
{
  SCOPED_TRACE(c.name);
  const size_t n = c.atomLayers.size() + 5;
  PluginLayerManager plugin("Plugin");

  // Two identical setups: one queried through a snapshot, one through the
  // per-call API. The settings arrays they are left with (which the CJSON
  // writer saves) must have the same shape.
  Molecule viaSnapshot;
  setupSnapshotConfig(c, viaSnapshot);
  activate(&viaSnapshot);
  {
    auto snap = plugin.snapshot<TestLayerData>();
    for (Index a = 0; a < n; ++a)
      if (snap.atomEnabled(a))
        snap.atomSetting(a);
  }
  Molecule viaApi;
  setupSnapshotConfig(c, viaApi);
  activate(&viaApi);
  for (Index a = 0; a < n; ++a)
    if (plugin.atomEnabled(a))
      plugin.getSetting<TestLayerData>(plugin.getLayerID(a));
  EXPECT_EQ(settingsShape(viaSnapshot), settingsShape(viaApi));

  // Now the active-layer and per-layer queries, again on both.
  activate(&viaSnapshot);
  {
    auto snap = plugin.snapshot<TestLayerData>();
    EXPECT_NE(snap.setting(MaxIndex), nullptr);
    snap.setting(c.layerCount + 2);
  }
  activate(&viaApi);
  plugin.getSetting<TestLayerData>();
  plugin.getSetting<TestLayerData>(c.layerCount + 2);
  EXPECT_EQ(settingsShape(viaSnapshot), settingsShape(viaApi));

  // Answers match the per-call API on a fresh setup.
  Molecule molecule;
  setupSnapshotConfig(c, molecule);
  activate(&molecule);
  auto snap = plugin.snapshot<TestLayerData>();
  for (Index a = 0; a < n; ++a) {
    EXPECT_EQ(snap.atomEnabled(a), plugin.atomEnabled(a)) << "atom " << a;
    EXPECT_EQ(snap.getLayerID(a), plugin.getLayerID(a)) << "atom " << a;
    EXPECT_EQ(snap.atomSetting(a),
              plugin.getSetting<TestLayerData>(plugin.getLayerID(a)))
      << "atom " << a;
    for (Index b = 0; b < n; ++b)
      EXPECT_EQ(snap.bondEnabled(a, b), plugin.bondEnabled(a, b));
  }
  for (size_t layer = 0; layer < c.layerCount; ++layer)
    EXPECT_EQ(snap.setting(layer), plugin.getSetting<TestLayerData>(layer));
  EXPECT_EQ(snap.setting(MaxIndex), plugin.getSetting<TestLayerData>());
  EXPECT_EQ(snap.setting(MaxIndex), plugin.getSetting<TestLayerData>(c.active));
  EXPECT_EQ(snap.setting(c.layerCount + 2),
            plugin.getSetting<TestLayerData>(c.layerCount + 2));
}

} // namespace

TEST_F(PluginLayerManagerTest, SnapshotMatchesPerCallApi)
{
  const std::vector<SnapshotConfig> configs = {
    { "regular",
      { 0, 0, 1, 1, 2 },
      3,
      0,
      true,
      { true, true, true },
      { true, true, true },
      true,
      {},
      3 },
    { "disabled and invisible layers",
      { 0, 1, 2, 3, 1, 0 },
      4,
      0,
      true,
      { true, false, true, true },
      { true, true, false, true },
      true,
      {},
      4 },
    { "enable shorter than layers",
      { 0, 1, 2, 3 },
      4,
      1,
      true,
      { true, true },
      { true, true, true, true },
      true,
      {},
      4 },
    { "visible shorter than layers",
      { 0, 1, 2, 3 },
      4,
      1,
      true,
      { true, true, true, true },
      { true, true },
      true,
      {},
      4 },
    { "active layer not 0, settings short",
      { 0, 1, 2, 3, 3 },
      4,
      3,
      true,
      { false, true, true, true },
      { true, true, true, true },
      true,
      {},
      1 },
    { "null settings slots",
      { 0, 1, 2, 0 },
      3,
      2,
      true,
      { true, true, true },
      { true, true, true },
      true,
      { 0, 2 },
      3 },
    { "missing settings entry",
      { 0, 1, 1 },
      2,
      1,
      true,
      { true, true },
      { true, true },
      false,
      {},
      0 },
    { "missing enable entry",
      { 0, 1, 1 },
      2,
      0,
      false,
      {},
      { true, true },
      true,
      {},
      2 },
    { "active layer one past max",
      { 0, 1 },
      2,
      2,
      true,
      { true, true, true },
      { true, true, true },
      true,
      {},
      2 },
    { "disabled layer stays null",
      { 0, 1, 2 },
      3,
      0,
      true,
      { true, false, true },
      { true, true, true },
      true,
      { 1 },
      3 },
    { "single atom, no atoms in some layers",
      { 3 },
      4,
      0,
      true,
      { true, true, true, true },
      { true, true, true, true },
      false,
      {},
      0 },
  };
  for (const auto& c : configs)
    checkSnapshot(c, [this](const Molecule* m) { setActiveMolecule(m); });
}

TEST_F(PluginLayerManagerTest, SnapshotWithNoActiveMolecule)
{
  PluginLayerManager plugin("Plugin");
  auto snap = plugin.snapshot<TestLayerData>();
  EXPECT_FALSE(snap.atomEnabled(0));
  EXPECT_FALSE(snap.bondEnabled(0, 1));
  EXPECT_EQ(snap.getLayerID(0), MaxIndex);
  EXPECT_EQ(snap.setting(MaxIndex), nullptr);
  EXPECT_EQ(snap.setting(0), nullptr);
  EXPECT_EQ(snap.atomSetting(3), nullptr);
}
