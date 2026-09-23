/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/layermanager.h>
#include <avogadro/core/moleculeinfo.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/pluginlayermanager.h>

#include <memory>
#include <string>

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
