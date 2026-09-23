/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/layermanager.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/rwlayermanager.h>
#include <avogadro/qtgui/rwmolecule.h>

using Avogadro::Index;
using Avogadro::Core::LayerManager;
using Avogadro::QtGui::Molecule;
using Avogadro::QtGui::RWLayerManager;

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
