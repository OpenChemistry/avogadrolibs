/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/layer.h>
#include <avogadro/core/layermanager.h>
#include <avogadro/core/molecule.h>

using Avogadro::Core::LayerManager;
using Avogadro::Core::Molecule;

namespace {

// Layer state is owned by each Molecule, so there is no registry to isolate
// between cases -- only the active-molecule cursor, which is process-global.
// Mirrors the fixture in layertest.cpp; kept separate because it lives in a
// different translation unit.
class LayerManagerTest : public ::testing::Test, protected LayerManager
{
protected:
  void SetUp() override { m_activeInfo.reset(); }
};

} // namespace

// getMoleculeLayer(mol) is documented to hand back that molecule's own
// state, not a copy -- this is what lets qtgui edit it in place.
TEST_F(LayerManagerTest, GetMoleculeLayerReturnsTheMoleculesOwnState)
{
  Molecule molecule;
  molecule.addAtom(6);

  EXPECT_EQ(&LayerManager::getMoleculeLayer(&molecule), &molecule.layer());
}

// The doc comment on getMoleculeLayer(mol) says it "creates MoleculeInfo if
// not exists" -- check that a molecule whose layer info has never been
// touched still answers safely and ends up with real state afterwards.
TEST_F(LayerManagerTest, GetMoleculeLayerForMolCreatesInfoOnFirstUse)
{
  Molecule molecule;

  EXPECT_NO_FATAL_FAILURE(LayerManager::getMoleculeLayer(&molecule));
  EXPECT_NE(LayerManager::getMoleculeInfo(&molecule), nullptr);
}

// layerCount() with no active molecule is covered in layertest.cpp
// (LayerCountWithNoActiveMoleculeIsSafe); this is the other half.
TEST_F(LayerManagerTest, LayerCountReflectsTheActiveMoleculesLayers)
{
  Molecule molecule;
  molecule.addAtom(6);
  molecule.layer().addLayer();
  molecule.layer().addLayer();
  LayerManager::setActiveMolecule(&molecule);

  EXPECT_EQ(static_cast<size_t>(3), LayerManager::layerCount());
}

// With no active molecule, the no-arg getMoleculeLayer() falls back to a
// function-local static "empty" Layer (see layermanager.cpp) rather than
// constructing a fresh one on every call -- callers that stash the
// reference briefly must see the same object each time.
TEST_F(LayerManagerTest, GetMoleculeLayerNoArgReturnsTheSameEmptyLayerEachTime)
{
  EXPECT_EQ(&LayerManager::getMoleculeLayer(),
            &LayerManager::getMoleculeLayer());
}

// Once a molecule is active, the no-arg overload has to resolve to that
// molecule's own Layer object, the same as the mol-argument overload does.
TEST_F(LayerManagerTest, GetMoleculeLayerNoArgMatchesTheActiveMoleculesLayer)
{
  Molecule molecule;
  molecule.addAtom(6);
  LayerManager::setActiveMolecule(&molecule);

  EXPECT_EQ(&LayerManager::getMoleculeLayer(), &molecule.layer());
}
