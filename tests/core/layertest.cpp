/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/layer.h>
#include <avogadro/core/layermanager.h>
#include <avogadro/core/molecule.h>

using Avogadro::Index;
using Avogadro::Core::LayerManager;
using Avogadro::Core::Molecule;

namespace {

const Index atomsPerLayer = 2;
const size_t numLayers = 3;

// Fill @p molecule in place with atomsPerLayer * numLayers atoms spread over
// numLayers layers. Deliberately not a function returning a Molecule: that
// would exercise the very copy and move paths these tests are checking.
void buildMultiLayer(Molecule& molecule)
{
  for (size_t layer = 0; layer < numLayers; ++layer) {
    if (layer > 0)
      molecule.layer().addLayer();
    for (Index i = 0; i < atomsPerLayer; ++i) {
      auto atom = molecule.addAtom(6);
      molecule.layer().addAtom(layer, atom.index());
    }
  }
  // Core::Layer tracks only the atom-to-layer mapping. The parallel per-layer
  // flags live in MoleculeInfo and are normally grown by RWLayerManager in
  // qtgui, so size them here to match what a real multi-layer molecule has.
  auto info = LayerManager::getMoleculeInfo(&molecule);
  info->visible.assign(numLayers, true);
  info->locked.assign(numLayers, false);
}

void expectSameLayers(const Molecule& actual, const Molecule& expected)
{
  EXPECT_EQ(actual.layer().maxLayer(), expected.layer().maxLayer());
  EXPECT_EQ(actual.atomCount(), expected.atomCount());
  for (Index i = 0; i < expected.atomCount(); ++i)
    EXPECT_EQ(actual.layer().getLayerID(i), expected.layer().getLayerID(i))
      << "atom " << i;
}

// LayerManager keeps a process-global map keyed by raw Molecule*, and nothing
// ever removes entries from it (deleteMolecule has no callers). A molecule
// allocated at an address a previous test's molecule used therefore inherits
// that dead molecule's layer state, which makes these cases order-dependent.
// Clear the registry between cases. Safe here because every molecule in these
// tests is a local that has already been destroyed by the time SetUp runs.
class LayerTest : public ::testing::Test, protected LayerManager
{
protected:
  void SetUp() override { m_molToInfo.clear(); }
};

} // namespace

TEST_F(LayerTest, BuildsTheExpectedLayers)
{
  Molecule molecule;
  buildMultiLayer(molecule);

  EXPECT_EQ(molecule.atomCount(), atomsPerLayer * numLayers);
  EXPECT_EQ(molecule.layer().maxLayer(), numLayers - 1);
  EXPECT_EQ(molecule.layer().getLayerID(0), 0u);
  EXPECT_EQ(molecule.layer().getLayerID(atomsPerLayer * 2), 2u);
}

TEST_F(LayerTest, CopyConstructKeepsLayers)
{
  Molecule original;
  buildMultiLayer(original);

  Molecule copy(original);

  expectSameLayers(copy, original);
}

// Regression: this was a use-after-free. Molecule::operator= reassigned
// m_molToInfo[this], dropping the last reference to the MoleculeInfo that
// m_layers refers to, then wrote through the dangling reference.
TEST_F(LayerTest, CopyAssignMultiLayerDoesNotCrash)
{
  Molecule original;
  buildMultiLayer(original);
  Molecule target;
  target.addAtom(8);

  target = original;

  expectSameLayers(target, original);
}

// The move constructor initialises m_layers from this molecule's own
// MoleculeInfo and then reassigns m_molToInfo[this] to other's, freeing the
// info it just took a reference to.
TEST_F(LayerTest, MoveConstructMultiLayerDoesNotCrash)
{
  Molecule original;
  buildMultiLayer(original);
  const size_t maxLayer = original.layer().maxLayer();
  const Index atoms = original.atomCount();

  Molecule moved(std::move(original));

  EXPECT_EQ(moved.layer().maxLayer(), maxLayer);
  EXPECT_EQ(moved.atomCount(), atoms);
}

// The same defect on the move-assignment path, which calcworker.cpp reaches
// with m_molSnapshot = std::move(molSnapshot).
TEST_F(LayerTest, MoveAssignMultiLayerDoesNotCrash)
{
  Molecule original;
  buildMultiLayer(original);
  const size_t maxLayer = original.layer().maxLayer();
  const Index atoms = original.atomCount();
  Molecule target;
  target.addAtom(8);

  target = std::move(original);

  EXPECT_EQ(target.layer().maxLayer(), maxLayer);
  EXPECT_EQ(target.atomCount(), atoms);
}

// Layers belong to the molecule: editing a copy must not reach back into the
// molecule it came from. Undo snapshots (ModifyMoleculeCommand) and worker
// copies (calcworker's m_molSnapshot) both depend on that.
TEST_F(LayerTest, CopyAssignGivesIndependentLayerState)
{
  Molecule original;
  buildMultiLayer(original);
  Molecule copy;
  copy.addAtom(8);
  copy = original;

  LayerManager::getMoleculeInfo(&copy)->visible[0] = false;

  EXPECT_TRUE(LayerManager::getMoleculeInfo(&original)->visible[0])
    << "editing the copy leaked back into the original";
}

TEST_F(LayerTest, SelfAssignmentKeepsLayers)
{
  Molecule molecule;
  buildMultiLayer(molecule);
  const size_t maxLayer = molecule.layer().maxLayer();
  const Index atoms = molecule.atomCount();

  Molecule& alias = molecule;
  molecule = alias;

  EXPECT_EQ(molecule.layer().maxLayer(), maxLayer);
  EXPECT_EQ(molecule.atomCount(), atoms);
}
