/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <memory>
#include <type_traits>

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

// Layer state is owned by each Molecule, so there is no registry to isolate
// between cases -- only the active-molecule cursor, which is process-global.
class LayerTest : public ::testing::Test, protected LayerManager
{
protected:
  void SetUp() override { m_activeInfo.reset(); }
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

// Layer state belongs to the molecule, so a lookup is just a handle to it.
TEST_F(LayerTest, LookupReturnsTheMoleculesOwnState)
{
  Molecule molecule;
  buildMultiLayer(molecule);

  EXPECT_EQ(LayerManager::getMoleculeInfo(&molecule), molecule.layerInfo());
  EXPECT_EQ(findMoleculeInfo(nullptr), nullptr);
  EXPECT_EQ(activeMoleculeInfo(), nullptr);
}

// Phase 2: the state dies with the molecule. Previously every molecule ever
// constructed left a permanent entry in a global registry.
TEST_F(LayerTest, LayerStateIsReleasedWithTheMolecule)
{
  std::weak_ptr<Avogadro::Core::MoleculeInfo> watch;
  {
    Molecule molecule;
    buildMultiLayer(molecule);
    watch = molecule.layerInfo();
    EXPECT_FALSE(watch.expired());
  }
  EXPECT_TRUE(watch.expired()) << "layer state outlived its molecule";
}

// An undo command holding the state keeps it alive past the molecule, which is
// why the handle is shared rather than owned outright.
TEST_F(LayerTest, SharedHandleOutlivesTheMolecule)
{
  std::shared_ptr<Avogadro::Core::MoleculeInfo> held;
  {
    Molecule molecule;
    buildMultiLayer(molecule);
    held = molecule.layerInfo();
  }
  ASSERT_TRUE(held != nullptr);
  EXPECT_EQ(held->layer.maxLayer(), numLayers - 1);
}

// A moved-from molecule has to stay usable -- accessing its layers must not
// dereference null. It shares the moved-to molecule's state rather than
// getting fresh state, because allocating here would make the noexcept move
// able to throw.
TEST_F(LayerTest, MovedFromMoleculeStillHasLayerState)
{
  Molecule original;
  buildMultiLayer(original);
  Molecule moved(std::move(original));

  EXPECT_TRUE(original.layerInfo() != nullptr);
  EXPECT_EQ(moved.layer().maxLayer(), numLayers - 1);
  EXPECT_NO_FATAL_FAILURE(original.layer().maxLayer());
}

// The point of the ownership change: moving a molecule must not allocate, so
// the noexcept on the move operations is honest.
TEST_F(LayerTest, MovingAMoleculeDoesNotAllocateLayerState)
{
  static_assert(std::is_nothrow_move_constructible<Molecule>::value,
                "Molecule's move constructor must stay noexcept");
  static_assert(std::is_nothrow_move_assignable<Molecule>::value,
                "Molecule's move assignment must stay noexcept");

  Molecule original;
  buildMultiLayer(original);
  auto* before = original.layerInfo().get();

  Molecule moved(std::move(original));

  // The handle was transferred, not rebuilt.
  EXPECT_EQ(moved.layerInfo().get(), before);
}

// layerCount() used to assert and then dereference m_molToInfo[nullptr]; the
// assert compiles out under NDEBUG, leaving a null dereference in release.
TEST_F(LayerTest, LayerCountWithNoActiveMoleculeIsSafe)
{
  EXPECT_EQ(activeMoleculeInfo(), nullptr);
  EXPECT_EQ(LayerManager::layerCount(), 0u);
}

TEST_F(LayerTest, ActiveLayerWithNoActiveMoleculeIsSafe)
{
  EXPECT_EQ(activeMoleculeInfo(), nullptr);
  // Must not dereference null; an empty layer is the safe answer.
  EXPECT_EQ(LayerManager::getMoleculeLayer().maxLayer(), 0u);
  EXPECT_EQ(LayerManager::getMoleculeInfo(), nullptr);
}

TEST_F(LayerTest, NullMoleculeYieldsNoState)
{
  EXPECT_EQ(LayerManager::getMoleculeInfo(nullptr), nullptr);
  EXPECT_EQ(LayerManager::getMoleculeLayer(nullptr).maxLayer(), 0u);
}

namespace {

// A LayerData that reports its own lifetime, so the tests can show that layer
// settings are actually released rather than leaked.
int g_liveSettings = 0;

struct CountedLayerData : Avogadro::Core::LayerData
{
  std::string tag;

  explicit CountedLayerData(std::string t = "") : tag(std::move(t))
  {
    ++g_liveSettings;
  }
  CountedLayerData(const CountedLayerData& other)
    : LayerData(other), tag(other.tag)
  {
    ++g_liveSettings;
  }
  ~CountedLayerData() override { --g_liveSettings; }

  std::string serialize() override { return tag; }
  void deserialize(std::string save) override { tag = save; }
  LayerData* clone() override { return new CountedLayerData(*this); }
};

Avogadro::Core::LayerDataPtr makeSetting(const std::string& tag)
{
  return std::make_shared<CountedLayerData>(tag);
}

} // namespace

// Phase 3: settings used to be raw LayerData pointers that nothing ever freed.
TEST_F(LayerTest, LayerSettingsAreReleasedWithTheMolecule)
{
  const int before = g_liveSettings;
  {
    Molecule molecule;
    buildMultiLayer(molecule);
    molecule.layerInfo()->settings["TestPlugin"].push_back(makeSetting("a"));
    molecule.layerInfo()->settings["TestPlugin"].push_back(makeSetting("b"));
    EXPECT_EQ(g_liveSettings, before + 2);
  }
  EXPECT_EQ(g_liveSettings, before) << "layer settings leaked";
}

// Copies get their own settings objects, so editing one cannot reach the other.
TEST_F(LayerTest, CopyClonesLayerSettings)
{
  Molecule original;
  buildMultiLayer(original);
  original.layerInfo()->settings["TestPlugin"].push_back(
    makeSetting("original"));

  Molecule copy(original);

  ASSERT_EQ(copy.layerInfo()->settings["TestPlugin"].size(), 1u);
  auto* originalData = static_cast<CountedLayerData*>(
    original.layerInfo()->settings["TestPlugin"][0].get());
  auto* copyData = static_cast<CountedLayerData*>(
    copy.layerInfo()->settings["TestPlugin"][0].get());

  EXPECT_NE(originalData, copyData)
    << "the copy shares the original's settings";
  EXPECT_EQ(copyData->tag, "original") << "the copy lost its settings";

  copyData->tag = "edited";
  EXPECT_EQ(originalData->tag, "original")
    << "editing the copy's settings reached the original";
}

TEST_F(LayerTest, CopiedSettingsAreReleasedIndependently)
{
  const int before = g_liveSettings;
  {
    Molecule original;
    buildMultiLayer(original);
    original.layerInfo()->settings["TestPlugin"].push_back(makeSetting("x"));
    {
      Molecule copy(original);
      EXPECT_EQ(g_liveSettings, before + 2) << "the copy did not clone";
    }
    EXPECT_EQ(g_liveSettings, before + 1) << "the copy's clone leaked";
  }
  EXPECT_EQ(g_liveSettings, before);
}

// Phase 4: the active molecule is held weakly. It used to be a raw
// `const Molecule*`, which dangled the moment that molecule was destroyed --
// and since Phase 2 made the lookup dereference it rather than compare
// addresses, reading it afterwards either faulted or silently reported
// whatever object had taken over the address.
TEST_F(LayerTest, ActiveMoleculeDoesNotOutliveItsMolecule)
{
  {
    Molecule molecule;
    buildMultiLayer(molecule);
    LayerManager::setActiveMolecule(&molecule);
    ASSERT_TRUE(activeMoleculeInfo() != nullptr);
    EXPECT_EQ(LayerManager::layerCount(), numLayers);
  }

  EXPECT_EQ(activeMoleculeInfo(), nullptr)
    << "the active molecule outlived the molecule that owned it";
  EXPECT_EQ(LayerManager::layerCount(), 0u);
  EXPECT_EQ(LayerManager::getMoleculeInfo(), nullptr);
}

// The realistic sequence: close one molecule, open another that the allocator
// places at the same address. The stale pointer used to resolve to the new
// molecule's state while the manager still believed the old one was active.
TEST_F(LayerTest, ReusedAddressDoesNotResurrectTheOldActiveMolecule)
{
  std::unique_ptr<Molecule> first(new Molecule);
  buildMultiLayer(*first);
  LayerManager::setActiveMolecule(first.get());
  EXPECT_EQ(LayerManager::layerCount(), numLayers);

  first.reset();

  std::unique_ptr<Molecule> second(new Molecule);
  second->addAtom(8);

  // Whether or not `second` landed on `first`'s address, nothing is active.
  EXPECT_EQ(activeMoleculeInfo(), nullptr);
  EXPECT_EQ(LayerManager::layerCount(), 0u);
}

// An undo command holding the state keeps it resolvable, which is intended:
// the command still needs to apply against it.
TEST_F(LayerTest, ActiveInfoStaysResolvableWhileAnUndoCommandHoldsIt)
{
  std::shared_ptr<Avogadro::Core::MoleculeInfo> heldByUndo;
  {
    Molecule molecule;
    buildMultiLayer(molecule);
    LayerManager::setActiveMolecule(&molecule);
    heldByUndo = molecule.layerInfo();
  }
  EXPECT_TRUE(activeMoleculeInfo() != nullptr);
  EXPECT_EQ(activeMoleculeInfo(), heldByUndo);
}

// A moved-from molecule must not share layer state with the moved-to one.
// It used to keep the same handle, so a write through the moved-from object
// reached the molecule that had just been moved into.
TEST_F(LayerTest, MovedFromMoleculeDoesNotShareLayerState)
{
  Molecule original;
  buildMultiLayer(original);
  Molecule moved(std::move(original));

  ASSERT_EQ(moved.layer().maxLayer(), numLayers - 1);
  EXPECT_NE(original.layerInfo(), moved.layerInfo())
    << "the moved-from molecule still shares the moved-to molecule's state";

  // Mutating the moved-from molecule must leave the moved-to one alone.
  original.layer().addLayer();
  original.layer().addAtom(0, 0);
  original.layerInfo()->visible.assign(1, false);

  EXPECT_EQ(moved.layer().maxLayer(), numLayers - 1);
  for (Index i = 0; i < atomsPerLayer * numLayers; ++i)
    EXPECT_EQ(moved.layer().getLayerID(i), i / atomsPerLayer) << "atom " << i;
}

// The same, through assignment into the moved-from molecule.
TEST_F(LayerTest, AssigningToAMovedFromMoleculeLeavesTheTargetAlone)
{
  Molecule original;
  buildMultiLayer(original);
  Molecule moved(std::move(original));

  Molecule other;
  other.addAtom(8);
  other.layer().addLayer();
  original = other; // copy-assign into the moved-from molecule

  EXPECT_EQ(moved.layer().maxLayer(), numLayers - 1)
    << "assigning to the moved-from molecule changed the moved-to one";
}

// A moved-from molecule stays usable: its layer state is recreated on demand.
TEST_F(LayerTest, MovedFromMoleculeRecreatesItsLayerState)
{
  Molecule original;
  buildMultiLayer(original);
  Molecule moved(std::move(original));

  EXPECT_TRUE(original.layerInfo() != nullptr);
  EXPECT_EQ(original.layer().maxLayer(), 0u);
  EXPECT_EQ(original.layerInfo()->visible.size(), 1u);
}

TEST_F(LayerTest, addAtomBeyondTheEndGrowsByAtomNotLayer)
{
  // m_atomAndLayers is indexed by atom, and the branch that grows it resized
  // to layer + 1 instead: adding atom 5 to layer 0 sized the array to 1 and
  // then wrote to element 5. RemoveAtomCommand::undo() reaches this with the
  // index of the atom swap-and-pop moved.
  Avogadro::Core::Layer layer;
  layer.addAtom(0, 5);

  EXPECT_EQ(static_cast<size_t>(0), layer.getLayerID(5));
  // Atoms the gap skipped are not in any layer yet.
  EXPECT_EQ(Avogadro::MaxIndex, layer.getLayerID(3));
  EXPECT_EQ(Avogadro::MaxIndex, layer.getLayerID(6));

  layer.addAtom(0, 40);
  EXPECT_EQ(static_cast<size_t>(0), layer.getLayerID(40));
}

TEST_F(LayerTest, addAtomToALayerThatDoesNotExistYetCreatesIt)
{
  // A layer id past the last one grows the range rather than being refused:
  // layers are consecutive ids, so the atom lands in the layer it asked for
  // and layerCount() agrees with what the atoms hold.
  Avogadro::Core::Layer layer;
  EXPECT_EQ(static_cast<size_t>(0), layer.maxLayer());
  EXPECT_EQ(static_cast<size_t>(1), layer.layerCount());

  layer.addAtom(3, 0);
  EXPECT_EQ(static_cast<size_t>(3), layer.getLayerID(0));
  EXPECT_EQ(static_cast<size_t>(3), layer.maxLayer());
  EXPECT_EQ(static_cast<size_t>(4), layer.layerCount());

  // A layer that already exists leaves the range alone.
  layer.addAtom(1, 1);
  EXPECT_EQ(static_cast<size_t>(1), layer.getLayerID(1));
  EXPECT_EQ(static_cast<size_t>(3), layer.maxLayer());

  // MaxIndex is the "no layer" sentinel, not a layer id: taking it as one
  // would wrap layerCount() to zero.
  layer.addAtom(Avogadro::MaxIndex, 2);
  EXPECT_EQ(Avogadro::MaxIndex, layer.getLayerID(2));
  EXPECT_EQ(static_cast<size_t>(3), layer.maxLayer());
  EXPECT_EQ(static_cast<size_t>(4), layer.layerCount());
}

// ---------------------------------------------------------------------------
// Direct Core::Layer tests. Copy/move/lifetime/active-molecule behaviour is
// covered above; these exercise the plain atom<->layer bookkeeping in
// isolation.
// ---------------------------------------------------------------------------

TEST_F(LayerTest, EmptyLayerHasSensibleDefaults)
{
  Avogadro::Core::Layer layer;
  EXPECT_EQ(static_cast<size_t>(0), layer.atomCount());
  EXPECT_EQ(static_cast<size_t>(0), layer.maxLayer());
  EXPECT_EQ(static_cast<size_t>(1), layer.layerCount());
  // No atoms are tracked yet, so any index is "not in a layer".
  EXPECT_EQ(Avogadro::MaxIndex, layer.getLayerID(0));
}

TEST_F(LayerTest, AddAtomWithoutIndexAppends)
{
  Avogadro::Core::Layer layer;
  layer.addAtom(0);
  layer.addAtom(0);
  layer.addAtom(1);

  EXPECT_EQ(static_cast<size_t>(3), layer.atomCount());
  EXPECT_EQ(static_cast<size_t>(0), layer.getLayerID(0));
  EXPECT_EQ(static_cast<size_t>(0), layer.getLayerID(1));
  EXPECT_EQ(static_cast<size_t>(1), layer.getLayerID(2));
}

TEST_F(LayerTest, AddAtomToActiveLayerRespectsSetActiveLayer)
{
  Avogadro::Core::Layer layer;
  layer.addAtom(0);        // atom 0, layer 0
  layer.setActiveLayer(1); // one past maxLayer -- a not-yet-existing layer
  layer.addAtomToActiveLayer(1); // atom 1

  EXPECT_EQ(static_cast<size_t>(1), layer.getLayerID(1));
  EXPECT_EQ(static_cast<size_t>(1), layer.maxLayer());
  EXPECT_EQ(static_cast<size_t>(1), layer.activeLayer());
}

TEST_F(LayerTest, RemoveAtomIsSwapAndPop)
{
  // Matches how Molecule::removeAtom() removes atoms elsewhere, so this
  // has to be swap-and-pop too or the two arrays desync.
  Avogadro::Core::Layer layer;
  layer.addAtom(0); // atom 0 -> layer 0
  layer.addAtom(1); // atom 1 -> layer 1
  layer.addAtom(2); // atom 2 -> layer 2

  layer.removeAtom(0);

  // The last atom's layer moves into the removed slot; nothing else shifts.
  EXPECT_EQ(static_cast<size_t>(2), layer.atomCount());
  EXPECT_EQ(static_cast<size_t>(2), layer.getLayerID(0));
  EXPECT_EQ(static_cast<size_t>(1), layer.getLayerID(1));
}

TEST_F(LayerTest, AddLayerWithoutIndexOnlyGrowsMaxLayer)
{
  Avogadro::Core::Layer layer;
  layer.addAtom(0);
  layer.addAtom(1); // pre-existing layer 1, to check it is left untouched

  layer.addLayer(); // no shifting -- just a new top layer

  EXPECT_EQ(static_cast<size_t>(2), layer.maxLayer());
  EXPECT_EQ(static_cast<size_t>(0), layer.getLayerID(0));
  EXPECT_EQ(static_cast<size_t>(1), layer.getLayerID(1));
}

TEST_F(LayerTest, AddLayerAtIndexShiftsLaterLayersUp)
{
  Avogadro::Core::Layer layer;
  layer.addAtom(0);
  layer.addAtom(1);
  layer.addAtom(2);

  layer.addLayer(1); // insert a new layer 1; old 1 and 2 shift to 2 and 3

  EXPECT_EQ(static_cast<size_t>(3), layer.maxLayer());
  EXPECT_EQ(static_cast<size_t>(0), layer.getLayerID(0)); // untouched
  EXPECT_EQ(static_cast<size_t>(2), layer.getLayerID(1)); // was 1
  EXPECT_EQ(static_cast<size_t>(3), layer.getLayerID(2)); // was 2
}

TEST_F(LayerTest, RemoveLayerShiftsLaterLayersDown)
{
  // Layer 1 has no atoms in it, so this only exercises the renumbering --
  // no atom needs to move into the active layer. The mixed case (atoms
  // present in the removed layer) is covered by
  // RemoveLayerWithAtomsStillInItStaysInLockstep below.
  Avogadro::Core::Layer layer;
  layer.addAtom(0);
  layer.addLayer();
  layer.addLayer();
  layer.addAtom(2, 1); // second atom lives in layer 2

  layer.removeLayer(1);

  EXPECT_EQ(static_cast<size_t>(1), layer.maxLayer());
  EXPECT_EQ(static_cast<size_t>(2), layer.atomCount());
  EXPECT_EQ(static_cast<size_t>(0), layer.getLayerID(0));
  EXPECT_EQ(static_cast<size_t>(1), layer.getLayerID(1)); // was layer 2
}

TEST_F(LayerTest, ClearResetsEverything)
{
  Avogadro::Core::Layer layer;
  layer.addAtom(0);
  layer.addLayer();
  layer.setActiveLayer(1);

  layer.clear();

  EXPECT_EQ(static_cast<size_t>(0), layer.atomCount());
  EXPECT_EQ(static_cast<size_t>(0), layer.activeLayer());
  EXPECT_EQ(static_cast<size_t>(0), layer.maxLayer());
  EXPECT_EQ(static_cast<size_t>(1), layer.layerCount());
}

TEST_F(LayerTest, ResizeGrowsWithActiveLayerAndShrinks)
{
  Avogadro::Core::Layer layer;
  layer.addLayer();
  layer.setActiveLayer(1);

  layer.resize(3); // grow from 0 atoms; new atoms default to the active layer

  EXPECT_EQ(static_cast<size_t>(3), layer.atomCount());
  EXPECT_EQ(static_cast<size_t>(1), layer.getLayerID(0));
  EXPECT_EQ(static_cast<size_t>(1), layer.getLayerID(2));

  layer.resize(1); // shrink -- excess entries are dropped, not reassigned

  EXPECT_EQ(static_cast<size_t>(1), layer.atomCount());
  EXPECT_EQ(static_cast<size_t>(1), layer.getLayerID(0));
  EXPECT_EQ(Avogadro::MaxIndex, layer.getLayerID(1)); // no longer tracked
}

TEST_F(LayerTest, SwapLayerSwapsTwoEntries)
{
  Avogadro::Core::Layer layer;
  layer.addAtom(0);
  layer.addAtom(1);
  layer.addAtom(2);

  layer.swapLayer(0, 2);

  EXPECT_EQ(static_cast<size_t>(2), layer.getLayerID(0));
  EXPECT_EQ(static_cast<size_t>(1), layer.getLayerID(1));
  EXPECT_EQ(static_cast<size_t>(0), layer.getLayerID(2));
}

TEST_F(LayerTest, LayerCountIsAlwaysMaxLayerPlusOne)
{
  Avogadro::Core::Layer layer;
  EXPECT_EQ(layer.maxLayer() + 1, layer.layerCount());

  layer.addLayer();
  layer.addLayer();

  EXPECT_EQ(layer.maxLayer() + 1, layer.layerCount());
  EXPECT_EQ(static_cast<size_t>(3), layer.layerCount());
}

// ---------------------------------------------------------------------------
// Layer bookkeeping as reached through Molecule's atom operations.
// ---------------------------------------------------------------------------

TEST_F(LayerTest, AddAtomKeepsLayerInLockstepWithAtomCount)
{
  Molecule molecule;
  for (int i = 0; i < 5; ++i)
    molecule.addAtom(6);

  EXPECT_EQ(molecule.layer().atomCount(), molecule.atomCount());
  for (Index i = 0; i < molecule.atomCount(); ++i)
    EXPECT_EQ(static_cast<size_t>(0), molecule.layer().getLayerID(i));
}

TEST_F(LayerTest, RemoveAtomKeepsLayerInLockstepAndMovesLastAtomsLayer)
{
  Molecule molecule;
  buildMultiLayer(molecule); // atomsPerLayer * numLayers atoms, distinct layers
  const size_t lastAtomLayer =
    molecule.layer().getLayerID(molecule.atomCount() - 1);

  molecule.removeAtom(static_cast<Index>(0)); // swap-and-pop moves the last
                                              // atom into slot 0

  EXPECT_EQ(molecule.layer().atomCount(), molecule.atomCount());
  // Core::Layer's swap-and-pop has to track m_atomicNumbers'/m_graph's, or
  // the atom that is now at index 0 would report someone else's layer.
  EXPECT_EQ(lastAtomLayer, molecule.layer().getLayerID(0));
}

TEST_F(LayerTest, SwapAtomSwapsLayerToo)
{
  Molecule molecule;
  buildMultiLayer(molecule);
  const size_t layerAt0 = molecule.layer().getLayerID(0);
  const size_t layerAtLast =
    molecule.layer().getLayerID(molecule.atomCount() - 1);
  ASSERT_NE(layerAt0, layerAtLast);

  molecule.swapAtom(0, molecule.atomCount() - 1);

  EXPECT_EQ(layerAtLast, molecule.layer().getLayerID(0));
  EXPECT_EQ(layerAt0, molecule.layer().getLayerID(molecule.atomCount() - 1));
}

TEST_F(LayerTest, ClearAtomsResetsLayer)
{
  Molecule molecule;
  buildMultiLayer(molecule);

  molecule.clearAtoms();

  EXPECT_EQ(static_cast<Index>(0), molecule.atomCount());
  EXPECT_EQ(static_cast<size_t>(0), molecule.layer().atomCount());
  EXPECT_EQ(static_cast<size_t>(0), molecule.layer().maxLayer());
}

TEST_F(LayerTest, GetAtomsAtLayerReturnsDecreasingOrderForThatLayerOnly)
{
  Molecule molecule;
  buildMultiLayer(molecule); // layer 1 holds atoms {2, 3} (atomsPerLayer = 2)

  const std::list<Index> atLayer1 = molecule.getAtomsAtLayer(1);

  EXPECT_EQ((std::list<Index>{ 3, 2 }), atLayer1);
}

TEST_F(LayerTest, MaxLayerOnEmptyMoleculeIsZero)
{
  Molecule molecule;
  EXPECT_EQ(static_cast<size_t>(0), molecule.layer().maxLayer());
  EXPECT_EQ(static_cast<size_t>(1), molecule.layer().layerCount());
  EXPECT_EQ(static_cast<size_t>(0), molecule.layer().atomCount());
}

// Regression check for the crash pattern in the bug-hunt plan: query a
// deleted atom's former index afterwards. Both calls index m_atomAndLayers,
// so an atom that no longer exists must come back as "not tracked" rather
// than reading past the array or reporting a stale layer.
TEST_F(LayerTest, QueryingADeletedAtomsFormerIndexDoesNotCrash)
{
  Molecule molecule;
  buildMultiLayer(molecule);
  const Index formerLastIndex = molecule.atomCount() - 1;
  const size_t formerLastLayer = molecule.layer().getLayerID(formerLastIndex);

  ASSERT_TRUE(molecule.removeAtom(formerLastIndex));

  // The removed atom was already the last one, so nothing swapped into its
  // slot -- the index is now simply out of range.
  EXPECT_NO_FATAL_FAILURE(molecule.layer().getLayerID(formerLastIndex));
  EXPECT_EQ(Avogadro::MaxIndex, molecule.layer().getLayerID(formerLastIndex));

  // The layer that used to end at this atom must not still claim it.
  EXPECT_NO_FATAL_FAILURE(molecule.getAtomsAtLayer(formerLastLayer));
  for (Index i : molecule.getAtomsAtLayer(formerLastLayer))
    EXPECT_LT(i, molecule.atomCount());
}

// ---------------------------------------------------------------------------
// removeLayer() / addLayer() / setActiveLayer() / swapLayer() bounds and
// bookkeeping. Production code must never crash (no asserts, no exceptions
// -- see CLAUDE.md), so an out-of-range request must be a safe no-op, never
// silent corruption; and removing a layer must keep the per-atom array in
// lockstep with the molecule rather than erasing tracked atoms.
// ---------------------------------------------------------------------------

// removeLayer() renumbers layer ids rather than erasing tracked atoms: an
// atom that was in the removed layer is never removed from the molecule, so
// the array must stay the same length, and the orphaned atom must land in
// the (new) active layer.
TEST_F(LayerTest, RemoveLayerWithAtomsStillInItStaysInLockstep)
{
  Avogadro::Core::Layer layer;
  layer.addAtom(0); // atom 0 -> layer 0
  layer.addAtom(1); // atom 1 -> layer 1
  layer.addAtom(2); // atom 2 -> layer 2
  ASSERT_EQ(static_cast<size_t>(3), layer.atomCount());
  ASSERT_EQ(static_cast<size_t>(0), layer.activeLayer());

  layer.removeLayer(1); // atom 1's layer is removed, but atom 1 itself isn't

  EXPECT_EQ(static_cast<size_t>(3), layer.atomCount());
  EXPECT_EQ(static_cast<size_t>(0), layer.getLayerID(0));
  // Atom 1 was orphaned by the removed layer, so it moved into the (still)
  // active layer, which the removal did not touch here.
  EXPECT_EQ(layer.activeLayer(), layer.getLayerID(1));
  // Atom 2 (old layer 2) should have shifted down to layer 1.
  EXPECT_EQ(static_cast<size_t>(1), layer.getLayerID(2));
}

// Removing the active layer while it holds atoms: the layer below becomes
// active, and the orphaned atoms land there rather than being dropped.
TEST_F(LayerTest, RemovingActiveLayerWithAtomsMovesThemToTheLayerBelow)
{
  Avogadro::Core::Layer layer;
  layer.addAtom(0);        // atom 0 -> layer 0
  layer.addAtom(1);        // atom 1 -> layer 1
  layer.setActiveLayer(1); // layer 1 is active and holds atom 1

  layer.removeLayer(1);

  EXPECT_EQ(static_cast<size_t>(0), layer.maxLayer());
  EXPECT_EQ(static_cast<size_t>(0), layer.activeLayer());
  EXPECT_EQ(static_cast<size_t>(0), layer.getLayerID(1)); // moved to layer 0
}

// Removing a layer *below* the active one shifts the active id down so it
// keeps naming the same layer, instead of leaving it pointing at whatever
// now happens to have that number.
TEST_F(LayerTest, RemovingALayerBelowTheActiveOneDecrementsActiveLayer)
{
  Avogadro::Core::Layer layer;
  layer.addAtom(0); // layer 0
  layer.addAtom(1); // layer 1
  layer.addAtom(2); // layer 2
  layer.setActiveLayer(2);

  layer.removeLayer(0);

  EXPECT_EQ(static_cast<size_t>(1), layer.activeLayer());
  // The atom that used to be in layer 2 -- the active layer -- is still in
  // the active layer under its new, decremented id.
  EXPECT_EQ(layer.activeLayer(), layer.getLayerID(2));
}

// Removing layer 0 while it is active: there is no layer "below" 0, so the
// layer that shifts down into slot 0 becomes active, and atoms orphaned from
// layer 0 move there too.
TEST_F(LayerTest, RemovingLayerZeroWhileActive)
{
  Avogadro::Core::Layer layer;
  layer.addAtom(0); // layer 0, active by default
  layer.addAtom(1); // layer 1

  layer.removeLayer(0);

  EXPECT_EQ(static_cast<size_t>(0), layer.maxLayer());
  EXPECT_EQ(static_cast<size_t>(0), layer.activeLayer());
  EXPECT_EQ(static_cast<size_t>(0), layer.getLayerID(0)); // moved atom
  EXPECT_EQ(static_cast<size_t>(0), layer.getLayerID(1)); // was layer 1
}

// The only layer there is can't be removed: with maxLayer() == 0, removing
// layer 0 must leave the single layer -- and its atoms -- alone.
TEST_F(LayerTest, RemoveLayerWhenMaxLayerIsZeroIsANoOp)
{
  Avogadro::Core::Layer layer;
  layer.addAtom(0);
  layer.addAtom(0); // two atoms, both in the only layer

  layer.removeLayer(0);

  EXPECT_EQ(static_cast<size_t>(0), layer.maxLayer());
  EXPECT_EQ(static_cast<size_t>(2), layer.atomCount());
  EXPECT_EQ(static_cast<size_t>(0), layer.getLayerID(0));
  EXPECT_EQ(static_cast<size_t>(0), layer.getLayerID(1));
}

// A request naming a layer that was never created is a no-op: it must not
// remove whatever the top layer happens to be.
TEST_F(LayerTest, RemoveLayerOnNonexistentLayerIsANoOp)
{
  Avogadro::Core::Layer layer;
  layer.addAtom(0);
  layer.addLayer(); // maxLayer = 1

  layer.removeLayer(5); // layer 5 was never created

  EXPECT_EQ(static_cast<size_t>(1), layer.maxLayer());
}

// setActiveLayer() refuses a layer more than one past maxLayer() instead of
// storing it unchecked; the active layer is left wherever it was.
TEST_F(LayerTest, SetActiveLayerRefusesOutOfRangeValue)
{
  Avogadro::Core::Layer layer;
  layer.addAtom(0); // maxLayer stays 0

  layer.setActiveLayer(999);

  EXPECT_EQ(static_cast<size_t>(0), layer.activeLayer())
    << "an out-of-range active layer should have been refused, not stored";
}

// Inserting a layer at or below the active one shifts the active id up too,
// so it keeps naming the same layer instead of being silently displaced.
TEST_F(LayerTest, AddLayerAtOrBelowActiveShiftsActiveLayer)
{
  Avogadro::Core::Layer layer;
  layer.addAtom(0);
  layer.addAtom(1);
  layer.setActiveLayer(1);

  layer.addLayer(1); // insert a new layer 1; old layer 1 shifts up to 2

  EXPECT_EQ(static_cast<size_t>(2), layer.activeLayer());
  EXPECT_EQ(static_cast<size_t>(2), layer.getLayerID(1)); // atom shifted too
}

// An insertion point more than one past the top layer names a layer that
// could never exist yet, so it is refused rather than leaving a gap.
TEST_F(LayerTest, AddLayerPastMaxLayerPlusOneIsANoOp)
{
  Avogadro::Core::Layer layer;
  layer.addAtom(0); // maxLayer = 0

  layer.addLayer(5);

  EXPECT_EQ(static_cast<size_t>(0), layer.maxLayer());
  EXPECT_EQ(static_cast<size_t>(0), layer.getLayerID(0));
}

// swapLayer() has no way to report failure, so an out-of-range index must be
// a safe no-op rather than reading past the array's end.
TEST_F(LayerTest, SwapLayerOutOfRangeIsANoOp)
{
  Avogadro::Core::Layer layer;
  layer.addAtom(0);
  layer.addAtom(1);

  layer.swapLayer(0, 5); // index 5 does not exist

  EXPECT_EQ(static_cast<size_t>(0), layer.getLayerID(0));
  EXPECT_EQ(static_cast<size_t>(1), layer.getLayerID(1));
}

// removeLayer() no longer erases atoms, so it can never desync the layer
// array from atomCount() -- a swap afterwards must stay in lockstep rather
// than reading past the array's end.
TEST_F(LayerTest, SwapAtomAfterRemoveLayerStaysInLockstep)
{
  Molecule molecule;
  molecule.addAtom(6);
  molecule.addAtom(6);
  molecule.addAtom(6); // 3 atoms, all default to layer 0
  molecule.layer().addLayer();
  molecule.layer().addAtom(1, 1); // atom 1 moved to layer 1

  molecule.layer().removeLayer(1); // atom 1 moves into the active layer (0)
                                   // instead of being erased

  EXPECT_EQ(molecule.layer().atomCount(), molecule.atomCount());

  molecule.swapAtom(0, 2);
  EXPECT_EQ(molecule.layer().atomCount(), molecule.atomCount());
}

// An atom in no layer (MaxIndex, as cjsonformat.cpp assigns) must stay in no
// layer when other layers are renumbered: decrementing the sentinel invents a
// layer id, and incrementing it wraps to layer 0.
TEST_F(LayerTest, RenumberingLayersKeepsTheNoLayerSentinel)
{
  Avogadro::Core::Layer layer;
  layer.addAtom(0);
  layer.addAtom(Avogadro::MaxIndex);
  layer.addAtom(1);
  ASSERT_EQ(static_cast<size_t>(1), layer.maxLayer());

  layer.addLayer(0);
  EXPECT_EQ(Avogadro::MaxIndex, layer.getLayerID(1));
  EXPECT_EQ(static_cast<size_t>(2), layer.getLayerID(2));

  layer.removeLayer(0);
  EXPECT_EQ(Avogadro::MaxIndex, layer.getLayerID(1));
  EXPECT_EQ(static_cast<size_t>(1), layer.getLayerID(2));
}

// An active layer one past the last one does not exist until an atom lands in
// it. Atoms orphaned by removeLayer() landing there must create it, or they
// carry a layer id greater than maxLayer().
TEST_F(LayerTest, RemoveLayerIntoAnUncreatedActiveLayerCreatesIt)
{
  Avogadro::Core::Layer layer;
  layer.addAtom(2); // atom 0; creates layers 0-2
  layer.addAtom(0); // atom 1
  layer.setActiveLayer(layer.maxLayer() + 1);

  layer.removeLayer(0); // orphans atom 1 into the uncreated active layer

  EXPECT_EQ(static_cast<size_t>(1), layer.getLayerID(0));
  EXPECT_EQ(layer.activeLayer(), layer.getLayerID(1));
  EXPECT_LE(layer.getLayerID(1), layer.maxLayer());
  EXPECT_EQ(static_cast<size_t>(2), layer.maxLayer());
}
