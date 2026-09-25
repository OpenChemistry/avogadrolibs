/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <fuzzer/FuzzedDataProvider.h>

#include <avogadro/core/layer.h>
#include <avogadro/core/layermanager.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/moleculeinfo.h>

#include "fuzzhelpers.h"

#include <array>
#include <cstdio>
#include <cstdlib>
#include <list>
#include <memory>

using namespace Avogadro;
using namespace Avogadro::Core;
using Avogadro::FuzzHelpers::consumeAtomicNumber;

namespace {

// LayerManager::setActiveMolecule() is protected -- it is meant to be called
// by the GUI layer, not by arbitrary code -- but the historical crashes this
// target exists to catch are exactly about that active-molecule cursor
// outliving the molecule it points at, so the fuzzer needs to reach it too.
// tests/core/layertest.cpp reaches it the same way.
struct LayerManagerAccess : public LayerManager
{
  using LayerManager::setActiveMolecule;
};

constexpr size_t kPoolSize = 3;

// Layer ids are fuzzed over a range that deliberately exceeds maxLayer() + 1
// (0..maxLayer()+3), plus occasionally a value far out of range and
// occasionally MaxIndex, so the out-of-range guards in setActiveLayer(),
// addLayer() and removeLayer() are exercised, not just the in-range path.
size_t fuzzedLayerId(FuzzedDataProvider& fdp, size_t maxLayer)
{
  const uint8_t choice = fdp.ConsumeIntegral<uint8_t>() % 8;
  if (choice == 0)
    return MaxIndex;
  if (choice == 1) {
    // Far past anything addLayer()/removeLayer()/setActiveLayer() could
    // have created, without risking overflow in maxLayer + 3 elsewhere.
    return maxLayer + 1000000007ULL;
  }
  return fdp.ConsumeIntegralInRange<size_t>(0, maxLayer + 3);
}

// The oracle: every live molecule must keep its Layer in lockstep with its
// atom list and its layer bookkeeping internally consistent. Kept O(atoms)
// so exec/s stays high (fuzzhelpers.h caps atom count at kMaxAtoms).
void checkMolecule(const Molecule& mol, const char* where)
{
  const Layer& layer = mol.layer();

  if (layer.atomCount() != mol.atomCount()) {
    std::fprintf(stderr,
                 "oracle violation (%s): layer.atomCount()=%zu != "
                 "molecule.atomCount()=%zu\n",
                 where, layer.atomCount(),
                 static_cast<size_t>(mol.atomCount()));
    std::abort();
  }

  // MaxIndex is a legitimate, documented value here -- it is getLayerID()'s
  // "this atom is in no layer" sentinel (see layer.h/layer.cpp), and real
  // code stores it deliberately: cjsonformat.cpp does
  // `layer.addAtom(MaxIndex, i)` for an atom a CJSON document did not
  // assign to any layer. Only an in-range-but-wrong id is a bug.
  const size_t maxLayer = layer.maxLayer();
  for (Index i = 0; i < mol.atomCount(); ++i) {
    const size_t id = layer.getLayerID(i);
    if (id != MaxIndex && id > maxLayer) {
      std::fprintf(stderr,
                   "oracle violation (%s): atom %zu has layer id %zu > "
                   "maxLayer %zu\n",
                   where, static_cast<size_t>(i), id, maxLayer);
      std::abort();
    }
  }

  if (layer.activeLayer() > maxLayer + 1) {
    std::fprintf(stderr,
                 "oracle violation (%s): activeLayer()=%zu > maxLayer()+1="
                 "%zu\n",
                 where, layer.activeLayer(), maxLayer + 1);
    std::abort();
  }

  if (layer.layerCount() != maxLayer + 1) {
    std::fprintf(stderr,
                 "oracle violation (%s): layerCount()=%zu != maxLayer()+1="
                 "%zu\n",
                 where, layer.layerCount(), maxLayer + 1);
    std::abort();
  }
}

} // namespace

// Fuzz Core::Layer / Core::LayerManager / Core::MoleculeInfo, mixed with the
// Molecule atom operations real callers interleave them with, plus the
// lifetime operations (copy/move/destroy) that have historically caused
// use-after-frees in the layer state.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size)
{
  FuzzedDataProvider fdp(Data, Size);

  // No active molecule at the start of this run. A previous run's molecules
  // are already gone (the pool is a local variable in that call), so the
  // weak_ptr would already be expired -- this just makes that explicit.
  LayerManagerAccess::setActiveMolecule(nullptr);

  std::array<std::unique_ptr<Molecule>, kPoolSize> pool;
  for (auto& slot : pool)
    slot = std::make_unique<Molecule>(FuzzHelpers::buildMolecule(fdp));

  // A moved-from Molecule is dead until it is reassigned or destroyed --
  // that is the normal C++ rule (a moved-from object is only guaranteed to
  // be in a "valid but unspecified state"), and it is the rule the
  // maintainer chose for this harness. movedFrom[i] tracks which pool
  // slots are currently in that state: set on the source of a
  // move-construct or move-assign, cleared when a slot is copy-assigned
  // into, move-assigned into, or destroyed and recreated. While a slot is
  // moved-from, every op below skips it except those two "assigned into"
  // cases and destroy/recreate -- it is never read, never used as the
  // source of a copy or move, never pointed at by setActiveMolecule(), and
  // never checked by the oracle.
  //
  // This is deliberately not the same thing as the atomCount()/layer
  // desync a moved-from Molecule can be caught in today: the move
  // constructor and move-assignment operator move m_graph (a real
  // std::move) but only copy-share m_atomicNumbers/m_bondOrders, because
  // Core::Array has no move constructor -- so a moved-from molecule can be
  // internally inconsistent rather than simply empty. That is a known,
  // separately tracked bug (see the fuzz_core_layer soak report); it is
  // not what this flag is guarding against, and fixing that bug does not
  // make this flag unnecessary -- do not remove this tracking on the
  // assumption that bug is the only reason for it.
  std::array<bool, kPoolSize> movedFrom{};

  const size_t steps = fdp.ConsumeIntegralInRange<size_t>(1, 128);
  for (size_t step = 0; step < steps; ++step) {
    const size_t a = fdp.ConsumeIntegral<uint8_t>() % kPoolSize;
    const size_t b = fdp.ConsumeIntegral<uint8_t>() % kPoolSize;

    switch (fdp.ConsumeIntegral<uint8_t>() % 24) {
      case 0: { // add atom
        auto& m = pool[a];
        if (m && !movedFrom[a] && m->atomCount() < FuzzHelpers::kMaxAtoms)
          m->addAtom(consumeAtomicNumber(fdp));
        break;
      }
      case 1: { // remove atom
        auto& m = pool[a];
        if (m && !movedFrom[a] && m->atomCount() > 0) {
          Index idx = fdp.ConsumeIntegral<uint8_t>() % m->atomCount();
          m->removeAtom(idx);
        }
        break;
      }
      case 2: { // swap atom
        auto& m = pool[a];
        if (m && !movedFrom[a] && m->atomCount() >= 2) {
          Index i1 = fdp.ConsumeIntegral<uint8_t>() % m->atomCount();
          Index i2 = fdp.ConsumeIntegral<uint8_t>() % m->atomCount();
          m->swapAtom(i1, i2);
        }
        break;
      }
      case 3: { // clear atoms
        if (pool[a] && !movedFrom[a])
          pool[a]->clearAtoms();
        break;
      }
      case 4: { // add bond (occasional)
        auto& m = pool[a];
        if (m && !movedFrom[a] && m->atomCount() >= 2 &&
            m->bondCount() < FuzzHelpers::kMaxBonds) {
          Index i1 = fdp.ConsumeIntegral<uint8_t>() % m->atomCount();
          Index i2 = fdp.ConsumeIntegral<uint8_t>() % m->atomCount();
          if (i1 != i2) {
            unsigned char order = static_cast<unsigned char>(
              1 + (fdp.ConsumeIntegral<uint8_t>() % 3));
            m->addBond(i1, i2, order);
          }
        }
        break;
      }
      case 5: { // remove bond (occasional)
        auto& m = pool[a];
        if (m && !movedFrom[a] && m->bondCount() > 0) {
          Index idx = fdp.ConsumeIntegral<uint8_t>() % m->bondCount();
          m->removeBond(idx);
        }
        break;
      }
      case 6: { // layer().addLayer() -- grows maxLayer without shifting
        if (pool[a] && !movedFrom[a])
          pool[a]->layer().addLayer();
        break;
      }
      case 7: { // layer().addLayer(n)
        if (pool[a] && !movedFrom[a]) {
          Layer& layer = pool[a]->layer();
          layer.addLayer(fuzzedLayerId(fdp, layer.maxLayer()));
        }
        break;
      }
      case 8: { // layer().removeLayer(n)
        if (pool[a] && !movedFrom[a]) {
          Layer& layer = pool[a]->layer();
          layer.removeLayer(fuzzedLayerId(fdp, layer.maxLayer()));
        }
        break;
      }
      case 9: { // layer().setActiveLayer(n)
        if (pool[a] && !movedFrom[a]) {
          Layer& layer = pool[a]->layer();
          layer.setActiveLayer(fuzzedLayerId(fdp, layer.maxLayer()));
        }
        break;
      }
      case 10: { // layer().addAtom(layer, existingAtom) -- move an atom
        auto& m = pool[a];
        if (m && !movedFrom[a] && m->atomCount() > 0) {
          Index atomIdx = fdp.ConsumeIntegral<uint8_t>() % m->atomCount();
          Layer& layer = m->layer();
          layer.addAtom(fuzzedLayerId(fdp, layer.maxLayer()), atomIdx);
        }
        break;
      }
      case 11: { // layer().swapLayer(a, b), atom indices < atomCount()
        auto& m = pool[a];
        if (m && !movedFrom[a] && m->atomCount() > 0) {
          Index i1 = fdp.ConsumeIntegral<uint8_t>() % m->atomCount();
          Index i2 = fdp.ConsumeIntegral<uint8_t>() % m->atomCount();
          m->layer().swapLayer(i1, i2);
        }
        break;
      }
      case 12: { // getAtomsAtLayer(n) -- every returned atom must be live
        auto& m = pool[a];
        if (m && !movedFrom[a]) {
          Layer& layer = m->layer();
          const size_t queryLayer = fuzzedLayerId(fdp, layer.maxLayer());
          std::list<Index> atoms = m->getAtomsAtLayer(queryLayer);
          for (Index idx : atoms) {
            if (idx >= m->atomCount()) {
              std::fprintf(stderr,
                           "oracle violation: getAtomsAtLayer(%zu) "
                           "returned atom %zu >= atomCount() %zu\n",
                           queryLayer, static_cast<size_t>(idx),
                           static_cast<size_t>(m->atomCount()));
              std::abort();
            }
          }
        }
        break;
      }
      case 13: { // getLayerID(atom), occasionally past atomCount()
        auto& m = pool[a];
        if (m && !movedFrom[a]) {
          const size_t bound = m->atomCount() + 4;
          Index atomIdx = fdp.ConsumeIntegral<uint8_t>() % bound;
          m->layer().getLayerID(atomIdx);
        }
        break;
      }
      case 14: { // grow visible/locked -- mimics AddLayerCommand::redo()
        if (pool[a] && !movedFrom[a]) {
          auto info = pool[a]->layerInfo();
          if (fdp.ConsumeBool())
            info->visible.push_back(fdp.ConsumeBool());
          else
            info->locked.push_back(fdp.ConsumeBool());
        }
        break;
      }
      case 15: { // shrink visible/locked -- mimics RemoveLayerCommand::redo()
        if (pool[a] && !movedFrom[a]) {
          auto info = pool[a]->layerInfo();
          if (fdp.ConsumeBool()) {
            if (!info->visible.empty()) {
              size_t idx =
                fdp.ConsumeIntegral<uint8_t>() % info->visible.size();
              info->visible.erase(info->visible.begin() +
                                  static_cast<std::ptrdiff_t>(idx));
            }
          } else {
            if (!info->locked.empty()) {
              size_t idx = fdp.ConsumeIntegral<uint8_t>() % info->locked.size();
              info->locked.erase(info->locked.begin() +
                                 static_cast<std::ptrdiff_t>(idx));
            }
          }
        }
        break;
      }
      case 16: { // copy-construct: replace slot b with a copy of slot a
        // A moved-from slot is never a copy/move source; the destination
        // slot is a brand-new object either way, so it comes back live.
        if (pool[a] && !movedFrom[a]) {
          pool[b] = std::make_unique<Molecule>(*pool[a]);
          movedFrom[b] = false;
        }
        break;
      }
      case 17: { // copy-assign: a moved-from slot may be the target
        if (pool[a] && pool[b] && !movedFrom[b]) {
          *pool[a] = *pool[b];
          movedFrom[a] = false;
        }
        break;
      }
      case 18: { // move-construct: replace slot b, leave a moved-from
        if (pool[a] && !movedFrom[a]) {
          // a == b: the source is read by the move ctor and then
          // immediately destroyed when the new unique_ptr replaces it, so
          // the slot ends up live (the moved-from intermediate never
          // survives to be observed).
          const bool selfReplace = (a == b);
          pool[b] = std::make_unique<Molecule>(std::move(*pool[a]));
          movedFrom[b] = false;
          if (!selfReplace)
            movedFrom[a] = true;
        }
        break;
      }
      case 19: { // move-assign: a moved-from slot may be the target
        if (pool[a] && pool[b] && !movedFrom[b]) {
          // operator=(Molecule&&) guards `this != &other` (see
          // molecule.cpp), so a == b is a verified no-op: the slot stays
          // exactly as live as it already was.
          *pool[a] = std::move(*pool[b]);
          if (a != b) {
            movedFrom[a] = false;
            movedFrom[b] = true;
          }
        }
        break;
      }
      case 20: { // self-assignment, copy or move
        // Both operator=(const Molecule&) and operator=(Molecule&&) guard
        // `this != &other`, so this is always a verified no-op -- a
        // moved-from slot would be both source and target of the same
        // no-op, which is the one case this harness does not need to
        // bother distinguishing, so it is simply excluded like any other
        // use of a moved-from slot as a source.
        if (pool[a] && !movedFrom[a]) {
          if (fdp.ConsumeBool())
            *pool[a] = *pool[a];
          else
            *pool[a] = std::move(*pool[a]);
        }
        break;
      }
      case 21: { // destroy or recreate a pool slot
        if (fdp.ConsumeBool())
          pool[a].reset();
        else
          pool[a] = std::make_unique<Molecule>(FuzzHelpers::buildMolecule(fdp));
        movedFrom[a] = false;
        break;
      }
      case 22: { // LayerManager's active-molecule cursor
        // Never point the cursor at a moved-from molecule -- it is dead as
        // far as this harness is concerned, so skip the whole op rather
        // than exercise setActiveMolecule() on it.
        if (pool[a] && movedFrom[a])
          break;

        LayerManagerAccess::setActiveMolecule(pool[a] ? pool[a].get()
                                                      : nullptr);
        // Sometimes destroy the molecule right after pointing the cursor at
        // it -- the historical bug class: the cursor must not dangle.
        if (pool[a] && fdp.ConsumeBool()) {
          pool[a].reset();
          movedFrom[a] = false;
        }

        const size_t activeCount = LayerManager::layerCount();
        Layer& activeLayer = LayerManager::getMoleculeLayer();
        auto activeInfo = LayerManager::getMoleculeInfo();
        (void)activeLayer;
        if (pool[a]) {
          if (activeCount != pool[a]->layer().maxLayer() + 1) {
            std::fprintf(stderr,
                         "oracle violation: LayerManager::layerCount()=%zu "
                         "!= active molecule's maxLayer()+1=%zu\n",
                         activeCount, pool[a]->layer().maxLayer() + 1);
            std::abort();
          }
        } else if (activeCount != 0 || activeInfo != nullptr) {
          std::fprintf(stderr,
                       "oracle violation: a destroyed active molecule "
                       "still resolves (layerCount()=%zu)\n",
                       activeCount);
          std::abort();
        }
        break;
      }
      case 23: { // LayerManager lookup by explicit molecule pointer
        // A moved-from slot is not one of the two ops allowed on it, so
        // treat it the same as a null slot would be treated: skip.
        if (pool[b] && movedFrom[b])
          break;

        Molecule* mptr = pool[b] ? pool[b].get() : nullptr;
        Layer& layer = LayerManager::getMoleculeLayer(mptr);
        auto info = LayerManager::getMoleculeInfo(mptr);
        (void)layer;
        if (mptr && info == nullptr) {
          std::fprintf(stderr,
                       "oracle violation: getMoleculeInfo(mol) returned "
                       "null for a live molecule\n");
          std::abort();
        }
        if (!mptr && info != nullptr) {
          std::fprintf(stderr, "oracle violation: getMoleculeInfo(nullptr) "
                               "returned non-null\n");
          std::abort();
        }
        break;
      }
      default:
        break;
    }

    for (size_t i = 0; i < kPoolSize; ++i)
      if (pool[i] && !movedFrom[i])
        checkMolecule(*pool[i], "after step");
  }

  return 0;
}
