/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <fuzzer/FuzzedDataProvider.h>

#include <QtGui/QGuiApplication>

#include <avogadro/core/array.h>
#include <avogadro/core/avogadrocore.h>
#include <avogadro/core/layer.h>
#include <avogadro/core/layermanager.h>
#include <avogadro/core/moleculeinfo.h>
#include <avogadro/qtgui/layermodel.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/pluginlayermanager.h>
#include <avogadro/qtgui/rwmolecule.h>

#include "fuzzhelpers.h"

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

using namespace Avogadro;
using namespace Avogadro::QtGui;
using Avogadro::Core::Array;
using Avogadro::Core::LayerData;
using Avogadro::Core::LayerManager;
using Avogadro::Core::MoleculeInfo;
using Avogadro::FuzzHelpers::consumeAtomicNumber;
using Avogadro::FuzzHelpers::consumeVector3;

namespace {

// LayerModel loads icons in its constructor, which needs a QGuiApplication
// (not just a QCoreApplication -- see tests/qtgui/layermodeltest.cpp's own
// ensureApp(), which this mirrors). Offscreen so this runs headless.
QGuiApplication* ensureApp()
{
  static int argc = 1;
  static char arg0[] = "fuzz";
  static char* argv[] = { arg0, nullptr };
  if (qEnvironmentVariableIsEmpty("QT_QPA_PLATFORM"))
    qputenv("QT_QPA_PLATFORM", "offscreen");
  static QGuiApplication app(argc, argv);
  return &app;
}

constexpr size_t kMaxSteps = 128;

// A row index for LayerModel::removeItem(), fuzzed past the end the same way
// tests/core/fuzz-layer.cpp fuzzes layer ids for Core::Layer: removeItem()
// documents that row >= names.size() (which includes the synthetic "+" row)
// is simply ignored, so this exercises that guard instead of assuming it.
size_t fuzzedRow(FuzzedDataProvider& fdp, size_t bound)
{
  const uint8_t choice = fdp.ConsumeIntegral<uint8_t>() % 8;
  if (choice == 0)
    return bound + 1000000007ULL; // far past anything real
  return fdp.ConsumeIntegralInRange<size_t>(0, bound + 3);
}

void abortWith(const char* where, const std::string& detail)
{
  std::fprintf(stderr, "oracle violation (%s): %s\n", where, detail.c_str());
  std::abort();
}

// Per-step oracle. layer().atomCount() tracks atomCount(), every atom's
// layer id is in range or the documented MaxIndex "no layer" sentinel,
// activeLayer() never points more than one past maxLayer(), and visible()/
// locked() track layerCount() exactly -- i.e. every layer has an entry, even
// though (see the comment on Snapshot below) which way that entry is set is
// not something undo restores.
//
// The size check is NOT weakened here, even though it easily could be:
// RWMolecule::setLayer() ultimately calls Core::Layer::addAtom(layer, atom),
// which grows m_maxLayer to match whatever layer id it is given (see
// layer.cpp) without touching MoleculeInfo::visible/locked at all -- those
// are only grown/shrunk in lockstep by AddLayerCommand/RemoveLayerCommand.
// Fuzzing setLayer() with an out-of-range layer id would desync
// visible/locked's *size* from layerCount() exactly the way this comment
// predicts, AND it would make the undo round-trip check below fail for a
// reason that is not a bug: addAtom() only ever grows m_maxLayer, so
// undoing such a setLayer() (which calls setLayer() again with the
// pre-image layer id, itself in-range) never shrinks m_maxLayer back down.
// That is Core::Layer's documented one-way ratchet, not a defect. So this
// harness's setLayer op (case 6 below) is deliberately restricted to layer
// ids already in [0, maxLayer()], plus MaxIndex, which never grows
// maxLayer -- keeping this size invariant, and the undo round trip, both
// meaningful without weakening them.
void checkMolecule(const Molecule& mol, const char* where)
{
  const Core::Layer& layer = mol.layer();
  if (layer.atomCount() != mol.atomCount())
    abortWith(where, "layer.atomCount() != molecule.atomCount()");

  const size_t maxLayer = layer.maxLayer();
  for (Index i = 0; i < mol.atomCount(); ++i) {
    const size_t id = layer.getLayerID(i);
    if (id != MaxIndex && id > maxLayer)
      abortWith(where, "atom layer id out of range");
  }

  if (layer.activeLayer() > maxLayer + 1)
    abortWith(where, "activeLayer() > maxLayer()+1");

  auto info = LayerManager::getMoleculeInfo(&mol);
  const size_t layerCount = maxLayer + 1;
  if (info->visible.size() != layerCount)
    abortWith(where, "visible.size() != layerCount()");
  if (info->locked.size() != layerCount)
    abortWith(where, "locked.size() != layerCount()");
}

// What undoing the whole stack must restore: each atom's layer and element,
// the atom count, and the active and max layer ids.
//
// Visible/locked values and per-layer plugin enable are left out on purpose:
// toggling them is view state and never goes on the undo stack, like
// switching the active conformer. Only their lengths follow undo, through
// layer add/remove, and checkMolecule() checks those at every step and at
// both ends of the round trip.
struct Snapshot
{
  std::vector<size_t> atomLayers;
  std::vector<unsigned char> atomElements;
  size_t maxLayer = 0;
  size_t activeLayer = 0;

  bool operator==(const Snapshot& other) const
  {
    return atomLayers == other.atomLayers &&
           atomElements == other.atomElements && maxLayer == other.maxLayer &&
           activeLayer == other.activeLayer;
  }
};

Snapshot captureSnapshot(const Molecule& mol)
{
  Snapshot snap;
  auto info = LayerManager::getMoleculeInfo(&mol);
  const Index n = mol.atomCount();
  for (Index i = 0; i < n; ++i) {
    snap.atomLayers.push_back(info->layer.getLayerID(i));
    snap.atomElements.push_back(mol.atomicNumber(i));
  }
  snap.maxLayer = info->layer.maxLayer();
  snap.activeLayer = info->layer.activeLayer();
  return snap;
}

void checkUndoRoundTrip(RWMolecule* rw, const Molecule& mol,
                        const Snapshot& initial, const char* moleculeName)
{
  // The step loop can end partway down the stack (it undoes and jumps too),
  // so move to the top before capturing the state redo must reproduce.
  const int count = rw->undoStack().count();
  rw->undoStack().setIndex(count);
  const Snapshot final = captureSnapshot(mol);

  rw->undoStack().setIndex(0);
  if (!(captureSnapshot(mol) == initial)) {
    abortWith("undo round trip",
              std::string("setIndex(0) did not reproduce the initial state "
                          "for ") +
                moleculeName);
  }
  checkMolecule(mol, "after undo round trip setIndex(0)");

  rw->undoStack().setIndex(count);
  if (!(captureSnapshot(mol) == final)) {
    abortWith(
      "undo round trip",
      std::string("setIndex(count()) did not reproduce the pre-undo state "
                  "for ") +
        moleculeName);
  }
  checkMolecule(mol, "after undo round trip setIndex(count())");
}

} // namespace

// Fuzz QtGui::LayerModel / RWLayerManager / PluginLayerManager -- the
// undoable layer-editing path a real Avogadro session drives from the
// Layers dock and from ScenePlugins -- mixed with the RWMolecule atom edits
// real callers interleave them with.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size)
{
  ensureApp();

  FuzzedDataProvider fdp(Data, Size);

  Molecule molA = FuzzHelpers::buildMolecule(fdp);
  Molecule molB = FuzzHelpers::buildMolecule(fdp);
  RWMolecule* rwA = molA.undoMolecule();
  RWMolecule* rwB = molB.undoMolecule();

  Molecule* mols[2] = { &molA, &molB };
  RWMolecule* rws[2] = { rwA, rwB };
  size_t activeIdx = 0;

  LayerModel model;
  model.addMolecule(mols[activeIdx]); // the way the GUI activates a molecule

  PluginLayerManager pluginA("FuzzPluginA");
  PluginLayerManager pluginB("FuzzPluginB");

  const Snapshot initial[2] = { captureSnapshot(molA), captureSnapshot(molB) };

  const size_t steps = fdp.ConsumeIntegralInRange<size_t>(1, kMaxSteps);
  for (size_t step = 0; step < steps; ++step) {
    Molecule& mol = *mols[activeIdx];
    RWMolecule* rw = rws[activeIdx];

    switch (fdp.ConsumeIntegral<uint8_t>() % 20) {
      case 0: { // add atom
        if (rw->atomCount() < FuzzHelpers::kMaxAtoms) {
          unsigned char z = consumeAtomicNumber(fdp);
          if (fdp.ConsumeBool())
            rw->addAtom(z, consumeVector3(fdp));
          else
            rw->addAtom(z, fdp.ConsumeBool());
        }
        break;
      }
      case 1: { // remove atom
        if (rw->atomCount() > 0) {
          Index idx = fdp.ConsumeIntegral<uint8_t>() % rw->atomCount();
          rw->removeAtom(idx);
        }
        break;
      }
      case 2: { // swap atoms -- RWMolecule has no swapAtom(); reorderAtoms()
                // is its undo-tracked equivalent (Molecule::swapAtom() is a
                // direct, non-undo mutation that would desync the undo
                // stack from reality and break the round-trip oracle).
        Index count = rw->atomCount();
        if (count >= 2) {
          Array<Index> order(count);
          for (Index i = 0; i < count; ++i)
            order[i] = i;
          Index i1 = fdp.ConsumeIntegral<uint8_t>() % count;
          Index i2 = fdp.ConsumeIntegral<uint8_t>() % count;
          std::swap(order[i1], order[i2]);
          rw->reorderAtoms(order);
        }
        break;
      }
      case 3: { // add bond
        if (rw->atomCount() >= 2 && rw->bondCount() < FuzzHelpers::kMaxBonds) {
          Index a = fdp.ConsumeIntegral<uint8_t>() % rw->atomCount();
          Index b = fdp.ConsumeIntegral<uint8_t>() % rw->atomCount();
          if (a != b) {
            unsigned char order = static_cast<unsigned char>(
              1 + (fdp.ConsumeIntegral<uint8_t>() % 3));
            rw->addBond(a, b, order);
          }
        }
        break;
      }
      case 4: { // remove bond
        if (rw->bondCount() > 0) {
          Index idx = fdp.ConsumeIntegral<uint8_t>() % rw->bondCount();
          rw->removeBond(idx);
        }
        break;
      }
      case 5: { // set selection
        if (rw->atomCount() > 0) {
          Index idx = fdp.ConsumeIntegral<uint8_t>() % rw->atomCount();
          rw->setAtomSelected(idx, fdp.ConsumeBool());
        }
        break;
      }
      case 6: { // setLayer -- restricted to already-valid layer ids (plus
                // MaxIndex); see the long comment above checkMolecule() for
                // why an out-of-range id is deliberately excluded here.
        if (rw->atomCount() > 0) {
          Index idx = fdp.ConsumeIntegral<uint8_t>() % rw->atomCount();
          const size_t maxLayer = mol.layer().maxLayer();
          size_t target = fdp.ConsumeBool()
                            ? MaxIndex
                            : fdp.ConsumeIntegralInRange<size_t>(0, maxLayer);
          rw->setLayer(idx, target);
        }
        break;
      }
      case 7: { // LayerModel::addLayer
        model.addLayer(rw);
        break;
      }
      case 8: { // LayerModel::removeItem -- row fuzzed past the end
        model.updateRows();
        size_t row = fuzzedRow(fdp, model.items());
        model.removeItem(static_cast<int>(row), rw);
        break;
      }
      case 9: { // LayerModel::setActiveLayer -- row fuzzed past the end.
                // setActiveLayer() used to guard its row with assert() only,
                // which a release build never checked; it now ignores
                // row < 0 or row >= names.size() (layermodel.cpp), so this
                // is safe to fuzz the same way removeItem() is.
        model.updateRows();
        size_t row = fuzzedRow(fdp, model.items());
        model.setActiveLayer(static_cast<int>(row), rw);
        break;
      }
      case 10: { // LayerModel::flipVisible -- row fuzzed past the end.
                 // flipVisible()/flipLocked() used to index names[row] with
                 // no check at all; both now ignore row >= names.size()
                 // (layermodel.cpp), so this is safe to fuzz past the end
                 // too.
        model.updateRows();
        size_t row = fuzzedRow(fdp, model.items());
        model.flipVisible(row);
        break;
      }
      case 11: { // LayerModel::flipLocked -- same reasoning as case 10.
        model.updateRows();
        size_t row = fuzzedRow(fdp, model.items());
        model.flipLocked(row);
        break;
      }
      case 12: { // PluginLayerManager::setEnabled
        PluginLayerManager& plugin = fdp.ConsumeBool() ? pluginA : pluginB;
        plugin.setEnabled(fdp.ConsumeBool());
        break;
      }
      case 13: { // PluginLayerManager queries
        PluginLayerManager& plugin = fdp.ConsumeBool() ? pluginA : pluginB;
        (void)plugin.isEnabled();
        (void)plugin.isActiveLayerEnabled();
        (void)plugin.activeLayerLocked();
        (void)plugin.layerCount();
        if (rw->atomCount() > 0) {
          Index idx1 = fdp.ConsumeIntegral<uint8_t>() % rw->atomCount();
          Index idx2 = fdp.ConsumeIntegral<uint8_t>() % rw->atomCount();
          (void)plugin.atomEnabled(idx1);
          (void)plugin.atomLocked(idx1);
          (void)plugin.getLayerID(idx1);
          (void)plugin.bondEnabled(idx1, idx2);
        }
        break;
      }
      case 14: { // PluginLayerManager::getSetting<LayerData>() -- grows the
                 // per-plugin settings array to activeLayer()+1 lazily.
        PluginLayerManager& plugin = fdp.ConsumeBool() ? pluginA : pluginB;
        LayerData* setting = plugin.getSetting<LayerData>();
        (void)setting;
        break;
      }
      case 15: { // undo
        rw->undoStack().undo();
        break;
      }
      case 16: { // redo
        rw->undoStack().redo();
        break;
      }
      case 17: { // setIndex(random)
        const int count = rw->undoStack().count();
        if (count > 0) {
          int idx = fdp.ConsumeIntegralInRange<int>(0, count);
          rw->undoStack().setIndex(idx);
        }
        break;
      }
      case 18: { // LayerModel::updateRows()
        model.updateRows();
        break;
      }
      case 19: { // switch the model to the other molecule and back
        activeIdx = 1 - activeIdx;
        model.addMolecule(mols[activeIdx]);
        break;
      }
      default:
        break;
    }

    checkMolecule(molA, "after step");
    checkMolecule(molB, "after step");
  }

  checkUndoRoundTrip(rwA, molA, initial[0], "molA");
  checkUndoRoundTrip(rwB, molB, initial[1], "molB");

  return 0;
}
