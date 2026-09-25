/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "layer.h"

namespace Avogadro::Core {

void Layer::addAtom(size_t layer)
{
  addAtom(layer, m_atomAndLayers.size());
}

void Layer::addAtom(size_t layer, Index atom)
{
  // Layer ids are consecutive, so asking for a layer past the last one grows
  // the range rather than being an error: the atom lands in the layer it
  // asked for instead of carrying an id that no layer has. Per-layer state
  // kept alongside this class -- MoleculeInfo's visible, locked, enable and
  // settings -- is grown lazily and every reader falls back to the default
  // for a layer it has not been told about, so nothing else needs telling.
  //
  // MaxIndex is getLayerID()'s "this atom is in no layer" answer and the fill
  // value for the gap below, not a layer id. It must never become m_maxLayer,
  // which would wrap layerCount() to zero.
  if (layer != MaxIndex && layer > m_maxLayer)
    m_maxLayer = layer;

  if (atom == m_atomAndLayers.size()) {
    m_atomAndLayers.push_back(layer);
  } else if (atom > m_atomAndLayers.size()) {
    // m_atomAndLayers is indexed by atom, so it has to grow to hold this
    // atom. Resizing to layer + 1 left the write below past the end of the
    // array whenever the layer id was smaller than the atom index -- which
    // it is for every atom beyond the first in the default single layer.
    m_atomAndLayers.resize(atom + 1, MaxIndex);
    m_atomAndLayers[atom] = layer;
  } else {
    m_atomAndLayers[atom] = layer;
  }
}

void Layer::addAtomToActiveLayer(Index atom)
{
  addAtom(m_activeLayer, atom);
}

void Layer::setActiveLayer(size_t layer)
{
  // A layer one past the last one is allowed: it lets a caller point the
  // active layer at a not-yet-existing layer that will be created lazily
  // the moment an atom is actually added to it (see addAtom()'s comment).
  // Anything further out names a layer that could never be reached that
  // way, so it is refused rather than stored.
  if (layer > m_maxLayer + 1)
    return;
  m_activeLayer = layer;
}

void Layer::removeAtom(Index atom)
{
  m_atomAndLayers.swapAndPop(atom);
}

void Layer::addLayer()
{
  ++m_maxLayer;
}

void Layer::addLayer(size_t layer)
{
  if (layer > m_maxLayer + 1)
    return;
  // MaxIndex marks an atom in no layer; it is not a layer id to renumber,
  // and incrementing it would wrap to layer 0.
  for (auto& atomLayer : m_atomAndLayers) {
    if (atomLayer != MaxIndex && atomLayer >= layer) {
      ++atomLayer;
    }
  }
  // The active layer keeps pointing at the same layer it did before the
  // insertion, so it has to shift up too when the insertion point is at or
  // below it.
  if (m_activeLayer >= layer)
    ++m_activeLayer;
  ++m_maxLayer;
}

size_t Layer::getLayerID(Index atom) const
{
  if (atom >= m_atomAndLayers.size()) {
    return MaxIndex;
  } else {
    return m_atomAndLayers[atom];
  }
}

void Layer::clear()
{
  m_atomAndLayers.clear();
  m_activeLayer = m_maxLayer = 0;
}

void Layer::resize(size_t count)
{
  if (count == m_atomAndLayers.size())
    return;
  if (count < m_atomAndLayers.size()) {
    m_atomAndLayers.resize(count);
  } else {
    // Default new atoms to the active layer
    m_atomAndLayers.resize(count, m_activeLayer);
  }
}

size_t Layer::activeLayer() const
{
  return m_activeLayer;
}

size_t Layer::maxLayer() const
{
  return m_maxLayer;
}

size_t Layer::atomCount() const
{
  return m_atomAndLayers.size();
}

void Layer::removeLayer(size_t layer)
{
  // A layer id that was never created, or the only layer there is, leaves
  // everything alone rather than removing whatever the top layer happens to
  // be.
  if (layer > m_maxLayer || m_maxLayer == 0)
    return;

  // Work out the new active layer first, using ids as they stand before the
  // renumbering below. Layers above the removed one keep the same meaning
  // once shifted down, so an active layer above it simply moves down with
  // it; an active layer at the removed one falls to the layer below (layer 0
  // if there is no layer below).
  if (m_activeLayer > layer) {
    --m_activeLayer;
  } else if (m_activeLayer == layer) {
    m_activeLayer = (layer == 0) ? 0 : layer - 1;
  }

  // Atoms are never erased here: an atom that was in the removed layer moves
  // into the (now current) active layer instead, so the per-atom array
  // length never changes. Atoms above the removed layer shift down by one.
  // m_activeLayer already holds the post-renumbering id, so atoms landing on
  // it must not be decremented again.
  bool orphaned = false;
  for (auto& atomLayer : m_atomAndLayers) {
    if (atomLayer == layer) {
      atomLayer = m_activeLayer;
      orphaned = true;
    } else if (atomLayer > layer && atomLayer != MaxIndex) {
      --atomLayer;
    }
  }

  --m_maxLayer;
  // The active layer may be one past the last layer, waiting to be created
  // by the first atom added to it. Atoms moved into it here create it, just
  // as addAtom() would.
  if (orphaned && m_activeLayer > m_maxLayer)
    m_maxLayer = m_activeLayer;
}

void Layer::swapLayer(Index a, Index b)
{
  if (a >= m_atomAndLayers.size() || b >= m_atomAndLayers.size())
    return;

  // Allow Argument Dependent Lookup for swap
  using std::swap;

  swap(m_atomAndLayers[a], m_atomAndLayers[b]);
}

size_t Layer::layerCount() const
{
  return m_maxLayer + 1;
}

} // namespace Avogadro::Core
