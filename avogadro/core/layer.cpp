/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "layer.h"
#include <cassert>

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
  assert(layer <= m_maxLayer + 1);
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
  assert(layer <= m_maxLayer + 1);
  for (auto& atomLayer : m_atomAndLayers) {
    if (atomLayer >= layer) {
      ++atomLayer;
    }
  }
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
  assert(layer <= m_maxLayer);
  if (m_maxLayer >= 1) {
    for (auto it = m_atomAndLayers.begin(); it != m_atomAndLayers.end();) {
      if (*it == layer) {
        it = m_atomAndLayers.erase(it);
      } else {
        if (*it > layer) {
          --(*it);
        }
        ++it;
      }
    }
    --m_maxLayer;
  }
}

void Layer::swapLayer(Index a, Index b)
{
  // Allow Argument Dependent Lookup for swap
  using std::swap;

  swap(m_atomAndLayers[a], m_atomAndLayers[b]);
}

size_t Layer::layerCount() const
{
  return m_maxLayer + 1;
}

} // namespace Avogadro::Core
