/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "layer.h"
#include <cassert>

namespace Avogadro {
namespace Core {

using std::swap;

Layer::Layer() : m_activeLayer(0), m_maxLayer(0) {}

void Layer::addAtom(size_t layer)
{
  addAtom(layer, m_atomAndLayers.size());
}

void Layer::addAtom(size_t layer, Index atom)
{
  assert(layer <= m_maxLayer);
  if (atom == m_atomAndLayers.size()) {
    m_atomAndLayers.push_back(layer);
  } else if (atom > m_atomAndLayers.size()) {
    m_atomAndLayers.resize(layer + 1, MaxIndex);
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
  swap(m_atomAndLayers[a], m_atomAndLayers[b]);
}

size_t Layer::layerCount() const
{
  return m_maxLayer + 1;
}

} // namespace Core
} // namespace Avogadro
