/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_LAYER_H
#define AVOGADRO_CORE_LAYER_H

#include "avogadrocore.h"

#include <avogadro/core/array.h>
#include <avogadro/core/connectedgroup.h>

namespace Avogadro {
namespace Core {

class AVOGADROCORE_EXPORT Layer
{
public:
  Layer();

  void addAtom();
  void addAtom(size_t layer);
  void addAtom(size_t layer, Index atom);
  void addAtomToActiveLayer(Index atom);
  void removeAtom(Index atom);
  void removeLayer(size_t layer);

  size_t getLayerID(Index atom) const;
  size_t activeLayer() const;
  size_t maxLayer() const;
  size_t atomCount() const;

  void clear();
  void addLayer();
  void addLayer(size_t layer);
  void setActiveLayer(size_t layer);
  void swapLayer(Index a, Index b);

private:
  Core::Array<size_t> m_atomAndLayers;
  size_t m_activeLayer;
  size_t m_maxLayer;
};

} // namespace Core
} // namespace Avogadro

#endif
