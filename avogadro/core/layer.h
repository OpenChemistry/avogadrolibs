/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_LAYER_H
#define AVOGADRO_CORE_LAYER_H

#include "avogadrocoreexport.h"

#include "avogadrocore.h"

#include <avogadro/core/array.h>

namespace Avogadro {
namespace Core {

/**
 * @class Layer layer.h <avogadro/core/layer.h>
 * @brief The Layer class represents a relation one to one between atoms ID
 * and layer ID, and stores the unique active layer.
 * Layer's ID are consecutively and there can't be a ID bigger than @p
 * m_maxLayer.
 */
class AVOGADROCORE_EXPORT Layer
{
public:
  Layer();

  // att atom to param layer
  void addAtom(size_t layer);
  void addAtom(size_t layer, Index atom);
  void addAtomToActiveLayer(Index atom);
  void removeAtom(Index atom);
  void removeLayer(size_t layer);

  /**  @return the layer ID from the @p atom. */
  size_t getLayerID(Index atom) const;
  /**  @return the active Layer. */
  size_t activeLayer() const;

  /**  @return the maximum layer allowed. */
  size_t maxLayer() const;

  /** @return the number of layers. */
  size_t layerCount() const;

  /**  @return The number of atoms. */
  size_t atomCount() const;

  /**  remove all IDs. */
  void clear();

  /**  increase the maximum layer allowed .*/
  void addLayer();

  /**  insert a layer at @p layer, equal or bigger previous layers will be
   * shifted. */
  void addLayer(size_t layer);

  /** change @p m_activeLayer. */
  void setActiveLayer(size_t layer);

  /** swap the layer ID from @p a and @p b. */
  void swapLayer(Index a, Index b);

private:
  Core::Array<size_t> m_atomAndLayers;
  size_t m_activeLayer;
  size_t m_maxLayer;
};

} // namespace Core
} // namespace Avogadro

#endif
