/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_LAYER_H
#define AVOGADRO_CORE_LAYER_H

#include "avogadrocoreexport.h"

#include "avogadrocore.h"

#include <avogadro/core/array.h>

namespace Avogadro::Core {

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
  Layer() = default;
  ~Layer() = default;

  // att atom to param layer
  void addAtom(size_t layer);
  void addAtom(size_t layer, Index atom);
  void addAtomToActiveLayer(Index atom);
  void removeAtom(Index atom);

  /** Remove @p layer, renumbering higher layers down by one. Atoms that were
   * in @p layer are NOT removed from the per-atom array: they move into
   * whichever layer is active once the active layer itself has been updated
   * (see @a setActiveLayer's effect below), so @a atomCount() never changes.
   * If @p layer is the active layer, the layer below becomes active (layer 0
   * if @p layer is 0); if the active layer is above @p layer, its id is
   * decremented to keep naming the same layer. A no-op if @p layer is
   * greater than @a maxLayer(), or if @a maxLayer() is 0 (the only layer
   * cannot be removed). */
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

  /**  resize the atom-layer array to @p count atoms, removing any excess. */
  void resize(size_t count);

  /**  increase the maximum layer allowed .*/
  void addLayer();

  /**  insert a layer at @p layer, equal or bigger previous layers will be
   * shifted up by one, and the active layer shifts up with them if it was at
   * or above @p layer, so it keeps naming the same layer. A no-op if @p
   * layer is greater than @a maxLayer() + 1. */
  void addLayer(size_t layer);

  /** change @p m_activeLayer to @p layer. A layer id one past @a maxLayer()
   * is accepted: it lets a caller point the active layer at a layer that
   * does not exist yet, which is then created lazily the first time an atom
   * is actually added to it (see @a addAtomToActiveLayer() / @a addAtom()).
   * Anything further out of range is ignored, leaving the active layer
   * unchanged. */
  void setActiveLayer(size_t layer);

  /** swap the layer ID from @p a and @p b. A no-op if either index is out of
   * range (>= @a atomCount()). */
  void swapLayer(Index a, Index b);

private:
  Core::Array<size_t> m_atomAndLayers;
  size_t m_activeLayer = 0;
  size_t m_maxLayer = 0;
};

} // namespace Avogadro::Core

#endif
