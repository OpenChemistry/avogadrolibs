/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTGUI_RWLAYERMANAGER_H
#define AVOGADRO_QTGUI_RWLAYERMANAGER_H

#include "avogadroqtguiexport.h"

#include <avogadro/core/array.h>
#include <avogadro/core/layermanager.h>

namespace Avogadro {
namespace Core {
class Molecule;
}
namespace QtGui {

class RWMolecule;

/**
 * @class RWLayerManager rwlayermanager.h <avogadro/qtgui/rwlayermanager.h>
 * @brief The RWLayerManager do and undo for layer actions.
 */
class AVOGADROQTGUI_EXPORT RWLayerManager : protected Core::LayerManager
{
public:
  void removeLayer(size_t layer, RWMolecule* rwmolecule);
  void addLayer(RWMolecule* rwmolecule);
  void setActiveLayer(size_t layer, RWMolecule* rwmolecule);

protected:
  /** @return if @p layer is visible */
  bool visible(size_t layer) const;
  /** @return if @p layer is locked */
  bool locked(size_t layer) const;
  /** flip the visible value in layer */
  void flipVisible(size_t layer);
  /** flip the locked value in layer */
  void flipLocked(size_t layer);

  /** set mol as active molecule and add it if not exist */
  void addMolecule(const Core::Molecule* mol);

  /** @return a sorted array by layer ID, containing the ID and the key name */
  Core::Array<std::pair<size_t, std::string>> activeMoleculeNames() const;
};

} // namespace QtGui
} // namespace Avogadro

#endif
