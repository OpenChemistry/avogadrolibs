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

class AVOGADROQTGUI_EXPORT RWLayerManager : public Core::LayerManager
{
public:
  void removeLayer(size_t layer, RWMolecule* rwmolecule);
  void addLayer(RWMolecule* rwmolecule);
  void setActiveLayer(size_t layer, RWMolecule* rwmolecule);

protected:
  bool visible(size_t layer) const;
  bool locked(size_t layer) const;
  void flipVisible(size_t layer);
  void flipLocked(size_t layer);

  void addMolecule(const Core::Molecule* mol);

  Core::Array<std::pair<size_t, std::string>> activeMoleculeNames() const;
};

} // namespace QtGui
} // namespace Avogadro

#endif
