/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTGUI_RWLAYERMANAGER_H
#define AVOGADRO_QTGUI_RWLAYERMANAGER_H

#include "avogadroqtguiexport.h"

#include <avogadro/core/layermanager.h>

namespace Avogadro {
namespace QtGui {

class RWMolecule;

class AVOGADROQTGUI_EXPORT RWLayerManager : public Core::LayerManager
{
public:
  void removeLayer(size_t layer, RWMolecule* rwmolecule);
  void addLayer(RWMolecule* rwmolecule);
  void setActiveLayer(size_t layer, RWMolecule* rwmolecule);
};

} // namespace QtGui
} // namespace Avogadro

#endif
