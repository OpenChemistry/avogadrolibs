/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTGUI_LAYERMANAGER_H
#define AVOGADRO_QTGUI_LAYERMANAGER_H

#include "avogadroqtguiexport.h"

#include <avogadro/core/array.h>
#include <avogadro/core/layer.h>

#include <QtCore/QString>
#include <cassert>
#include <memory>

namespace Avogadro {
namespace QtGui {

struct MoleculeInfo;
class RWMolecule;

class AVOGADROQTGUI_EXPORT LayerManager
{
public:
  LayerManager();
  LayerManager(const QString& name);
  LayerManager(const void* mol, const QString& name);

  // active Layer
  static Core::Layer& getMoleculeLayer();
  static Core::Layer& getMoleculeLayer(const void* mol);
  static Core::Layer& getMoleculeLayer(const void* original, const void* copy);
  static bool activeLayerLocked();

  bool isEnabled() const;
  bool isActiveLayerEnabled() const;
  void setEnabled(bool enable);
  bool atomEnabled(Index atom) const;
  bool bondEnabled(Index atom1, Index atom2) const;
  void removeLayer(size_t layer, RWMolecule* rwmolecule);
  void addLayer(RWMolecule* rwmolecule);
  size_t layerCount() const;
  void setActiveLayer(size_t layer, RWMolecule* rwmolecule);

protected:
  bool visible(size_t layer) const;
  bool locked(size_t layer) const;
  void flipVisible(size_t layer);
  void flipLocked(size_t layer);
  void addMolecule(const void* mol);
  void removeMolecule(const void* i);
  Core::Array<std::pair<size_t, QString>> activeMoleculeNames() const;

private:
  static const void* m_activeMolecule;
  static std::map<const void*, std::shared_ptr<MoleculeInfo>> m_molToInfo;

  QString m_name;
};

} // namespace QtGui
} // namespace Avogadro

#endif
