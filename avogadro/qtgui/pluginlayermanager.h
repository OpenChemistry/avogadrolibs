/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTGUI_LAYERMANAGER_H
#define AVOGADRO_QTGUI_LAYERMANAGER_H

#include "avogadroqtguiexport.h"

#include <avogadro/core/layermanager.h>
#include <cassert>

namespace Avogadro {
namespace QtGui {

class AVOGADROQTGUI_EXPORT PluginLayerManager : protected Core::LayerManager
{
public:
  PluginLayerManager(const std::string& name = "undef");

  ~PluginLayerManager();

  static bool activeLayerLocked();

  bool isEnabled() const;
  void setEnabled(bool enable);

  bool atomEnabled(Index atom) const;
  bool atomEnabled(size_t layer, Index atom) const;
  bool bondEnabled(Index atom1, Index atom2) const;

  size_t getLayerID(Index atom) const;
  size_t count() const;
  bool isActiveLayerEnabled() const;

  template <typename T>
  T& getSetting(size_t layer = MaxIndex)
  {
    auto info = m_molToInfo[m_activeMolecule];
    if (layer == MaxIndex) {
      layer = info->layer.activeLayer();
    }
    assert(layer <= info->layer.maxLayer());
    if (info->settings.find(m_name) == info->settings.end()) {
      info->settings[m_name] = std::vector<Core::LayerData*>();
    }

    if (info->settings[m_name].size() > 0 &&
        dynamic_cast<T*>(info->settings[m_name][0]) == nullptr) {
      for (size_t i = 0; i < info->settings[m_name].size(); ++i) {
        T* aux = new T;
        aux->load(info->settings[m_name][i]->getSave());
        delete info->settings[m_name][i];
        info->settings[m_name][i] = aux;
      }
    }
    while (info->settings[m_name].size() < layer + 1) {
      info->settings[m_name].push_back(new T());
    }
    auto result = static_cast<T*>(info->settings[m_name][layer]);
    return *result;
  }

private:
  std::string m_name;
};

} // namespace QtGui
} // namespace Avogadro

#endif
