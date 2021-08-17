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

/**
 * @class PluginLayerManager pluginlayermanager.h
 * <avogadro/qtgui/pluginlayermanager.h>
 * @brief The PluginLayerManager class is a set of common layer dependent
 * operators usefull for Layer dependent QtPlugins.
 */
class AVOGADROQTGUI_EXPORT PluginLayerManager : protected Core::LayerManager
{
public:
  PluginLayerManager(const std::string& name = "undef");

  ~PluginLayerManager();

  /** @return if the active layer in the molecule is locked. */
  bool activeLayerLocked() const;
  bool atomLocked(size_t atom) const;

  /** check if there's existent data in the key and reload it in the custom
   * class. */
  template <typename T>
  void load()
  {
    if (m_activeMolecule != nullptr) {
      auto& info = m_molToInfo[m_activeMolecule];
      if (info->loaded.find(m_name) == info->loaded.end()) {
        for (size_t i = 0; i < info->settings[m_name].size(); ++i) {
          auto serial = info->settings[m_name][i]->getSave();
          if (serial != "") {
            T* aux = new T;
            aux->deserialize(serial);
            delete info->settings[m_name][i];
            info->settings[m_name][i] = aux;
          }
        }
        info->loaded.insert(m_name);
      }
    }
  }

  /** @return if the plugin is enabled in any layer */
  bool isEnabled() const;

  /** @return if the plugin is enabled in the active layer */
  bool isActiveLayerEnabled() const;

  /** set active layer @p enable */
  void setEnabled(bool enable);

  /** @return @p atom layer enabled globaly and in plugin */
  bool atomEnabled(Index atom) const;

  /** @return @p atom layer enabled globaly, in plugin and in @p layer */
  bool atomEnabled(size_t layer, Index atom) const;

  /** @return if @p atom1 or @p atom2 is enabled */
  bool bondEnabled(Index atom1, Index atom2) const;

  /** @return layer id from @p atom */
  size_t getLayerID(Index atom) const;
  /** @return layer count */
  size_t layerCount() const;

  /** @return custom data T derived from LayerData. if @p layer is equal to
   * MaxIndex returns activeLayer */
  template <typename T>
  T& getSetting(size_t layer = MaxIndex)
  {
    auto info = m_molToInfo[m_activeMolecule];
    if (layer == MaxIndex) {
      layer = info->layer.activeLayer();
    }
    assert(layer <= info->layer.maxLayer());
    if (info->settings.find(m_name) == info->settings.end()) {
      info->settings[m_name] = Core::Array<Core::LayerData*>();
    }

    while (info->settings[m_name].size() < layer + 1) {
      info->settings[m_name].push_back(new T());
    }
    auto result = static_cast<T*>(info->settings[m_name][layer]);
    return *result;
  }

private:
  // layer key identifier
  std::string m_name;
};

} // namespace QtGui
} // namespace Avogadro

#endif
