/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTGUI_LAYERMANAGER_H
#define AVOGADRO_QTGUI_LAYERMANAGER_H

#include "avogadroqtguiexport.h"

#include <avogadro/core/layermanager.h>
#include <cassert>
#include <memory>
#include <iostream>

namespace Avogadro {
namespace QtGui {

/**
 * @class PluginLayerManager pluginlayermanager.h
 * <avogadro/qtgui/pluginlayermanager.h>
 * @brief The PluginLayerManager class is a set of common layer dependent
 * operators useful for Layer dependent QtPlugins.
 */
class AVOGADROQTGUI_EXPORT PluginLayerManager : protected Core::LayerManager
{
public:
  PluginLayerManager(std::string name = "undef");

  ~PluginLayerManager();

  /** @return if the active layer in the molecule is locked. */
  bool activeLayerLocked() const;
  bool atomLocked(size_t atom) const;

  /** check if there's existent data in the key and reload it in the custom
   * class. */
  template <typename T>
  void load()
  {
    auto info = activeMoleculeInfo();
    if (info != nullptr) {
      if (info->loaded.find(m_name) == info->loaded.end()) {
        for (size_t i = 0; i < info->settings[m_name].size(); ++i) {
          // A null slot means this layer has no settings for this plugin;
          // leave it null. Every other slot has to be rebuilt as a T, empty
          // getSave() included: reading came from CjsonFormat, which can only
          // construct the LayerData base, and getSetting() below static_casts
          // whatever is here to T*.
          if (info->settings[m_name][i] == nullptr)
            continue;
          auto aux = std::make_shared<T>();
          aux->deserialize(info->settings[m_name][i]->getSave());
          info->settings[m_name][i] = aux;
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

  /** @return @p atom layer enabled globally and in plugin */
  bool atomEnabled(Index atom) const;

  /** @return @p atom layer enabled globally, in plugin and in @p layer */
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
  T* getSetting(size_t layer = MaxIndex)
  {
    auto info = activeMoleculeInfo();
    if (info == nullptr)
      return nullptr;

    if (layer == MaxIndex) {
      layer = info->layer.activeLayer();
    }

    if (info->settings.find(m_name) == info->settings.end()) {
      info->settings[m_name] = Core::Array<Core::LayerDataPtr>();
    }

    // do we need to create new layers in the array?
    while (info->settings[m_name].size() < layer + 1) {
      info->settings[m_name].push_back(std::make_shared<T>());
    }
    // An existing slot can still be null -- a layer that had no settings for
    // this plugin, from a file or from AddLayerCommand -- and callers
    // dereference what they get back.
    if (info->settings[m_name][layer] == nullptr)
      info->settings[m_name][layer] = std::make_shared<T>();
    // Borrowed: the Array keeps ownership, callers only read through this.
    return static_cast<T*>(info->settings[m_name][layer].get());
  }

private:
  // layer key identifier
  std::string m_name;
};

} // namespace QtGui
} // namespace Avogadro

#endif
