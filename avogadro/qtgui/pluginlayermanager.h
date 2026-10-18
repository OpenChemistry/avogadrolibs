/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTGUI_LAYERMANAGER_H
#define AVOGADRO_QTGUI_LAYERMANAGER_H

#include "avogadroqtguiexport.h"

#include <avogadro/core/layermanager.h>
#include <algorithm>
#include <cassert>
#include <iostream>
#include <memory>
#include <vector>

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
  /**
   * @class Snapshot
   * @brief Per-call cache of everything a render loop asks the manager.
   *
   * atomEnabled(), getLayerID() and getSetting() each resolve the active
   * molecule and look the plugin name up in a std::map. A Snapshot does that
   * once, then answers the same questions with array lookups. It gives the
   * same answers as the PluginLayerManager methods of the same name, and is
   * meant to live for a single process() call: it holds the layer state and
   * raw pointers into the settings, so build a new one after anything that
   * edits layers.
   */
  template <typename T>
  class Snapshot
  {
  public:
    /** @return same as PluginLayerManager::atomEnabled(@p atom) */
    bool atomEnabled(Index atom) const
    {
      if (!m_info)
        return false;
      size_t layer = m_info->layer.getLayerID(atom);
      return layer != MaxIndex && layer < m_enabled.size() && m_enabled[layer];
    }

    /** @return same as PluginLayerManager::bondEnabled(@p atom1, @p atom2) */
    bool bondEnabled(Index atom1, Index atom2) const
    {
      return atomEnabled(atom1) || atomEnabled(atom2);
    }

    /** @return same as PluginLayerManager::getLayerID(@p atom) */
    size_t getLayerID(Index atom) const
    {
      if (!m_info || atom >= m_info->layer.atomCount())
        return MaxIndex;
      return m_info->layer.getLayerID(atom);
    }

    /** @return same as PluginLayerManager::getSetting<T>(@p layer); MaxIndex
     * is the active layer. */
    T* setting(size_t layer) const
    {
      if (!m_info)
        return nullptr;
      // Settings are created lazily, on first use, by the real getSetting():
      // that keeps the molecule's settings arrays (which the CJSON writer
      // saves) exactly what the per-call API would have left behind.
      if (layer == MaxIndex) {
        if (m_active == nullptr)
          m_active = m_manager->getSetting<T>();
        return m_active;
      }
      if (layer < m_settings.size()) {
        if (m_settings[layer] == nullptr)
          m_settings[layer] = m_manager->getSetting<T>(layer);
        return m_settings[layer];
      }
      return m_manager->getSetting<T>(layer);
    }

    /** @return setting() of the layer holding @p atom */
    T* atomSetting(Index atom) const { return setting(getLayerID(atom)); }

  private:
    friend class PluginLayerManager;
    Snapshot() = default;

    PluginLayerManager* m_manager = nullptr;
    std::shared_ptr<Core::MoleculeInfo> m_info;
    // m_enabled[layer]: enabled by the plugin and visible
    std::vector<char> m_enabled;
    // Lazily filled cache of getSetting<T>(layer) for 0..layerCount-1, and of
    // the active layer; nullptr means "not fetched yet".
    mutable std::vector<T*> m_settings;
    mutable T* m_active = nullptr;
  };

  /** Capture the layer state of the active molecule for one render pass.
   * Settings entries are created lazily, only for layers actually queried. */
  template <typename T>
  Snapshot<T> snapshot()
  {
    Snapshot<T> snap;
    snap.m_manager = this;
    snap.m_info = activeMoleculeInfo();
    if (!snap.m_info)
      return snap;

    auto it = snap.m_info->enable.find(m_name);
    if (it != snap.m_info->enable.end()) {
      const auto& enable = it->second;
      const auto& visible = snap.m_info->visible;
      size_t n = std::min(enable.size(), visible.size());
      snap.m_enabled.resize(n);
      for (size_t i = 0; i < n; ++i)
        snap.m_enabled[i] = (enable[i] && visible[i]) ? 1 : 0;
    }

    snap.m_settings.assign(snap.m_info->layer.layerCount(), nullptr);
    return snap;
  }

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
