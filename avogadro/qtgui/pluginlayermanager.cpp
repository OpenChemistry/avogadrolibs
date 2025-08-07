/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "pluginlayermanager.h"

#include <avogadro/qtplugins/ballandstick/ballandstick.h>
#include <avogadro/qtplugins/cartoons/cartoons.h>

#include <QtCore/QSettings>
#include <cassert>
#include <utility>
#include <vector>

namespace Avogadro::QtGui {

using std::string;
using std::vector;

PluginLayerManager::PluginLayerManager(string name) : m_name(std::move(name)) {}

PluginLayerManager::~PluginLayerManager() = default;

bool PluginLayerManager::isEnabled() const
{
  auto molecule = activeMoleculeInfo();
  if (molecule == nullptr)
    return false;
  auto it = molecule->enable.find(m_name);
  if (it == molecule->enable.end())
    return false;
  for (const auto& b : it->second) {
    if (b) {
      return true;
    }
  }
  return false;
}

bool PluginLayerManager::isActiveLayerEnabled() const
{
  auto molecule = activeMoleculeInfo();
  if (molecule == nullptr)
    return false;
  auto it = molecule->enable.find(m_name);
  if (it == molecule->enable.end())
    return false;
  size_t active = molecule->layer.activeLayer();
  if (active < it->second.size()) {
    return it->second[active];
  }
  return false;
}

void PluginLayerManager::setEnabled(bool enable)
{
  auto molecule = activeMoleculeInfo();
  if (molecule == nullptr)
    return;
  auto it = molecule->enable.find(m_name);
  if (it == molecule->enable.end()) {
    molecule->enable[m_name] = vector<bool>();
  }
  size_t qttyLayers = molecule->layer.layerCount();
  if (molecule->enable[m_name].size() != qttyLayers) {
    molecule->enable[m_name].resize(qttyLayers, false);
  }
  size_t activeLayer = molecule->layer.activeLayer();
  molecule->enable[m_name][activeLayer] = enable;
}

bool PluginLayerManager::atomEnabled(Index atom) const
{
  auto molecule = activeMoleculeInfo();
  if (molecule == nullptr)
    return false;
  auto it = molecule->enable.find(m_name);
  if (it == molecule->enable.end())
    return false;
  size_t layer = molecule->layer.getLayerID(atom);
  if (layer == MaxIndex) {
    return false;
  }
  // visible is sized per layer independently of Layer itself, so bounds check
  // it separately rather than assuming the two agree.
  return layer < it->second.size() && it->second[layer] &&
         layer < molecule->visible.size() && molecule->visible[layer];
}

size_t PluginLayerManager::getLayerID(Index atom) const
{
  auto molecule = activeMoleculeInfo();
  if (molecule == nullptr || atom >= molecule->layer.atomCount())
    return MaxIndex;
  return molecule->layer.getLayerID(atom);
}

bool PluginLayerManager::atomEnabled(size_t layerFilter, Index atom) const
{
  bool enabled = atomEnabled(atom);
  if (!enabled) {
    return false;
  }
  auto molecule = activeMoleculeInfo();
  if (molecule == nullptr)
    return false;
  size_t layer = molecule->layer.getLayerID(atom);
  return layer == layerFilter;
}

bool PluginLayerManager::bondEnabled(Index atom1, Index atom2) const
{
  return atomEnabled(atom1) || atomEnabled(atom2);
}

bool PluginLayerManager::activeLayerLocked() const
{
  auto molecule = activeMoleculeInfo();
  if (molecule == nullptr)
    return false;
  size_t active = molecule->layer.activeLayer();
  return active < molecule->locked.size() && molecule->locked[active];
}

bool PluginLayerManager::atomLocked(size_t atom) const
{
  auto molecule = activeMoleculeInfo();
  if (molecule == nullptr)
    return false;
  // getLayerID returns MaxIndex for an atom that is in no layer, which would
  // index locked far out of bounds.
  size_t layer = molecule->layer.getLayerID(atom);
  return layer < molecule->locked.size() && molecule->locked[layer];
}

size_t PluginLayerManager::layerCount() const
{
  return LayerManager::layerCount();
}
} // namespace Avogadro::QtGui
