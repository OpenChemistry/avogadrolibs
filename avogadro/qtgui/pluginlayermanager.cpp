/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "pluginlayermanager.h"

#include <avogadro/qtplugins/ballandstick/ballandstick.h>
#include <avogadro/qtplugins/cartoons/cartoons.h>

#include <QtCore/QSettings>
#include <cassert>
#include <vector>

namespace Avogadro {
namespace QtGui {

using Core::LayerData;
using QtPlugins::BallAndStick;
using QtPlugins::Cartoons;
using std::string;
using std::vector;

PluginLayerManager::PluginLayerManager(const string& name) : m_name(name) {}

PluginLayerManager::~PluginLayerManager()
{
  for (auto& info : m_molToInfo) {
    auto itEnable = info.second->enable.find(m_name);
    if (itEnable != info.second->enable.end()) {
      info.second->enable.erase(itEnable);
    }

    auto itSettings = info.second->settings.find(m_name);
    if (itSettings != info.second->settings.end()) {
      info.second->settings.erase(itSettings);
    }
  }
}

bool PluginLayerManager::isEnabled() const
{
  if (m_activeMolecule == nullptr ||
      m_molToInfo[m_activeMolecule]->enable.find(m_name) ==
        m_molToInfo[m_activeMolecule]->enable.end()) {
    return false;
  }
  for (const auto& b : m_molToInfo[m_activeMolecule]->enable[m_name]) {
    if (b) {
      return true;
    }
  }
  return false;
}

bool PluginLayerManager::isActiveLayerEnabled() const
{
  if (m_activeMolecule == nullptr ||
      m_molToInfo[m_activeMolecule]->enable.find(m_name) ==
        m_molToInfo[m_activeMolecule]->enable.end()) {
    return false;
  }
  auto& molecule = m_molToInfo[m_activeMolecule];
  size_t active = molecule->layer.activeLayer();
  if (active < molecule->enable[m_name].size()) {
    return molecule->enable[m_name][active];
  }
  return false;
}

void PluginLayerManager::setEnabled(bool enable)
{
  if (m_activeMolecule == nullptr) {
    return;
  }
  auto& molecule = m_molToInfo[m_activeMolecule];
  auto it = molecule->enable.find(m_name);
  if (it == molecule->enable.end()) {
    molecule->enable[m_name] = vector<bool>();
  }
  size_t qttyLayers = molecule->layer.layerCount();
  if (molecule->enable[m_name].size() != qttyLayers) {
    molecule->enable[m_name].resize(qttyLayers, false);
  }
  // if this is a fully fresh run, set some intial trues
  if ((m_name == BallAndStick::getName() || m_name == Cartoons::getName())) {
    QSettings settings;
    bool enable;
    if (m_name == BallAndStick::getName()) {
      enable = settings.value("ballandstick/enable", true).toBool();
      settings.setValue("ballandstick/enable", false);
    } else if (m_name == Cartoons::getName()) {
      enable = settings.value("cartoon/enable", true).toBool();
      settings.setValue("cartoon/enable", false);
    }
    if (enable) {
      molecule->enable[m_name][0] = true;
      return;
    }
  }
  size_t activeLayer = molecule->layer.activeLayer();
  molecule->enable[m_name][activeLayer] = enable;
}

bool PluginLayerManager::atomEnabled(Index atom) const
{
  if (m_activeMolecule == nullptr ||
      m_molToInfo[m_activeMolecule]->enable.find(m_name) ==
        m_molToInfo[m_activeMolecule]->enable.end()) {
    return false;
  }
  auto& molecule = m_molToInfo[m_activeMolecule];
  size_t layer = molecule->layer.getLayerID(atom);
  if (layer == MaxIndex) {
    return false;
  }
  return layer < molecule->enable[m_name].size() &&
         molecule->enable[m_name][layer] && molecule->visible[layer];
}

size_t PluginLayerManager::getLayerID(Index atom) const
{
  assert(m_activeMolecule != nullptr);
  auto& molecule = m_molToInfo[m_activeMolecule];
  assert(atom < molecule->layer.atomCount());
  return molecule->layer.getLayerID(atom);
}

bool PluginLayerManager::atomEnabled(size_t layerFilter, Index atom) const
{
  bool enabled = atomEnabled(atom);
  if (!enabled) {
    return false;
  }
  auto& molecule = m_molToInfo[m_activeMolecule];
  size_t layer = molecule->layer.getLayerID(atom);
  return layer == layerFilter;
}

bool PluginLayerManager::bondEnabled(Index atom1, Index atom2) const
{
  return atomEnabled(atom1) || atomEnabled(atom2);
}

bool PluginLayerManager::activeLayerLocked() const
{
  assert(m_activeMolecule != nullptr);
  auto& molecule = m_molToInfo[m_activeMolecule];
  size_t active = molecule->layer.activeLayer();
  return molecule->locked[active];
}

bool PluginLayerManager::atomLocked(size_t atom) const
{
  assert(m_activeMolecule != nullptr);
  auto& molecule = m_molToInfo[m_activeMolecule];
  size_t layer = molecule->layer.getLayerID(atom);
  return molecule->locked[layer];
}

size_t PluginLayerManager::layerCount() const
{
  return LayerManager::layerCount();
}
} // namespace QtGui
} // namespace Avogadro
