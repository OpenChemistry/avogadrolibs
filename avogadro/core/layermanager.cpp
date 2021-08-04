/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "layermanager.h"
#include <cassert>
#include <iostream>

namespace Avogadro {
namespace Core {

using std::make_shared;
using std::map;
using std::set;
using std::shared_ptr;
using std::vector;

const Molecule* LayerManager::m_activeMolecule = nullptr;
map<const Molecule*, shared_ptr<MoleculeInfo>> LayerManager::m_molToInfo;

LayerManager::LayerManager() : LayerManager("undef") {}
LayerManager::LayerManager(const std::string& name) : m_name(name) {}

Layer& LayerManager::getMoleculeLayer()
{
  assert(m_activeMolecule != nullptr);
  auto it = m_molToInfo.find(m_activeMolecule);
  assert(it != m_molToInfo.end());
  return it->second->layer;
}

Layer& LayerManager::getMoleculeLayer(const Molecule* mol)
{
  auto it = m_molToInfo.find(mol);
  if (it == m_molToInfo.end()) {
    m_molToInfo[mol] = make_shared<MoleculeInfo>(mol);
  }
  return m_molToInfo[mol]->layer;
}

shared_ptr<MoleculeInfo> LayerManager::getMoleculeInfo()
{
  assert(m_activeMolecule != nullptr);
  return m_molToInfo[m_activeMolecule];
}

shared_ptr<MoleculeInfo> LayerManager::getMoleculeInfo(const Molecule* mol)
{
  auto it = m_molToInfo.find(mol);
  if (it == m_molToInfo.end()) {
    m_molToInfo[mol] = make_shared<MoleculeInfo>(mol);
  }
  return m_molToInfo[mol];
}

Layer& LayerManager::getMoleculeLayer(const Molecule* original,
                                      const Molecule* copy)
{
  auto it = m_molToInfo.find(original);
  if (it == m_molToInfo.end()) {
    auto molecule = make_shared<MoleculeInfo>(original);
    m_molToInfo[original] = molecule;
    m_molToInfo[copy] = molecule;
    return m_molToInfo[original]->layer;
  } else {
    m_molToInfo[copy] = it->second;
    return it->second->layer;
  }
}

void LayerManager::addMolecule(const Molecule* mol)
{
  m_activeMolecule = mol;
  auto it = m_molToInfo.find(mol);
  if (it == m_molToInfo.end()) {
    m_molToInfo[mol] = make_shared<MoleculeInfo>(mol);
  }
}

void LayerManager::deleteMolecule(const Molecule* mol)
{
  auto aux = m_molToInfo.find(mol);
  if (aux != m_molToInfo.end()) {
    auto id = aux->second->mol;
    if (id == mol) {
      auto it = m_molToInfo.begin();
      while (it != m_molToInfo.end()) {
        if (id == it->second->mol) {
          it = m_molToInfo.erase(it);
        } else {
          ++it;
        }
      }
    } else {
      if (m_activeMolecule == mol) {
        m_activeMolecule = aux->second->mol;
      }
      m_molToInfo.erase(aux);
    }
  }
}

bool LayerManager::isEnabled() const
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

bool LayerManager::isActiveLayerEnabled() const
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

void LayerManager::setEnabled(bool enable)
{
  if (m_activeMolecule == nullptr) {
    return;
  }
  auto& molecule = m_molToInfo[m_activeMolecule];
  auto it = molecule->enable.find(m_name);
  if (it == molecule->enable.end()) {
    molecule->enable[m_name] = vector<bool>();
  }
  size_t qttyLayers = molecule->layer.maxLayer() + 1;
  if (molecule->enable[m_name].size() != qttyLayers) {
    molecule->enable[m_name].resize(qttyLayers, false);
  }

  size_t activeLayer = molecule->layer.activeLayer();
  molecule->enable[m_name][activeLayer] = enable;
}

bool LayerManager::atomEnabled(Index atom) const
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

bool LayerManager::bondEnabled(Index atom1, Index atom2) const
{
  return atomEnabled(atom1) || atomEnabled(atom2);
}

Array<std::pair<size_t, std::string>> LayerManager::activeMoleculeNames() const
{
  if (m_activeMolecule == nullptr) {
    return Array<std::pair<size_t, std::string>>();
  }
  auto& molecule = m_molToInfo[m_activeMolecule];
  size_t qttyLayer = molecule->layer.maxLayer() + 1;
  vector<set<std::string>> active(qttyLayer, set<std::string>());
  for (const auto& names : molecule->enable) {
    for (size_t i = 0; i < names.second.size(); ++i) {
      if (names.second[i]) {
        active[i].insert(names.first);
      }
    }
  }

  Array<std::pair<size_t, std::string>> result;
  size_t layer = 0;
  for (const auto& names : active) {
    result.push_back(std::make_pair(layer, "Layer"));
    for (const auto& name : names) {
      result.push_back(std::make_pair(layer, name));
    }
    ++layer;
  }
  return result;
}

bool LayerManager::visible(size_t layer) const
{
  return m_molToInfo[m_activeMolecule]->visible[layer];
}

bool LayerManager::locked(size_t layer) const
{
  return m_molToInfo[m_activeMolecule]->locked[layer];
}

void LayerManager::flipVisible(size_t layer)
{
  auto& molecule = m_molToInfo[m_activeMolecule];
  molecule->visible[layer] = !molecule->visible[layer];
}

void LayerManager::flipLocked(size_t layer)
{
  auto& molecule = m_molToInfo[m_activeMolecule];
  molecule->locked[layer] = !molecule->locked[layer];
}

bool LayerManager::activeLayerLocked()
{
  std::cout << "m_molToInfo.size()" << std::endl;
  std::cout << m_molToInfo.size() << std::endl;
  std::cout << m_activeMolecule << std::endl;
  for (const auto& p : m_molToInfo) {
    std::cout << p.first << " " << p.second->mol << std::endl;
  }
  assert(m_activeMolecule != nullptr);
  auto& molecule = m_molToInfo[m_activeMolecule];
  size_t active = molecule->layer.activeLayer();
  return molecule->locked[active];
}

size_t LayerManager::layerCount() const
{
  return m_molToInfo[m_activeMolecule]->layer.maxLayer() + 1;
}

} // namespace Core
} // namespace Avogadro
