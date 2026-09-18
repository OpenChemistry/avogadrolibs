/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "layermanager.h"
#include <cassert>

namespace Avogadro::Core {

using std::make_shared;
using std::map;
using std::shared_ptr;

const Molecule* LayerManager::m_activeMolecule = nullptr;
map<const Molecule*, shared_ptr<MoleculeInfo>> LayerManager::m_molToInfo;

std::shared_ptr<MoleculeInfo> LayerManager::findMoleculeInfo(
  const Molecule* mol)
{
  if (mol == nullptr)
    return nullptr;
  auto it = m_molToInfo.find(mol);
  if (it == m_molToInfo.end())
    return nullptr;
  return it->second;
}

std::shared_ptr<MoleculeInfo> LayerManager::activeMoleculeInfo()
{
  return findMoleculeInfo(m_activeMolecule);
}

Layer& LayerManager::getMoleculeLayer()
{
  auto info = activeMoleculeInfo();
  if (info == nullptr) {
    // There is no active molecule to answer for. Returning a reference to a
    // shared empty layer keeps callers from dereferencing null; the previous
    // code relied on an assert, which compiles out of release builds.
    static Layer emptyLayer;
    return emptyLayer;
  }
  return info->layer;
}

Layer& LayerManager::getMoleculeLayer(const Molecule* mol)
{
  return getMoleculeInfo(mol)->layer;
}

shared_ptr<MoleculeInfo> LayerManager::getMoleculeInfo()
{
  return activeMoleculeInfo();
}

shared_ptr<MoleculeInfo> LayerManager::getMoleculeInfo(const Molecule* mol)
{
  if (mol == nullptr) {
    // Never key the registry on null: that entry could never be found again
    // and every later null lookup would share it.
    static shared_ptr<MoleculeInfo> orphan = make_shared<MoleculeInfo>(nullptr);
    return orphan;
  }
  auto it = m_molToInfo.find(mol);
  if (it == m_molToInfo.end())
    it = m_molToInfo.emplace(mol, make_shared<MoleculeInfo>(mol)).first;
  return it->second;
}

Layer& LayerManager::getMoleculeLayer(const Molecule* original,
                                      const Molecule* copy)
{
  assert(original != nullptr);
  assert(copy != nullptr);

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

void LayerManager::deleteMolecule(const Molecule* mol)
{
  assert(mol != nullptr);

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

size_t LayerManager::layerCount()
{
  auto info = activeMoleculeInfo();
  if (info == nullptr)
    return 0;
  return info->layer.maxLayer() + 1;
}

} // namespace Avogadro::Core
