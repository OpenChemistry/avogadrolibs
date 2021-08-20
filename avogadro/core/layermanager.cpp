/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "layermanager.h"
#include <cassert>

namespace Avogadro {
namespace Core {

using std::make_shared;
using std::map;
using std::shared_ptr;

const Molecule* LayerManager::m_activeMolecule = nullptr;
map<const Molecule*, shared_ptr<MoleculeInfo>> LayerManager::m_molToInfo;

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

size_t LayerManager::layerCount()
{
  assert(m_activeMolecule != nullptr);
  return m_molToInfo[m_activeMolecule]->layer.maxLayer() + 1;
}

} // namespace Core
} // namespace Avogadro
