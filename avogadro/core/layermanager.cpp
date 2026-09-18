/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "layermanager.h"

#include "molecule.h"

namespace Avogadro::Core {

using std::shared_ptr;

const Molecule* LayerManager::m_activeMolecule = nullptr;

shared_ptr<MoleculeInfo> LayerManager::findMoleculeInfo(const Molecule* mol)
{
  if (mol == nullptr)
    return nullptr;
  return mol->layerInfo();
}

shared_ptr<MoleculeInfo> LayerManager::activeMoleculeInfo()
{
  return findMoleculeInfo(m_activeMolecule);
}

Layer& LayerManager::getMoleculeLayer()
{
  auto info = activeMoleculeInfo();
  if (info == nullptr) {
    // There is no active molecule to answer for. Returning a reference to a
    // shared empty layer keeps callers from dereferencing null.
    static Layer emptyLayer;
    return emptyLayer;
  }
  return info->layer;
}

Layer& LayerManager::getMoleculeLayer(const Molecule* mol)
{
  auto info = findMoleculeInfo(mol);
  if (info == nullptr) {
    static Layer emptyLayer;
    return emptyLayer;
  }
  return info->layer;
}

shared_ptr<MoleculeInfo> LayerManager::getMoleculeInfo()
{
  return activeMoleculeInfo();
}

shared_ptr<MoleculeInfo> LayerManager::getMoleculeInfo(const Molecule* mol)
{
  return findMoleculeInfo(mol);
}

size_t LayerManager::layerCount()
{
  auto info = activeMoleculeInfo();
  if (info == nullptr)
    return 0;
  return info->layer.maxLayer() + 1;
}

} // namespace Avogadro::Core
