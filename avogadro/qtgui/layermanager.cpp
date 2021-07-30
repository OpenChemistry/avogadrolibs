/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "layermanager.h"
#include "rwmolecule.h"

#include <QtCore/QObject>
#include <QtWidgets/QUndoCommand>
#include <QtWidgets/QUndoStack>

namespace Avogadro {
namespace QtGui {

using Core::Array;
using Core::Layer;
using std::make_shared;
using std::map;
using std::set;
using std::shared_ptr;
using std::vector;

struct MoleculeInfo
{
  const void* mol;
  vector<bool> visible;
  vector<bool> locked;
  map<QString, vector<bool>> enable;
  Layer layer;

  MoleculeInfo(const void* m) : mol(m)
  {
    locked.push_back(false);
    visible.push_back(true);
  }

  MoleculeInfo(const void* m, const QString& name) : MoleculeInfo(m)
  {
    enable[name] = vector<bool>();
  }

  void clear()
  {
    visible.clear();
    locked.clear();
    enable.clear();
    layer.clear();
  }
}; // namespace QtGui

namespace {
class AddLayerCommand : public QUndoCommand
{
public:
  AddLayerCommand(shared_ptr<MoleculeInfo> mol)
    : QUndoCommand(QObject::tr("Modify Layers")), m_moleculeInfo(mol)
  {}

  void redo() override
  {
    m_moleculeInfo->visible.push_back(true);
    m_moleculeInfo->locked.push_back(false);

    for (auto& enable : m_enable) {
      m_moleculeInfo->enable[enable.first].push_back(enable.second);
    }

    m_moleculeInfo->layer.addLayer();
  }

  void undo() override
  {
    m_moleculeInfo->visible.pop_back();
    m_moleculeInfo->locked.pop_back();

    for (auto& enable : m_moleculeInfo->enable) {
      m_enable[enable.first] = enable.second[enable.second.size() - 1];
      enable.second.pop_back();
    }

    m_moleculeInfo->layer.removeLayer(m_moleculeInfo->layer.maxLayer());
  }

protected:
  shared_ptr<MoleculeInfo> m_moleculeInfo;
  map<QString, bool> m_enable;
};

class ActiveLayerCommand : public QUndoCommand
{
public:
  ActiveLayerCommand(shared_ptr<MoleculeInfo> mol, size_t layer)
    : QUndoCommand(QObject::tr("Modify Layers")), m_moleculeInfo(mol),
      m_newActiveLayer(layer)
  {
    m_oldActiveLayer = m_moleculeInfo->layer.activeLayer();
  }

  void redo() override
  {
    m_moleculeInfo->layer.setActiveLayer(m_newActiveLayer);
  }

  void undo() override
  {
    m_moleculeInfo->layer.setActiveLayer(m_oldActiveLayer);
  }

protected:
  shared_ptr<MoleculeInfo> m_moleculeInfo;
  size_t m_oldActiveLayer;
  size_t m_newActiveLayer;
};

class RemoveLayerCommand : public QUndoCommand
{
public:
  RemoveLayerCommand(shared_ptr<MoleculeInfo> mol, size_t layer)
    : QUndoCommand(QObject::tr("Modify Layers")), m_moleculeInfo(mol),
      m_layer(layer)
  {}

  void redo() override
  {
    m_visible = m_moleculeInfo->visible[m_layer];
    m_moleculeInfo->visible.erase(
      std::next(m_moleculeInfo->visible.begin(), m_layer));

    m_locked = m_moleculeInfo->locked[m_layer];
    m_moleculeInfo->locked.erase(
      std::next(m_moleculeInfo->locked.begin(), m_layer));

    for (auto& enable : m_moleculeInfo->enable) {
      if (m_layer < enable.second.size()) {
        m_enable[enable.first] = enable.second[m_layer];
        enable.second.erase(std::next(enable.second.begin(), m_layer));
      }
    }
    m_moleculeInfo->layer.removeLayer(m_layer);
  }

  void undo() override
  {
    auto itVisible = m_moleculeInfo->visible.begin() + m_layer;
    m_moleculeInfo->visible.insert(itVisible, m_visible);
    auto itLocked = m_moleculeInfo->locked.begin() + m_layer;
    m_moleculeInfo->locked.insert(itLocked, m_locked);
    for (const auto& enable : m_enable) {
      auto itEnable = m_moleculeInfo->enable[enable.first].begin() + m_layer;
      m_moleculeInfo->enable[enable.first].insert(itEnable, enable.second);
    }
    m_moleculeInfo->layer.addLayer(m_layer);
  }

protected:
  shared_ptr<MoleculeInfo> m_moleculeInfo;
  size_t m_layer;

  bool m_visible;
  bool m_locked;
  map<QString, bool> m_enable;
};
} // namespace

const void* LayerManager::m_activeMolecule = nullptr;
map<const void*, shared_ptr<MoleculeInfo>> LayerManager::m_molToInfo;

LayerManager::LayerManager() : LayerManager("undef") {}
LayerManager::LayerManager(const QString& name) : m_name(name) {}

LayerManager::LayerManager(const void* mol, const QString& name) : m_name(name)
{
  auto it = m_molToInfo.find(mol);
  if (it == m_molToInfo.end()) {
    m_molToInfo[mol] = make_shared<MoleculeInfo>(new MoleculeInfo(mol, name));
  }
}

Layer& LayerManager::getMoleculeLayer()
{
  assert(m_activeMolecule != nullptr);
  return getMoleculeLayer(m_activeMolecule);
}

Layer& LayerManager::getMoleculeLayer(const void* mol)
{
  auto it = m_molToInfo.find(mol);
  if (it == m_molToInfo.end()) {
    m_molToInfo[mol] = make_shared<MoleculeInfo>(new MoleculeInfo(mol));
  }
  return m_molToInfo[mol]->layer;
}

Layer& LayerManager::getMoleculeLayer(const void* original, const void* copy)
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

void LayerManager::addMolecule(const void* mol)
{
  m_activeMolecule = mol;
  auto it = m_molToInfo.find(mol);
  if (it == m_molToInfo.end()) {
    m_molToInfo[mol] = make_shared<MoleculeInfo>(mol);
  }
}

void LayerManager::removeMolecule(const void* mol)
{
  auto it = m_molToInfo.begin();
  auto id = m_molToInfo[mol]->mol;
  while (it != m_molToInfo.end()) {
    if (id == it->second->mol) {
      it = m_molToInfo.erase(it);
    } else {
      ++it;
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

void LayerManager::addLayer(RWMolecule* rwmolecule)
{
  assert(m_activeMolecule != nullptr);
  assert(rwmolecule != nullptr);
  rwmolecule->undoStack().beginMacro(QObject::tr("Add Layer"));
  auto& molecule = m_molToInfo[m_activeMolecule];
  AddLayerCommand* comm = new AddLayerCommand(molecule);
  comm->setText(QObject::tr("Add Layer Info"));
  rwmolecule->undoStack().push(comm);
  rwmolecule->undoStack().endMacro();
}

void LayerManager::setActiveLayer(size_t layer, RWMolecule* rwmolecule)
{
  rwmolecule->undoStack().beginMacro(QObject::tr("Change Layer"));
  auto& molecule = m_molToInfo[m_activeMolecule];
  ActiveLayerCommand* comm = new ActiveLayerCommand(molecule, layer);
  comm->setText(QObject::tr("Change Layer"));
  rwmolecule->undoStack().push(comm);
  rwmolecule->undoStack().endMacro();
}

void LayerManager::removeLayer(size_t layer, RWMolecule* rwmolecule)
{
  assert(m_activeMolecule != nullptr);
  assert(rwmolecule != nullptr);
  rwmolecule->undoStack().beginMacro(QObject::tr("Remove Layer"));
  auto atoms = rwmolecule->molecule().getAtomsAtLayer(layer);
  for (const Index& atom : atoms) {
    rwmolecule->removeAtom(atom);
  }
  auto& molecule = m_molToInfo[m_activeMolecule];
  RemoveLayerCommand* comm = new RemoveLayerCommand(molecule, layer);
  comm->setText(QObject::tr("Remove Layer Info"));
  rwmolecule->undoStack().push(comm);
  rwmolecule->undoStack().endMacro();
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

Array<std::pair<size_t, QString>> LayerManager::activeMoleculeNames() const
{
  if (m_activeMolecule == nullptr) {
    return Array<std::pair<size_t, QString>>();
  }
  auto& molecule = m_molToInfo[m_activeMolecule];
  size_t qttyLayer = molecule->layer.maxLayer() + 1;
  vector<set<QString>> active(qttyLayer, set<QString>());
  for (const auto& names : molecule->enable) {
    for (size_t i = 0; i < names.second.size(); ++i) {
      if (names.second[i]) {
        active[i].insert(names.first);
      }
    }
  }

  Array<std::pair<size_t, QString>> result;
  size_t layer = 0;
  for (const auto& names : active) {
    result.push_back(std::make_pair(layer, QObject::tr("Layer")));
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
  size_t qttyLayers = molecule->layer.maxLayer() + 1;
  molecule->visible[layer] = !molecule->visible[layer];
}

void LayerManager::flipLocked(size_t layer)
{
  auto& molecule = m_molToInfo[m_activeMolecule];
  size_t qttyLayers = molecule->layer.maxLayer() + 1;
  molecule->locked[layer] = !molecule->locked[layer];
}

bool LayerManager::activeLayerLocked()
{
  assert(m_activeMolecule != nullptr);
  auto& molecule = m_molToInfo[m_activeMolecule];
  size_t active = molecule->layer.activeLayer();
  return molecule->locked[active];
}

size_t LayerManager::layerCount() const
{
  return m_molToInfo[m_activeMolecule]->layer.maxLayer() + 1;
}

} // namespace QtGui
} // namespace Avogadro
