/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "rwlayermanager.h"
#include "rwmolecule.h"

#include <avogadro/core/molecule.h>

#include <QObject>
#include <QUndoCommand>
#include <QUndoStack>
#include <cassert>

namespace Avogadro::QtGui {

using Core::Array;
using Core::LayerData;
using Core::MoleculeInfo;
using std::map;
using std::set;
using std::shared_ptr;
using std::string;
using std::vector;

namespace {
class AddLayerCommand : public QUndoCommand
{
public:
  AddLayerCommand(shared_ptr<MoleculeInfo> mol)
    : QUndoCommand(QObject::tr("Modify Layers")), m_moleculeInfo(mol)
  {
    m_visible = true;
    m_locked = false;

    const auto activeLayer = m_moleculeInfo->layer.activeLayer();
    // A new layer inherits the active layer's state. The per-plugin vectors
    // are grown independently of Core::Layer -- a plugin that has never been
    // asked about this layer has a shorter vector -- so skip those rather than
    // indexing past the end. RemoveLayerCommand::redo() already does this.
    for (const auto& names : m_moleculeInfo->enable) {
      if (activeLayer < names.second.size())
        m_enable[names.first] = names.second[activeLayer];
    }
    for (const auto& names : m_moleculeInfo->settings) {
      if (activeLayer < names.second.size() &&
          names.second[activeLayer] != nullptr)
        m_settings[names.first] = names.second[activeLayer];
    }
  }

  void redo() override
  {
    m_moleculeInfo->visible.push_back(m_visible);
    m_moleculeInfo->locked.push_back(m_locked);

    // it's confusing to create an empty layer
    //  .. so we just create a layer that matches the active layer
    for (const auto& enable : m_enable) {
      m_moleculeInfo->enable[enable.first].push_back(enable.second);
    }
    for (const auto& settings : m_settings) {
      if (settings.second == nullptr)
        continue;
      // A new layer gets its own copy of the active layer's settings.
      m_moleculeInfo->settings[settings.first].push_back(
        Core::LayerDataPtr(settings.second->clone()));
    }

    m_moleculeInfo->layer.addLayer();
  }

  void undo() override
  {
    if (m_moleculeInfo->visible.empty() || m_moleculeInfo->locked.empty())
      return;
    m_visible = m_moleculeInfo->visible.back();
    m_locked = m_moleculeInfo->locked.back();

    m_moleculeInfo->visible.pop_back();
    m_moleculeInfo->locked.pop_back();
    size_t qttyLayer = m_moleculeInfo->layer.layerCount();
    for (auto& enable : m_moleculeInfo->enable) {
      if (enable.second.size() == qttyLayer) {
        m_enable[enable.first] = enable.second[enable.second.size() - 1];
        enable.second.pop_back();
      }
    }

    for (auto& setting : m_moleculeInfo->settings) {
      if (setting.second.size() == qttyLayer) {
        m_settings[setting.first] = setting.second[setting.second.size() - 1];
        setting.second.pop_back();
      }
    }

    m_moleculeInfo->layer.removeLayer(m_moleculeInfo->layer.maxLayer());
  }

protected:
  shared_ptr<MoleculeInfo> m_moleculeInfo;
  map<string, bool> m_enable;
  map<string, Core::LayerDataPtr> m_settings;
  bool m_visible;
  bool m_locked;
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
  {
  }

  void redo() override
  {
    m_applied = false;
    if (m_layer >= m_moleculeInfo->visible.size() ||
        m_layer >= m_moleculeInfo->locked.size())
      return;

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

    for (auto& setting : m_moleculeInfo->settings) {
      if (m_layer < setting.second.size()) {
        m_settings[setting.first] = setting.second[m_layer];
        setting.second.erase(std::next(setting.second.begin(), m_layer));
      }
    }
    m_moleculeInfo->layer.removeLayer(m_layer);
    m_applied = true;
  }

  void undo() override
  {
    // redo() declined to remove anything, so there is nothing to put back and
    // m_visible / m_locked were never recorded.
    if (!m_applied)
      return;

    auto itVisible = m_moleculeInfo->visible.begin() + m_layer;
    m_moleculeInfo->visible.insert(itVisible, m_visible);
    auto itLocked = m_moleculeInfo->locked.begin() + m_layer;
    m_moleculeInfo->locked.insert(itLocked, m_locked);
    for (const auto& enable : m_enable) {
      auto itEnable = m_moleculeInfo->enable[enable.first].begin() + m_layer;
      m_moleculeInfo->enable[enable.first].insert(itEnable, enable.second);
    }
    for (const auto& setting : m_settings) {
      auto itSetting =
        m_moleculeInfo->settings[setting.first].begin() + m_layer;
      m_moleculeInfo->settings[setting.first].insert(itSetting, setting.second);
    }
    m_moleculeInfo->layer.addLayer(m_layer);
  }

protected:
  shared_ptr<MoleculeInfo> m_moleculeInfo;
  size_t m_layer;

  bool m_visible = true;
  bool m_locked = false;
  bool m_applied = false;
  map<string, Core::LayerDataPtr> m_settings;
  map<string, bool> m_enable;
};
} // namespace

void RWLayerManager::removeLayer(size_t layer, RWMolecule* rwmolecule)
{
  assert(rwmolecule != nullptr);
  rwmolecule->undoStack().beginMacro(QObject::tr("Remove Layer"));
  // Check before touching the molecule: removing the atoms and then bailing
  // out would leave the layer half removed.
  auto molecule = activeMoleculeInfo();
  if (molecule == nullptr) {
    rwmolecule->undoStack().endMacro();
    return;
  }
  auto atoms = rwmolecule->molecule().getAtomsAtLayer(layer);
  for (const Index& atom : atoms) {
    rwmolecule->removeAtom(atom);
  }
  auto* comm = new RemoveLayerCommand(molecule, layer);
  comm->setText(QObject::tr("Remove Layer Info"));
  rwmolecule->undoStack().push(comm);
  rwmolecule->undoStack().endMacro();
}

void RWLayerManager::addLayer(RWMolecule* rwmolecule)
{
  assert(rwmolecule != nullptr);
  rwmolecule->undoStack().beginMacro(QObject::tr("Add Layer"));
  auto molecule = activeMoleculeInfo();
  if (molecule == nullptr) {
    rwmolecule->undoStack().endMacro();
    return;
  }
  auto* comm = new AddLayerCommand(molecule);
  comm->setText(QObject::tr("Add Layer Info"));
  rwmolecule->undoStack().push(comm);
  rwmolecule->undoStack().endMacro();
}

void RWLayerManager::setActiveLayer(size_t layer, RWMolecule* rwmolecule)
{
  rwmolecule->undoStack().beginMacro(QObject::tr("Change Layer"));
  auto molecule = activeMoleculeInfo();
  if (molecule == nullptr) {
    rwmolecule->undoStack().endMacro();
    return;
  }
  auto* comm = new ActiveLayerCommand(molecule, layer);
  comm->setText(QObject::tr("Change Layer"));
  rwmolecule->undoStack().push(comm);
  rwmolecule->undoStack().endMacro();
}

bool RWLayerManager::visible(size_t layer) const
{
  auto molecule = activeMoleculeInfo();
  if (molecule == nullptr || layer >= molecule->visible.size())
    return true; // the default a fresh MoleculeInfo starts with
  return molecule->visible[layer];
}

bool RWLayerManager::locked(size_t layer) const
{
  auto molecule = activeMoleculeInfo();
  if (molecule == nullptr || layer >= molecule->locked.size())
    return false; // the default a fresh MoleculeInfo starts with
  return molecule->locked[layer];
}

void RWLayerManager::flipVisible(size_t layer)
{
  auto molecule = activeMoleculeInfo();
  if (molecule == nullptr || layer >= molecule->visible.size())
    return;
  molecule->visible[layer] = !molecule->visible[layer];
}

void RWLayerManager::flipLocked(size_t layer)
{
  auto molecule = activeMoleculeInfo();
  if (molecule == nullptr || layer >= molecule->locked.size())
    return;
  molecule->locked[layer] = !molecule->locked[layer];
}

void RWLayerManager::addMolecule(const Core::Molecule* mol)
{
  setActiveMolecule(mol);
}

Array<std::pair<size_t, string>> RWLayerManager::activeMoleculeNames() const
{
  auto molecule = activeMoleculeInfo();
  if (molecule == nullptr) {
    return Array<std::pair<size_t, string>>();
  }

  size_t qttyLayer = molecule->layer.layerCount();
  vector<set<string>> active(qttyLayer, set<string>());
  for (const auto& names : molecule->enable) {
    for (size_t i = 0; i < names.second.size(); ++i) {
      if (names.second[i]) {
        active[i].insert(names.first);
      }
    }
  }

  Array<std::pair<size_t, string>> result;
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

} // namespace Avogadro::QtGui
