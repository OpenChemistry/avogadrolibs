/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "rwlayermanager.h"
#include "rwmolecule.h"

#include <QtCore/QObject>
#include <QtWidgets/QUndoCommand>
#include <QtWidgets/QUndoStack>
#include <cassert>

namespace Avogadro {
namespace QtGui {

using Core::Array;
using Core::Layer;
using Core::MoleculeInfo;
using std::map;
using std::shared_ptr;
using std::string;

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
  map<string, bool> m_enable;
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
  map<string, bool> m_enable;
};
} // namespace

void RWLayerManager::removeLayer(size_t layer, RWMolecule* rwmolecule)
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

void RWLayerManager::addLayer(RWMolecule* rwmolecule)
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

void RWLayerManager::setActiveLayer(size_t layer, RWMolecule* rwmolecule)
{
  rwmolecule->undoStack().beginMacro(QObject::tr("Change Layer"));
  auto& molecule = m_molToInfo[m_activeMolecule];
  ActiveLayerCommand* comm = new ActiveLayerCommand(molecule, layer);
  comm->setText(QObject::tr("Change Layer"));
  rwmolecule->undoStack().push(comm);
  rwmolecule->undoStack().endMacro();
}

} // namespace QtGui
} // namespace Avogadro
