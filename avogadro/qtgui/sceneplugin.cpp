/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "sceneplugin.h"

#ifdef QTGUI_HAS_RENDERING
#include <avogadro/rendering/groupnode.h>
#endif

namespace Avogadro::QtGui {

ScenePlugin::ScenePlugin(QObject* parent_) : QObject(parent_) {}

ScenePlugin::~ScenePlugin() {}

void ScenePlugin::process(const QtGui::Molecule&, Rendering::GroupNode&) {}

void ScenePlugin::processEditable(const RWMolecule&, Rendering::GroupNode&) {}

void ScenePlugin::updateCoordinates(const QtGui::Molecule& molecule,
                                    Rendering::GroupNode& node)
{
#ifdef QTGUI_HAS_RENDERING
  // Keep the node itself: plugins may hold a pointer to it.
  node.clear();
  node.clearUI();
#endif
  process(molecule, node);
}

QWidget* ScenePlugin::setupWidget()
{
  return nullptr;
}

bool ScenePlugin::isEnabled() const
{
  return m_layerManager.isEnabled();
}

bool ScenePlugin::isActiveLayerEnabled() const
{
  return m_layerManager.isActiveLayerEnabled();
}

void ScenePlugin::setEnabled(bool enable)
{
  m_layerManager.setEnabled(enable);
}

} // namespace Avogadro::QtGui
