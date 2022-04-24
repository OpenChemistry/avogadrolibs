/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "focus.h"

#include <avogadro/qtgui/molecule.h>
#include <avogadro/rendering/camera.h>

#include <QtWidgets/QAction>
#include <iostream>

namespace Avogadro {
namespace QtPlugins {

using Avogadro::QtGui::ExtensionPlugin;

Focus::Focus(QObject* parent_)
  : ExtensionPlugin(parent_),
    m_focusSelectionAction(new QAction(tr("Focus Selection"), this)),
    m_unfocusAction(new QAction(tr("Unfocus"), this))
{
  m_focusSelectionAction->setProperty("menu priority", 200);
  m_unfocusAction->setProperty("menu priority", 200);

  connect(m_focusSelectionAction, SIGNAL(triggered()), SLOT(focusSelection()));
  connect(m_unfocusAction, SIGNAL(triggered()), SLOT(unfocus()));
}

Focus::~Focus() {}

QList<QAction*> Focus::actions() const
{
  QList<QAction*> result;
  return result << m_focusSelectionAction << m_unfocusAction;
}

QStringList Focus::menuPath(QAction*) const
{
  return QStringList() << tr("&View");
}

void Focus::setMolecule(QtGui::Molecule* mol)
{
  m_molecule = mol;
}

void Focus::setCamera(Rendering::Camera* camera)
{
  m_camera = camera;
}

void Focus::setScene(Rendering::Scene* scene)
{
  m_scene = scene;
}

void Focus::newFocus(Eigen::Vector3f point)
{
  Eigen::Vector3f oldFocus = m_camera->focus();
  Eigen::Vector3f translation = oldFocus - point;
  m_camera->translate(translation);
  m_camera->setFocus(point);  
}

void Focus::focusSelection()
{
  if (!m_molecule || !m_camera)
    return;
  if (m_molecule->atomPositions3d().size() != m_molecule->atomCount())
    return;
  if (m_molecule->isSelectionEmpty())
    return;
  
  Eigen::Vector3f selectionCenter;
  int selectionSize = 0;
  for (Index i = 0; i < m_molecule->atomCount(); ++i)
  {
    if (m_molecule->atomSelected(i))
    {
      selectionCenter += m_molecule->atomPosition3d(i).cast<float>();
      ++selectionSize;
    }
  }
  selectionCenter /= selectionSize;
  
  newFocus(selectionCenter);
}

void Focus::unfocus()
{
  if (!m_camera || !m_scene)
    return;
  
  newFocus(m_scene->center());
}

} // namespace QtPlugins
} // namespace Avogadro
