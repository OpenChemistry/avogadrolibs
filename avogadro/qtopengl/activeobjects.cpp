/* This source file is part of the Avogadro project.
   It is released under the 3-Clause BSD License, see "LICENSE". */

#include "activeobjects.h"

#include "glwidget.h"

#include <avogadro/qtgui/molecule.h>

namespace Avogadro {
namespace QtOpenGL {

ActiveObjects::ActiveObjects() = default;
ActiveObjects::~ActiveObjects() = default;

ActiveObjects& ActiveObjects::instance()
{
  static ActiveObjects singletonInstance;
  return singletonInstance;
}

GLWidget* ActiveObjects::activeGLWidget() const
{
  return m_glWidget;
}

QWidget* ActiveObjects::activeWidget() const
{
  return m_widget;
}

QtGui::Molecule* ActiveObjects::activeMolecule() const
{
  return m_molecule;
}

void ActiveObjects::setActiveGLWidget(GLWidget* glWidget)
{
  if (m_glWidget != glWidget) {
    m_widget = nullptr;
    m_glWidget = glWidget;
    emit activeGLWidgetChanged(m_glWidget);
    setActiveWidget(glWidget);
  }
}

void ActiveObjects::setActiveWidget(QWidget* widget)
{
  if (m_widget != widget) {
    m_glWidget = nullptr;
    m_widget = widget;
    emit activeWidgetChanged(widget);
  }
}

void ActiveObjects::setActiveMolecule(QtGui::Molecule* molecule)
{
  if (m_molecule != molecule) {
    m_molecule = molecule;
    emit activeMoleculeChanged(molecule);
  }
}

} // namespace QtOpenGL
} // namespace Avogadro
