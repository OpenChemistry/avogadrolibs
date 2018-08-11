/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "activeobjects.h"

#include "glwidget.h"

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

void ActiveObjects::setActiveGLWidget(GLWidget* glWidget)
{
  m_glWidget = glWidget;
}

} // End QtOpenGL namespace
} // End Avogadro namespace