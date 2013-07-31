/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2012-13 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "glwidget.h"

#include "qttextrenderstrategy.h"

#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/sceneplugin.h>
#include <avogadro/qtgui/scenepluginmodel.h>
#include <avogadro/qtgui/toolplugin.h>

#include <avogadro/rendering/camera.h>

#include <QtGui/QAction>
#include <QtGui/QKeyEvent>
#include <QtGui/QMouseEvent>
#include <QtGui/QWheelEvent>

#include <QtCore/QDebug>

namespace Avogadro {
namespace QtOpenGL {

GLWidget::GLWidget(QWidget *parent_)
  : QGLWidget(parent_),
    m_activeTool(NULL),
    m_defaultTool(NULL)
{
  setFocusPolicy(Qt::ClickFocus);
  connect(&m_scenePlugins,
          SIGNAL(pluginStateChanged(Avogadro::QtGui::ScenePlugin*)),
          SLOT(updateScene()));
  m_renderer.setTextRenderStrategy(new QtTextRenderStrategy);
}

GLWidget::~GLWidget()
{
}

void GLWidget::setMolecule(QtGui::Molecule *mol)
{
  clearScene();
  if (m_molecule)
    disconnect(m_molecule, 0, 0, 0);
  m_molecule = mol;
  foreach (QtGui::ToolPlugin *tool, m_tools)
    tool->setMolecule(m_molecule);
  connect(m_molecule, SIGNAL(changed(unsigned int)), SLOT(updateScene()));
}

QtGui::Molecule * GLWidget::molecule()
{
  return m_molecule;
}

const QtGui::Molecule * GLWidget::molecule() const
{
  return m_molecule;
}

void GLWidget::updateScene()
{
  // Build up the scene with the scene plugins, creating the appropriate nodes.
  if (m_molecule) {
    Rendering::GroupNode &node = m_renderer.scene().rootNode();
    node.clear();
    Rendering::GroupNode *moleculeNode = new Rendering::GroupNode(&node);

    foreach (QtGui::ScenePlugin *scenePlugin,
             m_scenePlugins.activeScenePlugins()) {
      Rendering::GroupNode *engineNode = new Rendering::GroupNode(moleculeNode);
      scenePlugin->process(*m_molecule, *engineNode);
    }
    m_renderer.resetGeometry();
    update();
  }
}

void GLWidget::clearScene()
{
  m_renderer.scene().clear();
}

void GLWidget::resetCamera()
{
  m_renderer.resetCamera();
  update();
}

void GLWidget::resetGeometry()
{
  m_renderer.resetGeometry();
}

void GLWidget::setTools(const QList<QtGui::ToolPlugin *> &toolList)
{
  foreach (QtGui::ToolPlugin *tool, toolList)
    addTool(tool);
}

void GLWidget::addTool(QtGui::ToolPlugin *tool)
{
  if (m_tools.contains(tool))
    return;

  tool->setParent(this);
  tool->setGLWidget(this);
  tool->setMolecule(m_molecule);
  m_tools << tool;
}

void GLWidget::setActiveTool(const QString &name)
{
  foreach (QtGui::ToolPlugin *tool, m_tools) {
    QAction *toolAction = tool->activateAction();
    if (tool->name() == name
        || (toolAction && toolAction->text() == name)) {
      setActiveTool(tool);
      return;
    }
  }
}

void GLWidget::setActiveTool(QtGui::ToolPlugin *tool)
{
  if (tool)
    addTool(tool);
  m_activeTool = tool;
}

void GLWidget::setDefaultTool(const QString &name)
{
  foreach (QtGui::ToolPlugin *tool, m_tools) {
    QAction *toolAction = tool->activateAction();
    if (tool->name() == name
        || (toolAction && toolAction->text() == name)) {
      setDefaultTool(tool);
      return;
    }
  }
}

void GLWidget::setDefaultTool(QtGui::ToolPlugin *tool)
{
  if (tool)
    addTool(tool);
  m_defaultTool = tool;
}

void GLWidget::initializeGL()
{
  m_renderer.initialize();
  if (!m_renderer.isValid()) {
    qDebug() << "Error initializing: " << m_renderer.error().c_str();
  }
}

void GLWidget::resizeGL(int width_, int height_)
{
  m_renderer.resize(width_, height_);
}

void GLWidget::paintGL()
{
  m_renderer.render();
}

void GLWidget::mouseDoubleClickEvent(QMouseEvent *e)
{
  e->ignore();

  if (m_activeTool)
    m_activeTool->mouseDoubleClickEvent(e);

  if (m_defaultTool && !e->isAccepted())
    m_defaultTool->mouseDoubleClickEvent(e);

  if (!e->isAccepted())
    QGLWidget::mouseDoubleClickEvent(e);
}


void GLWidget::mousePressEvent(QMouseEvent *e)
{
  e->ignore();

  if (m_activeTool)
    m_activeTool->mousePressEvent(e);

  if (m_defaultTool && !e->isAccepted())
    m_defaultTool->mousePressEvent(e);

  if (!e->isAccepted())
    QGLWidget::mousePressEvent(e);
}

void GLWidget::mouseMoveEvent(QMouseEvent *e)
{
  e->ignore();

  if (m_activeTool)
    m_activeTool->mouseMoveEvent(e);

  if (m_defaultTool && !e->isAccepted())
    m_defaultTool->mouseMoveEvent(e);

  if (!e->isAccepted())
    QGLWidget::mouseMoveEvent(e);
}

void GLWidget::mouseReleaseEvent(QMouseEvent *e)
{
  e->ignore();

  if (m_activeTool)
    m_activeTool->mouseReleaseEvent(e);

  if (m_defaultTool && !e->isAccepted())
    m_defaultTool->mouseReleaseEvent(e);

  if (!e->isAccepted())
    QGLWidget::mouseReleaseEvent(e);
}

void GLWidget::wheelEvent(QWheelEvent *e)
{
  e->ignore();

  if (m_activeTool)
    m_activeTool->wheelEvent(e);

  if (m_defaultTool && !e->isAccepted())
    m_defaultTool->wheelEvent(e);

  if (!e->isAccepted())
    QGLWidget::wheelEvent(e);
}

void GLWidget::keyPressEvent(QKeyEvent *e)
{
  e->ignore();

  if (m_activeTool)
    m_activeTool->keyPressEvent(e);

  if (m_defaultTool && !e->isAccepted())
    m_defaultTool->keyPressEvent(e);

  if (!e->isAccepted())
    QGLWidget::keyPressEvent(e);
}

void GLWidget::keyReleaseEvent(QKeyEvent *e)
{
  e->ignore();

  if (m_activeTool)
    m_activeTool->keyReleaseEvent(e);

  if (m_defaultTool && !e->isAccepted())
    m_defaultTool->keyReleaseEvent(e);

  if (!e->isAccepted())
    QGLWidget::keyReleaseEvent(e);
}

} // End QtOpenGL namespace
} // End Avogadro namespace
