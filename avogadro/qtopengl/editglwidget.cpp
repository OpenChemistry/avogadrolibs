/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2014 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "editglwidget.h"

#include "qttextrenderstrategy.h"

#include <avogadro/qtgui/rwmolecule.h>
#include <avogadro/qtgui/sceneplugin.h>
#include <avogadro/qtgui/scenepluginmodel.h>
#include <avogadro/qtgui/toolplugin.h>

#include <avogadro/rendering/camera.h>

#include <QtWidgets/QAction>
#include <QtGui/QKeyEvent>
#include <QtGui/QMouseEvent>
#include <QtGui/QWheelEvent>

namespace Avogadro {
namespace QtOpenGL {

EditGLWidget::EditGLWidget(QWidget *parent_)
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

EditGLWidget::~EditGLWidget()
{
}

void EditGLWidget::setMolecule(QtGui::RWMolecule *mol)
{
  clearScene();
  if (m_molecule)
    disconnect(m_molecule, 0, 0, 0);
  m_molecule = mol;
  foreach (QtGui::ToolPlugin *tool, m_tools)
    tool->setEditMolecule(m_molecule);
  connect(m_molecule, SIGNAL(changed(unsigned int)), SLOT(updateScene()));
  if (m_molecule)
    m_molecule->setInteractive(true);
}

QtGui::RWMolecule * EditGLWidget::molecule()
{
  return m_molecule;
}

const QtGui::RWMolecule * EditGLWidget::molecule() const
{
  return m_molecule;
}

void EditGLWidget::updateScene()
{
  // Build up the scene with the scene plugins, creating the appropriate nodes.
  QtGui::RWMolecule *mol = m_molecule;
  if (!mol)
    mol = new QtGui::RWMolecule(this);
  if (mol) {
    Rendering::GroupNode &node = m_renderer.scene().rootNode();
    node.clear();
    Rendering::GroupNode *moleculeNode = new Rendering::GroupNode(&node);

    foreach (QtGui::ScenePlugin *scenePlugin,
             m_scenePlugins.activeScenePlugins()) {
      Rendering::GroupNode *engineNode = new Rendering::GroupNode(moleculeNode);
      scenePlugin->processEditable(*mol, *engineNode);
    }

    // Let the tools perform any drawing they need to do.
    if (m_activeTool) {
      Rendering::GroupNode *toolNode = new Rendering::GroupNode(moleculeNode);
      m_activeTool->draw(*toolNode);
    }

    if (m_defaultTool) {
      Rendering::GroupNode *toolNode = new Rendering::GroupNode(moleculeNode);
      m_defaultTool->draw(*toolNode);
    }

    m_renderer.resetGeometry();
    updateGL();
  }
  if (mol != m_molecule)
    delete mol;
}

void EditGLWidget::clearScene()
{
  m_renderer.scene().clear();
}

void EditGLWidget::resetCamera()
{
  m_renderer.resetCamera();
  updateGL();
}

void EditGLWidget::resetGeometry()
{
  m_renderer.resetGeometry();
}

void EditGLWidget::setTools(const QList<QtGui::ToolPlugin *> &toolList)
{
  foreach (QtGui::ToolPlugin *tool, toolList)
    addTool(tool);
}

void EditGLWidget::addTool(QtGui::ToolPlugin *tool)
{
  if (m_tools.contains(tool))
    return;

  connect(tool, SIGNAL(updateRequested()), SLOT(updateGL()));
  tool->setParent(this);
  //tool->setGLWidget(this);
  tool->setEditMolecule(m_molecule);
  tool->setGLRenderer(&m_renderer);
  m_tools << tool;
}

void EditGLWidget::setActiveTool(const QString &name)
{
  foreach (QtGui::ToolPlugin *tool, m_tools) {
    QAction *toolAction = tool->activateAction();
    if (tool->objectName() == name
        || (toolAction && toolAction->text() == name)) {
      setActiveTool(tool);
      return;
    }
  }
}

void EditGLWidget::setActiveTool(QtGui::ToolPlugin *tool)
{
  if (tool == m_activeTool)
    return;

  if (m_activeTool && m_activeTool != m_defaultTool) {
    disconnect(m_activeTool, SIGNAL(drawablesChanged()),
               this, SLOT(updateScene()));
  }

  if (tool)
    addTool(tool);
  m_activeTool = tool;

  if (m_activeTool && m_activeTool != m_defaultTool) {
    connect(m_activeTool, SIGNAL(drawablesChanged()),
            this, SLOT(updateScene()));
  }
}

void EditGLWidget::setDefaultTool(const QString &name)
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

void EditGLWidget::setDefaultTool(QtGui::ToolPlugin *tool)
{
  if (tool == m_defaultTool)
    return;

  if (m_defaultTool && m_activeTool != m_defaultTool) {
    disconnect(m_defaultTool, SIGNAL(drawablesChanged()),
               this, SLOT(updateScene()));
  }

  if (tool)
    addTool(tool);
  m_defaultTool = tool;

  if (m_defaultTool && m_activeTool != m_defaultTool) {
    connect(m_defaultTool, SIGNAL(drawablesChanged()),
            this, SLOT(updateScene()));
  }
}

void EditGLWidget::initializeGL()
{
  m_renderer.initialize();
  if (!m_renderer.isValid())
    emit rendererInvalid();
}

void EditGLWidget::resizeGL(int width_, int height_)
{
  m_renderer.resize(width_, height_);
}

void EditGLWidget::paintGL()
{
  m_renderer.render();
}

void EditGLWidget::mouseDoubleClickEvent(QMouseEvent *e)
{
  e->ignore();

  if (m_activeTool)
    m_activeTool->mouseDoubleClickEvent(e);

  if (m_defaultTool && !e->isAccepted())
    m_defaultTool->mouseDoubleClickEvent(e);

  if (!e->isAccepted())
    QGLWidget::mouseDoubleClickEvent(e);
}


void EditGLWidget::mousePressEvent(QMouseEvent *e)
{
  e->ignore();

  if (m_activeTool)
    m_activeTool->mousePressEvent(e);

  if (m_defaultTool && !e->isAccepted())
    m_defaultTool->mousePressEvent(e);

  if (!e->isAccepted())
    QGLWidget::mousePressEvent(e);
}

void EditGLWidget::mouseMoveEvent(QMouseEvent *e)
{
  e->ignore();

  if (m_activeTool)
    m_activeTool->mouseMoveEvent(e);

  if (m_defaultTool && !e->isAccepted())
    m_defaultTool->mouseMoveEvent(e);

  if (!e->isAccepted())
    QGLWidget::mouseMoveEvent(e);
}

void EditGLWidget::mouseReleaseEvent(QMouseEvent *e)
{
  e->ignore();

  if (m_activeTool)
    m_activeTool->mouseReleaseEvent(e);

  if (m_defaultTool && !e->isAccepted())
    m_defaultTool->mouseReleaseEvent(e);

  if (!e->isAccepted())
    QGLWidget::mouseReleaseEvent(e);
}

void EditGLWidget::wheelEvent(QWheelEvent *e)
{
  e->ignore();

  if (m_activeTool)
    m_activeTool->wheelEvent(e);

  if (m_defaultTool && !e->isAccepted())
    m_defaultTool->wheelEvent(e);

  if (!e->isAccepted())
    QGLWidget::wheelEvent(e);
}

void EditGLWidget::keyPressEvent(QKeyEvent *e)
{
  e->ignore();

  if (m_activeTool)
    m_activeTool->keyPressEvent(e);

  if (m_defaultTool && !e->isAccepted())
    m_defaultTool->keyPressEvent(e);

  if (!e->isAccepted())
    QGLWidget::keyPressEvent(e);
}

void EditGLWidget::keyReleaseEvent(QKeyEvent *e)
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
