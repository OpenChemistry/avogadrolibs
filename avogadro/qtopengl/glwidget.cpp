/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "glwidget.h"

#include "qttextrenderstrategy.h"

#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/rwmolecule.h>
#include <avogadro/qtgui/sceneplugin.h>
#include <avogadro/qtgui/scenepluginmodel.h>
#include <avogadro/qtgui/toolplugin.h>

#include <avogadro/rendering/camera.h>

#include <QAction>
#include <QtCore/QTimer>
#include <QtGui/QImage>
#include <QtGui/QKeyEvent>
#include <QtGui/QMouseEvent>
#include <QtGui/QWheelEvent>
#include <QtGui/QWindow>
#include <QtWidgets/QApplication>
#include <QtWidgets/QVBoxLayout>

namespace Avogadro::QtOpenGL {

#ifdef Q_OS_WASM
class WasmOpenGLWindow : public QOpenGLWindow
{
public:
  explicit WasmOpenGLWindow(GLWidget* owner)
    : QOpenGLWindow(QOpenGLWindow::NoPartialUpdate), m_owner(owner)
  {
  }

protected:
  void initializeGL() override { m_owner->initializeGL(); }
  void resizeGL(int width, int height) override
  {
    m_owner->resizeGL(width, height);
  }
  void paintGL() override { m_owner->paintGL(); }

  void mouseDoubleClickEvent(QMouseEvent* e) override
  {
    m_owner->mouseDoubleClickEvent(e);
    if (!e->isAccepted())
      QOpenGLWindow::mouseDoubleClickEvent(e);
  }
  void mousePressEvent(QMouseEvent* e) override
  {
    m_owner->mousePressEvent(e);
    if (!e->isAccepted())
      QOpenGLWindow::mousePressEvent(e);
  }
  void mouseMoveEvent(QMouseEvent* e) override
  {
    m_owner->mouseMoveEvent(e);
    if (!e->isAccepted())
      QOpenGLWindow::mouseMoveEvent(e);
  }
  void mouseReleaseEvent(QMouseEvent* e) override
  {
    m_owner->mouseReleaseEvent(e);
    if (!e->isAccepted())
      QOpenGLWindow::mouseReleaseEvent(e);
  }
  void wheelEvent(QWheelEvent* e) override
  {
    m_owner->wheelEvent(e);
    if (!e->isAccepted())
      QOpenGLWindow::wheelEvent(e);
  }
  void keyPressEvent(QKeyEvent* e) override
  {
    m_owner->keyPressEvent(e);
    if (!e->isAccepted())
      QOpenGLWindow::keyPressEvent(e);
  }
  void keyReleaseEvent(QKeyEvent* e) override
  {
    m_owner->keyReleaseEvent(e);
    if (!e->isAccepted())
      QOpenGLWindow::keyReleaseEvent(e);
  }

private:
  GLWidget* m_owner;
};
#endif

GLWidget::GLWidget(QWidget* p)
#ifdef Q_OS_WASM
  : QWidget(p), m_activeTool(nullptr), m_defaultTool(nullptr),
    m_renderTimer(nullptr), m_glWindow(new WasmOpenGLWindow(this)),
    m_glContainer(nullptr)
#else
  : QOpenGLWidget(p), m_activeTool(nullptr), m_defaultTool(nullptr),
    m_renderTimer(nullptr)
#endif
{
#ifdef Q_OS_WASM
  auto* layout = new QVBoxLayout(this);
  layout->setContentsMargins(0, 0, 0, 0);
  layout->setSpacing(0);
  m_glContainer = QWidget::createWindowContainer(m_glWindow, this);
  m_glContainer->setFocusPolicy(Qt::ClickFocus);
  layout->addWidget(m_glContainer);
#endif
  setFocusPolicy(Qt::ClickFocus);
  connect(&m_scenePlugins, &QtGui::ScenePluginModel::pluginStateChanged, this,
          &GLWidget::updateScene);
  connect(&m_scenePlugins, &QtGui::ScenePluginModel::pluginConfigChanged, this,
          &GLWidget::updateScene);
  m_renderer.setTextRenderStrategy(new QtTextRenderStrategy);
}

GLWidget::~GLWidget() {}

#ifdef Q_OS_WASM
QImage GLWidget::grabFramebuffer()
{
  return m_glWindow ? m_glWindow->grabFramebuffer() : QImage();
}
#endif

void GLWidget::setMolecule(QtGui::Molecule* mol)
{
  clearScene();
  if (m_molecule)
    disconnect(m_molecule, nullptr, nullptr, nullptr);
  m_molecule = mol;
  foreach (QtGui::ToolPlugin* tool, m_tools)
    tool->setMolecule(m_molecule);

  if (m_molecule != nullptr) {
    // update properties like dipole rendering
    QTimer::singleShot(500, m_molecule, &QtGui::Molecule::update);
  }

  connect(m_molecule, &QtGui::Molecule::changed, this, &GLWidget::updateScene);
}

QtGui::Molecule* GLWidget::molecule()
{
  return m_molecule;
}

const QtGui::Molecule* GLWidget::molecule() const
{
  return m_molecule;
}

void GLWidget::updateMolecule()
{
  if (m_molecule != nullptr) {
    // update properties like dipole rendering
    QTimer::singleShot(500, m_molecule, &QtGui::Molecule::update);
  }
}

void GLWidget::updateScene()
{
  // Build up the scene with the scene plugins, creating the appropriate nodes.
  QtGui::Molecule* mol = m_molecule;
  if (!mol)
    mol = new QtGui::Molecule(this);
  if (mol) {
    Rendering::GroupNode& node = m_renderer.scene().rootNode();
    node.clear();
    auto* moleculeNode = new Rendering::GroupNode(&node);

    foreach (QtGui::ScenePlugin* scenePlugin,
             m_scenePlugins.activeScenePlugins()) {
      auto* engineNode = new Rendering::GroupNode(moleculeNode);
      scenePlugin->process(*mol, *engineNode);
    }

    // Let the tools perform any drawing they need to do.
    foreach (QtGui::ToolPlugin* tool, m_tools) {
      auto* toolNode = new Rendering::GroupNode(moleculeNode);
      tool->draw(*toolNode);
    }

    m_renderer.resetGeometry();
#ifdef Q_OS_WASM
    if (m_glWindow)
      m_glWindow->requestUpdate();
    else
      update();
#else
    update();
#endif
  }
  if (mol != m_molecule)
    delete mol;
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

void GLWidget::setTools(const QList<QtGui::ToolPlugin*>& toolList)
{
  foreach (QtGui::ToolPlugin* tool, toolList)
    addTool(tool);
}

void GLWidget::addTool(QtGui::ToolPlugin* tool)
{
  if (m_tools.contains(tool))
    return;

  connect(tool, &QtGui::ToolPlugin::updateRequested, this,
          &GLWidget::requestUpdate);
  tool->setParent(this);
  tool->setGLWidget(this);
  tool->setActiveWidget(this);
  tool->setMolecule(m_molecule);
  tool->setGLRenderer(&m_renderer);
  m_tools << tool;
}

void GLWidget::setActiveTool(const QString& name)
{
  foreach (QtGui::ToolPlugin* tool, m_tools) {
    QAction* toolAction = tool->activateAction();
    if (tool->objectName() == name ||
        (toolAction && toolAction->text() == name)) {
      setActiveTool(tool);
      return;
    }
  }
}

void GLWidget::setActiveTool(QtGui::ToolPlugin* tool)
{
  if (tool == m_activeTool)
    return;

  if (m_activeTool && m_activeTool != m_defaultTool) {
    disconnect(m_activeTool, &QtGui::ToolPlugin::drawablesChanged, this,
               &GLWidget::updateScene);
  }

  if (tool)
    addTool(tool);
  m_activeTool = tool;

  if (m_activeTool && m_activeTool != m_defaultTool) {
    connect(m_activeTool, &QtGui::ToolPlugin::drawablesChanged, this,
            &GLWidget::updateScene);
  }
}

void GLWidget::setDefaultTool(const QString& name)
{
  foreach (QtGui::ToolPlugin* tool, m_tools) {
    QAction* toolAction = tool->activateAction();

    if (tool->objectName() == name || tool->name() == name ||
        (toolAction && toolAction->text() == name)) {
      setDefaultTool(tool);
      return;
    }
  }
}

void GLWidget::setDefaultTool(QtGui::ToolPlugin* tool)
{
  if (tool == m_defaultTool)
    return;

  if (m_defaultTool && m_activeTool != m_defaultTool) {
    disconnect(m_defaultTool, &QtGui::ToolPlugin::drawablesChanged, this,
               &GLWidget::updateScene);
  }

  if (tool)
    addTool(tool);
  m_defaultTool = tool;

  if (m_defaultTool && m_activeTool != m_defaultTool) {
    connect(m_defaultTool, &QtGui::ToolPlugin::drawablesChanged, this,
            &GLWidget::updateScene);
  }
}

void GLWidget::requestUpdate()
{
  if (!m_renderTimer) {
    m_renderTimer = new QTimer(this);
    connect(m_renderTimer, &QTimer::timeout, this, &GLWidget::updateTimeout);
    m_renderTimer->setSingleShot(1000 / 30); // 30 fps
    m_renderTimer->start();
  }
}

void GLWidget::updateTimeout()
{
  if (m_renderTimer) {
    m_renderTimer->deleteLater();
    m_renderTimer = nullptr;
  }
#ifdef Q_OS_WASM
  if (m_glWindow)
    m_glWindow->requestUpdate();
  else
    update();
#else
  update();
#endif
}

void GLWidget::initializeGL()
{
  m_renderer.initialize();
  if (!m_renderer.isValid())
    emit rendererInvalid();
}

void GLWidget::resizeGL(int width_, int height_)
{
#ifdef Q_OS_WASM
  float pixelRatio = m_glWindow ? m_glWindow->devicePixelRatio() : 1.0f;
#else
  float pixelRatio = window()->windowHandle()->devicePixelRatio();
#endif
  m_renderer.setPixelRatio(pixelRatio);
  m_renderer.resize(width_, height_);
}

void GLWidget::paintGL()
{
  m_renderer.render();
}

void GLWidget::mouseDoubleClickEvent(QMouseEvent* e)
{
  e->ignore();

  if (m_activeTool)
    m_activeTool->mouseDoubleClickEvent(e);

  if (m_defaultTool && !e->isAccepted())
    m_defaultTool->mouseDoubleClickEvent(e);

  if (!e->isAccepted()) {
#ifdef Q_OS_WASM
    QWidget::mouseDoubleClickEvent(e);
#else
    QOpenGLWidget::mouseDoubleClickEvent(e);
#endif
  }
}

void GLWidget::mousePressEvent(QMouseEvent* e)
{
  e->ignore();

  if (m_activeTool)
    m_activeTool->mousePressEvent(e);

  if (m_defaultTool && !e->isAccepted())
    m_defaultTool->mousePressEvent(e);

  if (!e->isAccepted()) {
#ifdef Q_OS_WASM
    QWidget::mousePressEvent(e);
#else
    QOpenGLWidget::mousePressEvent(e);
#endif
  }
}

void GLWidget::mouseMoveEvent(QMouseEvent* e)
{
  e->ignore();

  if (m_activeTool)
    m_activeTool->mouseMoveEvent(e);

  if (m_defaultTool && !e->isAccepted())
    m_defaultTool->mouseMoveEvent(e);

  if (!e->isAccepted()) {
#ifdef Q_OS_WASM
    QWidget::mouseMoveEvent(e);
#else
    QOpenGLWidget::mouseMoveEvent(e);
#endif
  }
}

void GLWidget::mouseReleaseEvent(QMouseEvent* e)
{
  e->ignore();

  if (m_activeTool)
    m_activeTool->mouseReleaseEvent(e);

  if (m_defaultTool && !e->isAccepted())
    m_defaultTool->mouseReleaseEvent(e);

  if (!e->isAccepted()) {
#ifdef Q_OS_WASM
    QWidget::mouseReleaseEvent(e);
#else
    QOpenGLWidget::mouseReleaseEvent(e);
#endif
  }
}

void GLWidget::wheelEvent(QWheelEvent* e)
{
  e->ignore();

  if (m_activeTool)
    m_activeTool->wheelEvent(e);

  if (m_defaultTool && !e->isAccepted())
    m_defaultTool->wheelEvent(e);

  if (!e->isAccepted()) {
#ifdef Q_OS_WASM
    QWidget::wheelEvent(e);
#else
    QOpenGLWidget::wheelEvent(e);
#endif
  }
}

void GLWidget::keyPressEvent(QKeyEvent* e)
{
  e->ignore();

  if (m_activeTool)
    m_activeTool->keyPressEvent(e);

  if (m_defaultTool && !e->isAccepted())
    m_defaultTool->keyPressEvent(e);

  if (!e->isAccepted()) {
#ifdef Q_OS_WASM
    QWidget::keyPressEvent(e);
#else
    QOpenGLWidget::keyPressEvent(e);
#endif
  }
}

void GLWidget::keyReleaseEvent(QKeyEvent* e)
{
  e->ignore();

  if (m_activeTool)
    m_activeTool->keyReleaseEvent(e);

  if (m_defaultTool && !e->isAccepted())
    m_defaultTool->keyReleaseEvent(e);

  if (!e->isAccepted()) {
#ifdef Q_OS_WASM
    QWidget::keyReleaseEvent(e);
#else
    QOpenGLWidget::keyReleaseEvent(e);
#endif
  }
}

} // namespace Avogadro::QtOpenGL
