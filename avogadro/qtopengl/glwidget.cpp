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
#include <QColor>
#include <QOpenGLContext>
#include <QOpenGLFramebufferObject>
#include <QOpenGLFramebufferObjectFormat>
#include <QOpenGLFunctions>
#include <QPainter>
#include <QtCore/QSettings>
#include <QtCore/QTimer>
#include <QtGui/QKeyEvent>
#include <QtGui/QMouseEvent>
#include <QtGui/QWheelEvent>
#include <QtWidgets/QApplication>

#include <algorithm>
#include <cmath>
#include <limits>
#include <memory>
#include <numeric>

namespace Avogadro::QtOpenGL {

namespace {

// Hard cap on either side of the render (output size times supersampling).
// 8192^2 needs about 1.5 GiB (24 bytes per pixel across the FBO, the
// SolidPipeline textures and the read-back).
constexpr int MaxRenderDimension = 8192;

struct RenderLayout
{
  int logicalWidth;
  int logicalHeight;
  float pixelRatio;
};

// GLRenderer::resize() and SolidPipeline::resize() compute a device size as
// the truncated float product of an integer logical size and the pixel ratio.
// Return whether that gives exactly the wanted device size.
bool isExact(int logicalW, int logicalH, float ratio, int deviceW, int deviceH)
{
  return static_cast<int>(logicalW * ratio) == deviceW &&
         static_cast<int>(logicalH * ratio) == deviceH;
}

// Find an integer logical size and a float pixel ratio whose device size is
// exactly deviceW x deviceH, with the logical height as close to the view's as
// possible (so labels and line widths keep their on-screen proportions).
//
// The logical size is an int pair and there is a single ratio, so the output
// aspect ratio is only exactly representable when the logical size is a
// multiple of the reduced aspect ratio uw:uh. Take the multiple nearest to the
// view height. If it is not within 1.5x of the view height (the output has an
// awkward aspect such as 1001 x 999), render with logical size = output size
// and ratio = supersample instead; labels then scale with the image, but the
// size is exact.
RenderLayout chooseLayout(int outW, int outH, int k, int viewH)
{
  const int deviceW = outW * k;
  const int deviceH = outH * k;

  const int d = std::gcd(outW, outH);
  const int uh = outH / d;
  const int uw = outW / d;
  if (viewH > 0) {
    const int m = std::max(
      1, static_cast<int>(std::lround(static_cast<double>(viewH) / uh)));
    const long long h = static_cast<long long>(m) * uh;
    const long long w = static_cast<long long>(m) * uw;
    if (h * 3 >= viewH * 2LL && h * 2 <= viewH * 3LL && w <= 1000000) {
      const int lw = static_cast<int>(w);
      const int lh = static_cast<int>(h);
      float ratio = static_cast<float>(static_cast<double>(deviceH) / lh);
      // Float rounding may land just under the exact value, which would
      // truncate to one pixel short. Nudge upwards; staying within a few ulps
      // keeps the truncation at the exact size.
      for (int i = 0; i < 8; ++i) {
        if (isExact(lw, lh, ratio, deviceW, deviceH))
          return { lw, lh, ratio };
        ratio = std::nextafter(ratio, std::numeric_limits<float>::infinity());
      }
    }
  }
  return { outW, outH, static_cast<float>(k) };
}

} // namespace

GLWidget::GLWidget(QWidget* p)
  : QOpenGLWidget(p), m_activeTool(nullptr), m_defaultTool(nullptr)
{
  setFocusPolicy(Qt::ClickFocus);
  connect(&m_scenePlugins, &QtGui::ScenePluginModel::pluginStateChanged, this,
          &GLWidget::updateScene);
  connect(&m_scenePlugins, &QtGui::ScenePluginModel::pluginConfigChanged, this,
          &GLWidget::updateScene);
  m_renderer.setTextRenderStrategy(new QtTextRenderStrategy);

  QSettings settings;
  m_navigationModifier = static_cast<Qt::KeyboardModifiers>(
    settings
      .value("glwidget/navigationModifier", static_cast<int>(Qt::AltModifier))
      .toInt());
}

GLWidget::~GLWidget() {}

void GLWidget::setMolecule(QtGui::Molecule* mol)
{
  clearScene();
  // Remove only this widget's own connection. A blanket disconnect would also
  // drop connections owned by other objects (e.g. the main window marking the
  // document modified), which may still be watching the same molecule.
  if (m_molecule) {
    disconnect(m_molecule, &QtGui::Molecule::changed, this,
               &GLWidget::updateScene);
  }
  m_molecule = mol;
  foreach (QtGui::ToolPlugin* tool, m_tools)
    tool->setMolecule(m_molecule);

  if (m_molecule != nullptr) {
    // update properties like dipole rendering
    QTimer::singleShot(500, m_molecule, &QtGui::Molecule::update);
  }

  if (m_molecule != nullptr) {
    connect(m_molecule, &QtGui::Molecule::changed, this,
            &GLWidget::updateScene);
  }
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
  // A scene plugin or tool can spin a nested event loop while it builds the
  // scene (e.g. waiting on an external process), which may deliver another
  // change to this widget. Rebuilding then would free the nodes the outer
  // pass is still filling, so defer: remember the request and rebuild once
  // the current pass has finished.
  if (m_updatingScene) {
    m_sceneUpdatePending = true;
    return;
  }

  m_updatingScene = true;
  do {
    m_sceneUpdatePending = false;

    // Build up the scene with the scene plugins, creating the appropriate
    // nodes. m_molecule is a QPointer and may change between passes.
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
    }
    if (mol != m_molecule)
      delete mol;
  } while (m_sceneUpdatePending);
  m_updatingScene = false;

  m_renderer.resetGeometry();
  update();
}

void GLWidget::clearScene()
{
  // Clearing now would free nodes the running build is still using
  if (m_updatingScene) {
    m_sceneUpdatePending = true;
    return;
  }
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
  // update() only schedules a repaint, so bursts of requests (e.g. mouse
  // moves while navigating) coalesce into one frame paced by the display.
  update();
}

void GLWidget::initializeGL()
{
  m_renderer.initialize();
  if (!m_renderer.isValid())
    emit rendererInvalid();
}

void GLWidget::resizeGL(int width_, int height_)
{
  // Qt hands us the widget size in logical pixels.
  m_pixelRatio = static_cast<float>(devicePixelRatioF());
  m_renderer.setPixelRatio(m_pixelRatio);
  m_renderer.resize(width_, height_);
}

void GLWidget::paintGL()
{
  // Moving the window to a screen with a different scale factor changes the
  // device pixel ratio without changing the widget size in logical pixels, so
  // resizeGL() is not necessarily called. Resize here to keep the offscreen
  // buffers in step with the framebuffer Qt has recreated for the new screen.
  auto pixelRatio = static_cast<float>(devicePixelRatioF());
  if (pixelRatio != m_pixelRatio)
    resizeGL(width(), height());

  m_renderer.render();
}

QImage GLWidget::renderImage(const RenderOptions& options, QString* error)
{
  auto fail = [error](const QString& message) {
    if (error != nullptr)
      *error = message;
    return QImage();
  };
  if (error != nullptr)
    error->clear();

  // 1. Validate.
  QSize outSize = options.size;
  // A default-constructed QSize (-1, -1) means "the view size"; any other
  // non-positive size is a mistake and is rejected below.
  if (outSize == QSize()) {
    const qreal dpr = devicePixelRatioF();
    outSize = QSize(static_cast<int>(std::lround(width() * dpr)),
                    static_cast<int>(std::lround(height() * dpr)));
  }
  if (outSize.width() <= 0 || outSize.height() <= 0)
    return fail(tr("The image size must be positive."));
  const int k = options.supersample;
  if (k < 1 || k > 4)
    return fail(tr("Supersampling must be between 1 and 4."));
  if (m_updatingScene)
    return fail(tr("The scene is being rebuilt; try again in a moment."));
  if (!m_renderer.isValid())
    return fail(tr("The renderer is not valid: %1")
                  .arg(QString::fromStdString(m_renderer.error())));

  // Check the cheap limits before touching GL.
  const long long renderW = static_cast<long long>(outSize.width()) * k;
  const long long renderH = static_cast<long long>(outSize.height()) * k;
  if (renderW > MaxRenderDimension || renderH > MaxRenderDimension) {
    return fail(tr("The image is too large: %1 x %2 pixels (including "
                   "supersampling) exceeds the maximum of %3.")
                  .arg(renderW)
                  .arg(renderH)
                  .arg(MaxRenderDimension));
  }

  makeCurrent();
  QOpenGLContext* ctx = QOpenGLContext::currentContext();
  if (context() == nullptr || ctx == nullptr) {
    return fail(tr("There is no OpenGL context. The view must have been "
                   "shown at least once."));
  }

  // From here on every exit path must restore the widget (see the guard).
  std::unique_ptr<QOpenGLFramebufferObject> fbo;
  struct Restore
  {
    GLWidget& widget;
    std::unique_ptr<QOpenGLFramebufferObject>& fbo;
    float pixelRatio;
    int logicalWidth;
    int logicalHeight;
    float projectionScale;
    Vector4ub background;
    ~Restore()
    {
      // Free the FBO while the context is still current.
      fbo.reset();
      Rendering::GLRenderer& r = widget.m_renderer;
      r.scene().setBackgroundColor(background);
      r.setProjectionScale(projectionScale);
      r.setPixelRatio(pixelRatio);
      // Reallocates the SolidPipeline textures at the on-screen size.
      r.resize(logicalWidth, logicalHeight);
      // Put back the framebuffer Qt expects to paint into.
      QOpenGLContext::currentContext()->functions()->glBindFramebuffer(
        GL_FRAMEBUFFER, widget.defaultFramebufferObject());
      widget.doneCurrent();
      widget.update();
    }
  } restore{ *this,
             fbo,
             m_renderer.pixelRatio(),
             m_renderer.camera().width(),
             m_renderer.camera().height(),
             m_renderer.projectionScale(),
             m_renderer.scene().backgroundColor() };

  // 2. Check the GL limits.
  QOpenGLFunctions* gl = ctx->functions();
  GLint maxTexture = 0, maxRenderbuffer = 0;
  GLint maxViewport[2] = { 0, 0 };
  gl->glGetIntegerv(GL_MAX_TEXTURE_SIZE, &maxTexture);
  gl->glGetIntegerv(GL_MAX_RENDERBUFFER_SIZE, &maxRenderbuffer);
  gl->glGetIntegerv(GL_MAX_VIEWPORT_DIMS, maxViewport);
  const long long limit = std::min({ static_cast<long long>(maxTexture),
                                     static_cast<long long>(maxRenderbuffer),
                                     static_cast<long long>(maxViewport[0]),
                                     static_cast<long long>(maxViewport[1]) });
  if (renderW > limit || renderH > limit) {
    return fail(tr("The image is too large for this graphics driver: "
                   "%1 x %2 pixels exceeds its limit of %3.")
                  .arg(renderW)
                  .arg(renderH)
                  .arg(limit));
  }

  // A scene change that has not been built yet must not be missed.
  if (m_sceneUpdatePending)
    updateScene();
  // updateScene() calls update() and leaves the context alone, but a scene
  // plugin may have spun an event loop; make sure we are still current.
  makeCurrent();

  // 4. Logical size and pixel ratio. The logical height stays close to the
  // widget's so labels keep their on-screen proportions.
  const int viewW = std::max(1, restore.logicalWidth);
  const int viewH = std::max(1, restore.logicalHeight);
  const RenderLayout layout =
    chooseLayout(outSize.width(), outSize.height(), k, viewH);

  // 5. Framing.
  float projectionScale = 1.0f;
  if (options.framing == RenderOptions::Framing::Fit) {
    const float viewAspect = static_cast<float>(viewW) / viewH;
    const float outAspect =
      static_cast<float>(outSize.width()) / outSize.height();
    projectionScale = std::max(1.0f, viewAspect / outAspect);
  }

  // 7. Render. Always with a fully transparent background, as the on-screen
  // export always has; an opaque image is composited over the background
  // colour afterwards.
  QOpenGLFramebufferObjectFormat format;
  format.setAttachment(QOpenGLFramebufferObject::CombinedDepthStencil);
  format.setInternalTextureFormat(GL_RGBA8);
  fbo = std::make_unique<QOpenGLFramebufferObject>(
    static_cast<int>(renderW), static_cast<int>(renderH), format);
  if (!fbo->isValid()) {
    fbo.reset();
    return fail(tr("The offscreen framebuffer could not be created. The "
                   "image may be too large for the available memory."));
  }

  const Vector4ub background = restore.background;
  m_renderer.scene().setBackgroundColor(Vector4ub(0, 0, 0, 0));
  m_renderer.setProjectionScale(projectionScale);
  m_renderer.setPixelRatio(layout.pixelRatio);
  m_renderer.resize(layout.logicalWidth, layout.logicalHeight);

  // Bind immediately before rendering: SolidPipeline::begin() records the
  // bound framebuffer as its output, and a pipeline that initialized lazily
  // would have left its own bound.
  if (!fbo->bind())
    return fail(tr("The offscreen framebuffer could not be bound."));
  m_renderer.render();
  gl->glFinish();

  // 8. Read back.
  QImage image = fbo->toImage();
  fbo->release();
  if (image.isNull())
    return fail(tr("Reading back the rendered image failed."));
  image.setDevicePixelRatio(1.0);
  if (k > 1) {
    image =
      image.scaled(outSize, Qt::IgnoreAspectRatio, Qt::SmoothTransformation);
    image.setDevicePixelRatio(1.0);
  }

  if (options.transparentBackground)
    return image.convertToFormat(QImage::Format_ARGB32);

  QImage opaque(outSize, QImage::Format_ARGB32_Premultiplied);
  opaque.fill(QColor(background[0], background[1], background[2], 255));
  {
    QPainter painter(&opaque);
    painter.drawImage(0, 0, image);
  }
  return opaque.convertToFormat(QImage::Format_RGB32);
}

Qt::KeyboardModifiers GLWidget::navigationModifier() const
{
  return m_navigationModifier;
}

void GLWidget::setNavigationModifier(Qt::KeyboardModifiers modifier)
{
  m_navigationModifier = modifier;
  QSettings settings;
  settings.setValue("glwidget/navigationModifier", static_cast<int>(modifier));
}

bool GLWidget::isNavigationMouseGesture(const QMouseEvent* event) const
{
  // Compare the whole mask: m_navigationModifier may hold a combination, and a
  // bare bitwise and would match when only one of the configured modifiers is
  // held.
  return m_defaultTool != nullptr && m_navigationModifier != Qt::NoModifier &&
         (event->modifiers() & m_navigationModifier) == m_navigationModifier;
}

bool GLWidget::isNavigationKeyGesture(const QKeyEvent* event) const
{
  if (m_defaultTool == nullptr)
    return false;

  Qt::KeyboardModifiers mods = event->modifiers();
  if (!(mods & Qt::ControlModifier) || (mods & Qt::ShiftModifier))
    return false;

  switch (event->key()) {
    case Qt::Key_Left:
    case Qt::Key_Right:
    case Qt::Key_Up:
    case Qt::Key_Down:
      return true;
    default:
      return false;
  }
}

void GLWidget::mouseDoubleClickEvent(QMouseEvent* e)
{
  e->ignore();

  if (m_activeTool)
    m_activeTool->mouseDoubleClickEvent(e);

  if (m_defaultTool && !e->isAccepted())
    m_defaultTool->mouseDoubleClickEvent(e);

  if (!e->isAccepted())
    QOpenGLWidget::mouseDoubleClickEvent(e);
}

void GLWidget::mousePressEvent(QMouseEvent* e)
{
  e->ignore();

  // Latch the navigation gesture for the duration of the drag: once a press
  // starts the camera navigating, keep it there through move and release
  // even if the user releases the modifier key mid-drag.
  m_navigationDrag = isNavigationMouseGesture(e);

  if (m_activeTool && !m_navigationDrag)
    m_activeTool->mousePressEvent(e);

  if (m_defaultTool && !e->isAccepted())
    m_defaultTool->mousePressEvent(e);

  if (!e->isAccepted())
    QOpenGLWidget::mousePressEvent(e);
}

void GLWidget::mouseMoveEvent(QMouseEvent* e)
{
  e->ignore();

  if (m_activeTool && !m_navigationDrag)
    m_activeTool->mouseMoveEvent(e);

  if (m_defaultTool && !e->isAccepted())
    m_defaultTool->mouseMoveEvent(e);

  if (!e->isAccepted())
    QOpenGLWidget::mouseMoveEvent(e);
}

void GLWidget::mouseReleaseEvent(QMouseEvent* e)
{
  e->ignore();

  if (m_activeTool && !m_navigationDrag)
    m_activeTool->mouseReleaseEvent(e);

  if (m_defaultTool && !e->isAccepted())
    m_defaultTool->mouseReleaseEvent(e);

  if (!e->isAccepted())
    QOpenGLWidget::mouseReleaseEvent(e);

  // Release the latch now that the drag sequence this press started has
  // finished being dispatched.
  m_navigationDrag = false;
}

void GLWidget::wheelEvent(QWheelEvent* e)
{
  e->ignore();

  if (m_activeTool)
    m_activeTool->wheelEvent(e);

  if (m_defaultTool && !e->isAccepted())
    m_defaultTool->wheelEvent(e);

  if (!e->isAccepted())
    QOpenGLWidget::wheelEvent(e);
}

void GLWidget::keyPressEvent(QKeyEvent* e)
{
  e->ignore();

  if (m_activeTool && !isNavigationKeyGesture(e))
    m_activeTool->keyPressEvent(e);

  if (m_defaultTool && !e->isAccepted())
    m_defaultTool->keyPressEvent(e);

  if (!e->isAccepted())
    QOpenGLWidget::keyPressEvent(e);
}

void GLWidget::keyReleaseEvent(QKeyEvent* e)
{
  e->ignore();

  if (m_activeTool && !isNavigationKeyGesture(e))
    m_activeTool->keyReleaseEvent(e);

  if (m_defaultTool && !e->isAccepted())
    m_defaultTool->keyReleaseEvent(e);

  if (!e->isAccepted())
    QOpenGLWidget::keyReleaseEvent(e);
}

} // namespace Avogadro::QtOpenGL
