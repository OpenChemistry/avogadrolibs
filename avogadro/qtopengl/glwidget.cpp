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
#include <QtCore/QSettings>
#include <QtCore/QTimer>
#include <QtGui/QKeyEvent>
#include <QtGui/QMouseEvent>
#include <QtGui/QWheelEvent>
#include <QtGui/QFont>
#include <QtGui/QFontDatabase>
#include <QtGui/QFontMetrics>
#include <QtGui/QOpenGLContext>
#include <QtGui/QOpenGLExtraFunctions>
#include <QtGui/QPainter>
#include <QtWidgets/QApplication>

#include <algorithm>
#include <chrono>

namespace Avogadro::QtOpenGL {

namespace {

using Clock = std::chrono::steady_clock;

double elapsedMs(Clock::time_point from, Clock::time_point to)
{
  return std::chrono::duration<double, std::milli>(to - from).count();
}

// The GPU time of a pass or total, or "n/a" when the driver gave none.
QString gpuText(double ms)
{
  return ms < 0.0 ? QStringLiteral("n/a") : QString::number(ms, 'f', 1);
}

// Sum the CPU and GPU times of the passes named in `names`.
void sectionTimes(const Rendering::RenderTimings& timings,
                  std::initializer_list<const char*> names, double& cpuMs,
                  double& gpuMs)
{
  cpuMs = 0.0;
  gpuMs = timings.gpuTimingAvailable ? 0.0 : -1.0;
  for (const Rendering::PassTiming& pass : timings.passes) {
    for (const char* name : names) {
      if (pass.name == name) {
        cpuMs += pass.cpuMs;
        if (gpuMs >= 0.0)
          gpuMs += pass.gpuMs;
      }
    }
  }
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

  const QByteArray stats = qgetenv("AVOGADRO_FRAME_STATS");
  if (!stats.isEmpty() && stats != "0") {
    m_statsLog = (stats == "log");
    setFrameStatsVisible(true);
  }
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
  // Build up the scene with the scene plugins, creating the appropriate nodes.
  const bool stats = m_statsVisible;
  Clock::time_point tStart, t0, t1;
  if (stats) {
    ++m_rebuildsSincePaint;
    m_rebuildPlugins.clear();
    tStart = t0 = Clock::now();
  }

  QtGui::Molecule* mol = m_molecule;
  if (!mol)
    mol = new QtGui::Molecule(this);
  if (mol) {
    Rendering::GroupNode& node = m_renderer.scene().rootNode();
    node.clear();
    auto* moleculeNode = new Rendering::GroupNode(&node);
    if (stats) {
      t1 = Clock::now();
      m_rebuildClearMs = elapsedMs(t0, t1);
    }

    foreach (QtGui::ScenePlugin* scenePlugin,
             m_scenePlugins.activeScenePlugins()) {
      auto* engineNode = new Rendering::GroupNode(moleculeNode);
      if (stats)
        t0 = Clock::now();
      scenePlugin->process(*mol, *engineNode);
      if (stats) {
        t1 = Clock::now();
        m_rebuildPlugins.emplace_back(scenePlugin->name(), elapsedMs(t0, t1));
      }
    }

    // Let the tools perform any drawing they need to do.
    if (stats)
      t0 = Clock::now();
    foreach (QtGui::ToolPlugin* tool, m_tools) {
      auto* toolNode = new Rendering::GroupNode(moleculeNode);
      tool->draw(*toolNode);
    }
    if (stats) {
      t1 = Clock::now();
      m_rebuildToolsMs = elapsedMs(t0, t1);
      t0 = t1;
    }

    m_renderer.resetGeometry();
    if (stats) {
      t1 = Clock::now();
      m_rebuildResetMs = elapsedMs(t0, t1);
      m_rebuildTotalMs = elapsedMs(tStart, t1);
    }
    update();
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

  if (!m_statsVisible) {
    m_renderer.render();
    return;
  }

  // Time between successive paints; a gap of a second or more is idleness
  // rather than frame time, so it restarts the average.
  const Clock::time_point now = Clock::now();
  if (m_haveLastPaint) {
    const double interval = elapsedMs(m_lastPaint, now);
    if (interval >= 1000.0) {
      m_frameIntervalCount = 0;
      m_frameIntervalNext = 0;
    } else {
      m_frameIntervals[m_frameIntervalNext] = interval;
      m_frameIntervalNext =
        (m_frameIntervalNext + 1) % static_cast<int>(m_frameIntervals.size());
      m_frameIntervalCount = std::min(
        m_frameIntervalCount + 1, static_cast<int>(m_frameIntervals.size()));
    }
  } else {
    m_lastStatsLog = now;
  }
  m_lastPaint = now;
  m_haveLastPaint = true;
  m_rebuildsAtLastPaint = m_rebuildsSincePaint;
  m_rebuildsSincePaint = 0;

  m_renderer.render();
  drawFrameStats();
}

void GLWidget::drawFrameStats()
{
  // Median frame interval of the recent paints.
  double interval = 0.0;
  if (m_frameIntervalCount > 0) {
    std::array<double, 30> sorted = m_frameIntervals;
    auto middle = sorted.begin() + m_frameIntervalCount / 2;
    std::nth_element(sorted.begin(), middle,
                     sorted.begin() + m_frameIntervalCount);
    interval = *middle;
  }

  const Rendering::RenderTimings& timings = m_renderer.timings();
  double solidCpu, solidGpu, postCpu, postGpu;
  sectionTimes(timings, { "solid" }, solidCpu, solidGpu);
  sectionTimes(timings, { "post" }, postCpu, postGpu);

  // The three slowest scene plugins of the last rebuild.
  std::vector<std::pair<QString, double>> top = m_rebuildPlugins;
  std::sort(top.begin(), top.end(),
            [](const auto& a, const auto& b) { return a.second > b.second; });
  QString plugins;
  for (size_t i = 0; i < top.size() && i < 3; ++i) {
    if (i > 0)
      plugins += QStringLiteral(", ");
    plugins += top[i].first + QString::asprintf(" %.1f", top[i].second);
  }

  const qsizetype atoms = m_molecule ? m_molecule->atomCount() : 0;
  const qsizetype bonds = m_molecule ? m_molecule->bondCount() : 0;

  QStringList lines;
  // Paints a second or more apart are idle time, not frame time.
  if (interval > 0.0)
    lines << QString::asprintf("%.0f fps  %.1f ms/frame", 1000.0 / interval,
                               interval);
  else
    lines << QStringLiteral("idle");
  lines << QString::asprintf("rebuild %.1f ms (%d this frame)",
                             m_rebuildTotalMs, m_rebuildsAtLastPaint);
  lines << QString::asprintf("  clear %.1f  tools %.1f  reset %.1f",
                             m_rebuildClearMs, m_rebuildToolsMs,
                             m_rebuildResetMs);
  if (!plugins.isEmpty())
    lines << QStringLiteral("  ") + plugins;
  lines << QStringLiteral("render CPU %1 ms  GPU %2 ms")
             .arg(timings.totalCpuMs(), 0, 'f', 1)
             .arg(gpuText(timings.totalGpuMs()));
  lines << QStringLiteral("  solid %1/%2  post %3/%4 (cpu/gpu)")
             .arg(solidCpu, 0, 'f', 1)
             .arg(gpuText(solidGpu))
             .arg(postCpu, 0, 'f', 1)
             .arg(gpuText(postGpu));
  lines << QString::asprintf("uploaded %.2f MB",
                             static_cast<double>(timings.bufferBytesUploaded) /
                               1.0e6);
  lines << QString::asprintf("%lld atoms  %lld bonds",
                             static_cast<long long>(atoms),
                             static_cast<long long>(bonds));

  if (m_statsLog && elapsedMs(m_lastStatsLog, m_lastPaint) >= 1000.0) {
    m_lastStatsLog = m_lastPaint;
    qInfo().noquote() << "frame-stats:" << lines.join(QStringLiteral(" | "));
  }

  // Hand the context to QPainter in the state its paint engine expects: none
  // of our objects bound, and the widget's own framebuffer as the target.
  QOpenGLExtraFunctions gl(context());
  gl.glBindVertexArray(0);
  gl.glUseProgram(0);
  gl.glBindBuffer(GL_ARRAY_BUFFER, 0);
  gl.glBindFramebuffer(GL_FRAMEBUFFER, defaultFramebufferObject());

  {
    QPainter painter(this);
    QFont font = QFontDatabase::systemFont(QFontDatabase::FixedFont);
    font.setPointSize(9);
    painter.setFont(font);
    const QFontMetrics metrics(font);
    const int pad = 6;
    int textWidth = 0;
    for (const QString& line : lines)
      textWidth = std::max(textWidth, metrics.horizontalAdvance(line));
    const int lineHeight = metrics.lineSpacing();
    const QRect box(8, 8, textWidth + 2 * pad,
                    lineHeight * static_cast<int>(lines.size()) + 2 * pad);
    painter.setRenderHint(QPainter::Antialiasing, false);
    painter.setPen(Qt::NoPen);
    painter.setBrush(QColor(0, 0, 0, 170));
    painter.drawRect(box);
    painter.setPen(QColor(255, 255, 255));
    int y = box.top() + pad + metrics.ascent();
    for (const QString& line : lines) {
      painter.drawText(box.left() + pad, y, line);
      y += lineHeight;
    }
    painter.end();
  }

  // QPainter leaves its own scissor, stencil, mask and texture-unit state
  // behind. render() sets depth test and blend itself but clears first, so a
  // stale scissor, mask or stencil would clip or drop the next frame's clear,
  // and the pipeline binds textures on whichever unit is active. The
  // framebuffer and viewport are re-read from the context on every frame by
  // SolidPipeline::begin(), so they need no restoring.
  gl.glBindVertexArray(0);
  gl.glUseProgram(0);
  gl.glBindBuffer(GL_ARRAY_BUFFER, 0);
  gl.glActiveTexture(GL_TEXTURE0);
  gl.glDisable(GL_SCISSOR_TEST);
  gl.glDisable(GL_STENCIL_TEST);
  gl.glDisable(GL_CULL_FACE);
  gl.glDepthMask(GL_TRUE);
  gl.glColorMask(GL_TRUE, GL_TRUE, GL_TRUE, GL_TRUE);
}

void GLWidget::setFrameStatsVisible(bool visible)
{
  if (visible == m_statsVisible)
    return;
  m_statsVisible = visible;
  m_haveLastPaint = false;
  m_frameIntervalCount = 0;
  m_frameIntervalNext = 0;
  m_rebuildsSincePaint = 0;
  m_rebuildsAtLastPaint = 0;
  m_renderer.setTimingEnabled(visible);
  update();
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
