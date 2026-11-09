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
#include <avogadro/rendering/rendertimings.h>

#include <QAction>
#include <QOpenGLContext>
#include <QOpenGLFramebufferObject>
#include <QOpenGLFramebufferObjectFormat>
#include <QOpenGLFunctions>
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
#include <array>
#include <chrono>
#include <cmath>
#include <memory>
#include <utility>
#include <vector>

namespace Avogadro::QtOpenGL {

namespace {

using Clock = std::chrono::steady_clock;

double elapsedMs(Clock::time_point from, Clock::time_point to)
{
  return std::chrono::duration<double, std::milli>(to - from).count();
}

// Milliseconds since the last mark, which it then resets to now.
struct Lap
{
  Clock::time_point mark;
  void reset() { mark = Clock::now(); }
  double operator()()
  {
    const Clock::time_point now = Clock::now();
    const double ms = elapsedMs(mark, now);
    mark = now;
    return ms;
  }
};

// The GPU time of a pass or total, or "n/a" when the driver gave none.
QString gpuText(double ms)
{
  return ms < 0.0 ? QStringLiteral("n/a") : QString::number(ms, 'f', 1);
}

// The CPU and GPU times of the pass called `name`. If there is no such pass
// the CPU time is 0, and the GPU time is 0 (or -1, "n/a", when the driver
// gives none).
Rendering::PassTiming passTiming(const Rendering::RenderTimings& timings,
                                 const char* name)
{
  for (const Rendering::PassTiming& pass : timings.passes) {
    if (pass.name == name)
      return pass;
  }
  Rendering::PassTiming none;
  none.cpuMs = 0.0;
  none.gpuMs = timings.gpuTimingAvailable ? 0.0 : -1.0;
  return none;
}

// True if the merged molecule changes only moved atoms, so scene plugins can
// update their existing nodes: Moved or Conformer, with nothing but Atoms
// besides.
bool isPositionsOnly(unsigned int changes)
{
  using Change = QtGui::Molecule::MoleculeChange;
  constexpr unsigned int allowed =
    Change::Atoms | Change::Moved | Change::Conformer;
  return (changes & (Change::Moved | Change::Conformer)) != 0 &&
         (changes & ~allowed) == 0;
}

} // namespace

// Frame statistics, see setFrameStatsVisible(). Only touched when the overlay
// is visible.
class GLWidget::Private
{
public:
  bool statsVisible = false;
  bool statsLog = false;
  Clock::time_point lastPaint;
  Clock::time_point lastStatsLog;
  bool haveLastPaint = false;
  std::array<double, 30> frameIntervals{};
  int frameIntervalCount = 0;
  int frameIntervalNext = 0;
  // The most recent scene rebuild.
  double rebuildTotalMs = 0.0;
  double rebuildClearMs = 0.0;
  double rebuildToolsMs = 0.0;
  double rebuildResetMs = 0.0;
  std::vector<std::pair<QString, double>> rebuildPlugins;
  int rebuildsSincePaint = 0;
  int rebuildsAtLastPaint = 0;
  // Aggregates over the ~1 s window starting at lastStatsLog; the "shown"
  // values are those of the last completed window.
  struct Window
  {
    int maxRebuilds = 0;
    int rebuilds = 0;
    int frames = 0;
  };
  Window current;
  Window shown;
  // Scene changes that arrived since the last rebuild. The merged
  // Molecule::changed flags are kept for dispatching on the kind of change;
  // anything from plugins or tools needs a full rebuild.
  bool scenePending = false;
  bool sceneFullRebuild = false;
  unsigned int pendingChanges = 0;
  // The scene tree of the last full rebuild, kept so a positions-only change
  // can update it in place. Valid only while treeMolecule is non-null; reset
  // by invalidateTree() whenever the tree is cleared or rebuilt.
  struct EngineNode
  {
    QPointer<QtGui::ScenePlugin> plugin;
    Rendering::GroupNode* node = nullptr;
  };
  struct ToolNode
  {
    QPointer<QtGui::ToolPlugin> tool;
    Rendering::GroupNode* node = nullptr;
  };
  QPointer<QtGui::Molecule> treeMolecule;
  std::vector<EngineNode> engineNodes;
  std::vector<ToolNode> toolNodes;
  bool rebuildCoords = false;

  void invalidateTree()
  {
    treeMolecule = nullptr;
    engineNodes.clear();
    toolNodes.clear();
  }

  void clearPending()
  {
    scenePending = false;
    sceneFullRebuild = false;
    pendingChanges = 0;
  }

  // True if the recorded tree belongs to `mol`, with the same active plugins
  // and tools in the same order.
  bool treeMatches(const QtGui::Molecule* mol,
                   const QList<QtGui::ScenePlugin*>& active,
                   const QList<QtGui::ToolPlugin*>& activeTools) const
  {
    if (!mol || treeMolecule != mol)
      return false;
    if (static_cast<size_t>(active.size()) != engineNodes.size() ||
        static_cast<size_t>(activeTools.size()) != toolNodes.size())
      return false;
    for (size_t i = 0; i < engineNodes.size(); ++i) {
      if (engineNodes[i].plugin != active[static_cast<qsizetype>(i)])
        return false;
    }
    for (size_t i = 0; i < toolNodes.size(); ++i) {
      if (toolNodes[i].tool != activeTools[static_cast<qsizetype>(i)])
        return false;
    }
    return true;
  }

  // The tail shared by both rebuild passes: reset the renderer's geometry
  // and record the reset and total times.
  void finishRebuild(Rendering::GLRenderer& renderer, bool stats, Lap& lap,
                     Clock::time_point tStart)
  {
    if (stats)
      lap.reset();
    renderer.resetGeometry();
    if (stats) {
      rebuildResetMs = lap();
      rebuildTotalMs = elapsedMs(tStart, lap.mark);
    }
  }
};

GLWidget::GLWidget(QWidget* p)
  : QOpenGLWidget(p), m_activeTool(nullptr), m_defaultTool(nullptr),
    d(std::make_unique<Private>())
{
  setFocusPolicy(Qt::ClickFocus);
  connect(&m_scenePlugins, &QtGui::ScenePluginModel::pluginStateChanged, this,
          &GLWidget::requestSceneRebuild);
  connect(&m_scenePlugins, &QtGui::ScenePluginModel::pluginConfigChanged, this,
          &GLWidget::requestSceneRebuild);
  m_renderer.setTextRenderStrategy(new QtTextRenderStrategy);

  QSettings settings;
  m_navigationModifier = static_cast<Qt::KeyboardModifiers>(
    settings
      .value("glwidget/navigationModifier", static_cast<int>(Qt::AltModifier))
      .toInt());

  const QByteArray stats = qgetenv("AVOGADRO_FRAME_STATS");
  if (!stats.isEmpty() && stats != "0") {
    d->statsLog = (stats == "log");
    setFrameStatsVisible(true);
  }
}

GLWidget::~GLWidget()
{
  // Release the timing queries while this widget's context is current.
  if (m_renderer.timingEnabled()) {
    makeCurrent();
    m_renderer.setTimingEnabled(false);
    doneCurrent();
  }
}

void GLWidget::setMolecule(QtGui::Molecule* mol)
{
  clearScene();
  d->invalidateTree();
  // Remove only this widget's own connection. A blanket disconnect would also
  // drop connections owned by other objects (e.g. the main window marking the
  // document modified), which may still be watching the same molecule.
  if (m_molecule) {
    disconnect(m_molecule, &QtGui::Molecule::changed, this,
               &GLWidget::moleculeChanged);
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
            &GLWidget::moleculeChanged);
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

void GLWidget::moleculeChanged(unsigned int changes)
{
  d->scenePending = true;
  d->pendingChanges |= changes;
  update();
}

void GLWidget::requestSceneRebuild()
{
  d->scenePending = true;
  d->sceneFullRebuild = true;
  update();
}

bool GLWidget::applyPending()
{
  if (!d->scenePending)
    return false;
  // A nested event loop inside a build: the running pass rebuilds once more
  // when it finishes, which supersedes what is pending now.
  if (m_updatingScene) {
    m_sceneUpdatePending = true;
    d->clearPending();
    return false;
  }

  if (!d->sceneFullRebuild && isPositionsOnly(d->pendingChanges) &&
      d->treeMatches(m_molecule, m_scenePlugins.activeScenePlugins(),
                     m_tools)) {
    rebuildCoordinates();
  } else {
    rebuildScene();
  }
  return true;
}

void GLWidget::applyPendingSceneChanges()
{
  if (applyPending())
    update();
}

void GLWidget::rebuildCoordinates()
{
  d->clearPending();

  const bool stats = d->statsVisible;
  Clock::time_point tStart;
  Lap lap;
  if (stats) {
    tStart = Clock::now();
    ++d->rebuildsSincePaint;
    d->rebuildCoords = true;
    d->rebuildPlugins.clear();
    d->rebuildClearMs = 0.0;
    lap.mark = tStart;
  }

  // The tree is only trusted while nothing clears it (clearScene() defers
  // while m_updatingScene is set). Work on copies so that a nested call
  // cannot invalidate what is being iterated.
  QtGui::Molecule* mol = m_molecule;
  const std::vector<Private::EngineNode> engines = d->engineNodes;
  const std::vector<Private::ToolNode> tools = d->toolNodes;

  m_updatingScene = true;
  m_sceneUpdatePending = false;
  for (const Private::EngineNode& engine : engines) {
    if (!engine.plugin)
      continue;
    if (stats)
      lap.reset();
    if (!engine.plugin->updateCoordinates(*mol, *engine.node)) {
      // No in-place update: rebuild this plugin's node, keeping the node.
      engine.node->clear();
      engine.node->clearUI();
      engine.plugin->process(*mol, *engine.node);
    }
    if (stats)
      d->rebuildPlugins.emplace_back(engine.plugin->name(), lap());
  }
  if (stats)
    lap.reset();
  for (const Private::ToolNode& tool : tools) {
    if (!tool.tool)
      continue;
    tool.node->clear();
    tool.tool->draw(*tool.node);
  }
  if (stats)
    d->rebuildToolsMs = lap();
  m_updatingScene = false;

  // A nested event loop delivered another change. It may be of any kind, so
  // rebuild everything rather than reason about what the plugins saw.
  if (m_sceneUpdatePending) {
    rebuildScene();
    return;
  }

  d->finishRebuild(m_renderer, stats, lap, tStart);
}

void GLWidget::updateScene()
{
  if (rebuildScene())
    update();
}

bool GLWidget::rebuildScene()
{
  // A scene plugin or tool can spin a nested event loop while it builds the
  // scene (e.g. waiting on an external process), which may deliver another
  // change to this widget. Rebuilding then would free the nodes the outer
  // pass is still filling, so defer: remember the request and rebuild once
  // the current pass has finished.
  if (m_updatingScene) {
    m_sceneUpdatePending = true;
    return false;
  }

  // A rebuild now supersedes anything waiting for the next paint.
  d->clearPending();

  // Each pass counts as a rebuild; the overlay shows the last pass's
  // breakdown and the total for the whole call.
  const bool stats = d->statsVisible;
  Clock::time_point tStart;
  Lap lap;
  if (stats)
    tStart = Clock::now();

  m_updatingScene = true;
  do {
    m_sceneUpdatePending = false;
    if (stats) {
      ++d->rebuildsSincePaint;
      d->rebuildPlugins.clear();
      d->rebuildCoords = false;
      lap.reset();
    }
    d->invalidateTree();

    // Build up the scene with the scene plugins, creating the appropriate
    // nodes. m_molecule is a QPointer and may change between passes.
    QtGui::Molecule* mol = m_molecule;
    if (!mol)
      mol = new QtGui::Molecule(this);
    if (mol) {
      Rendering::GroupNode& node = m_renderer.scene().rootNode();
      node.clear();
      auto* moleculeNode = new Rendering::GroupNode(&node);
      std::vector<Private::EngineNode> engines;
      std::vector<Private::ToolNode> tools;
      if (stats)
        d->rebuildClearMs = lap();

      foreach (QtGui::ScenePlugin* scenePlugin,
               m_scenePlugins.activeScenePlugins()) {
        auto* engineNode = new Rendering::GroupNode(moleculeNode);
        if (stats)
          lap.reset();
        scenePlugin->process(*mol, *engineNode);
        engines.push_back({ scenePlugin, engineNode });
        if (stats)
          d->rebuildPlugins.emplace_back(scenePlugin->name(), lap());
      }

      // Let the tools perform any drawing they need to do.
      if (stats)
        lap.reset();
      foreach (QtGui::ToolPlugin* tool, m_tools) {
        auto* toolNode = new Rendering::GroupNode(moleculeNode);
        tool->draw(*toolNode);
        tools.push_back({ tool, toolNode });
      }
      // Only a tree built for the widget's own molecule can be updated later.
      if (mol == m_molecule) {
        d->treeMolecule = mol;
        d->engineNodes = std::move(engines);
        d->toolNodes = std::move(tools);
      }
      if (stats)
        d->rebuildToolsMs = lap();
    }
    if (mol != m_molecule)
      delete mol;
  } while (m_sceneUpdatePending);
  m_updatingScene = false;

  d->finishRebuild(m_renderer, stats, lap, tStart);
  return true;
}

void GLWidget::clearScene()
{
  // Clearing now would free nodes the running build is still using
  if (m_updatingScene) {
    m_sceneUpdatePending = true;
    return;
  }
  d->invalidateTree();
  m_renderer.scene().clear();
}

void GLWidget::resetCamera()
{
  applyPendingSceneChanges();
  m_renderer.resetCamera();
  update();
}

void GLWidget::resetGeometry()
{
  applyPendingSceneChanges();
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
               &GLWidget::requestSceneRebuild);
  }

  if (tool)
    addTool(tool);
  m_activeTool = tool;

  if (m_activeTool && m_activeTool != m_defaultTool) {
    connect(m_activeTool, &QtGui::ToolPlugin::drawablesChanged, this,
            &GLWidget::requestSceneRebuild);
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
               &GLWidget::requestSceneRebuild);
  }

  if (tool)
    addTool(tool);
  m_defaultTool = tool;

  if (m_defaultTool && m_activeTool != m_defaultTool) {
    connect(m_defaultTool, &QtGui::ToolPlugin::drawablesChanged, this,
            &GLWidget::requestSceneRebuild);
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

  // Coalesced scene changes are built here, so a burst of changes between
  // paints costs one rebuild (counted toward this frame).
  // The paint in progress draws the result, so no update() is scheduled.
  applyPending();

  if (!d->statsVisible) {
    m_renderer.render();
    return;
  }

  // Time between successive paints; a gap of a second or more is idleness
  // rather than frame time, so it restarts the average.
  const Clock::time_point now = Clock::now();
  if (d->haveLastPaint) {
    const double interval = elapsedMs(d->lastPaint, now);
    if (interval >= 1000.0) {
      d->frameIntervalCount = 0;
      d->frameIntervalNext = 0;
    } else {
      d->frameIntervals[d->frameIntervalNext] = interval;
      d->frameIntervalNext =
        (d->frameIntervalNext + 1) % static_cast<int>(d->frameIntervals.size());
      d->frameIntervalCount = std::min(
        d->frameIntervalCount + 1, static_cast<int>(d->frameIntervals.size()));
    }
  } else {
    d->lastStatsLog = now;
  }
  d->lastPaint = now;
  d->haveLastPaint = true;
  d->rebuildsAtLastPaint = d->rebuildsSincePaint;
  d->rebuildsSincePaint = 0;

  d->current.maxRebuilds =
    std::max(d->current.maxRebuilds, d->rebuildsAtLastPaint);
  d->current.rebuilds += d->rebuildsAtLastPaint;
  ++d->current.frames;
  bool windowRolled = false;
  if (elapsedMs(d->lastStatsLog, now) >= 1000.0) {
    d->shown = d->current;
    d->current = {};
    d->lastStatsLog = now;
    windowRolled = true;
  }

  m_renderer.render();
  drawFrameStats(windowRolled);
}

void GLWidget::drawFrameStats(bool windowRolled)
{
  // Median frame interval of the recent paints.
  double interval = 0.0;
  if (d->frameIntervalCount > 0) {
    std::array<double, 30> sorted = d->frameIntervals;
    auto middle = sorted.begin() + d->frameIntervalCount / 2;
    std::nth_element(sorted.begin(), middle,
                     sorted.begin() + d->frameIntervalCount);
    interval = *middle;
    // A true median averages the two middle values of an even count.
    if (d->frameIntervalCount % 2 == 0)
      interval = 0.5 * (interval + *std::max_element(sorted.begin(), middle));
  }

  const Rendering::RenderTimings& timings = m_renderer.timings();
  const Rendering::PassTiming solid = passTiming(timings, "solid");
  const Rendering::PassTiming post = passTiming(timings, "post");

  // The three slowest scene plugins of the last rebuild.
  std::vector<std::pair<QString, double>> top = d->rebuildPlugins;
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
  lines << QString::asprintf(
    "rebuild %.1f ms (%s; %d this frame; last 1 s: max %d, %d in %d frames)",
    d->rebuildTotalMs, d->rebuildCoords ? "coords" : "full",
    d->rebuildsAtLastPaint, d->shown.maxRebuilds, d->shown.rebuilds,
    d->shown.frames);
  lines << QString::asprintf("  clear %.1f  tools %.1f  reset %.1f",
                             d->rebuildClearMs, d->rebuildToolsMs,
                             d->rebuildResetMs);
  if (!plugins.isEmpty())
    lines << QStringLiteral("  ") + plugins;
  // Nothing is published until the first timed frame has completed.
  if (timings.frame != 0) {
    lines << QStringLiteral("render CPU %1 ms  GPU %2 ms")
               .arg(timings.totalCpuMs(), 0, 'f', 1)
               .arg(gpuText(timings.totalGpuMs()));
    lines << QStringLiteral("  solid %1/%2  post %3/%4 (cpu/gpu)")
               .arg(solid.cpuMs, 0, 'f', 1)
               .arg(gpuText(solid.gpuMs))
               .arg(post.cpuMs, 0, 'f', 1)
               .arg(gpuText(post.gpuMs));
    lines << QString::asprintf(
      "uploaded %.2f MB",
      static_cast<double>(timings.bufferBytesUploaded) / 1.0e6);
  }
  lines << QString::asprintf("%lld atoms  %lld bonds",
                             static_cast<long long>(atoms),
                             static_cast<long long>(bonds));

  if (d->statsLog && windowRolled)
    qInfo().noquote() << "frame-stats:" << lines.join(QStringLiteral(" | "));

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

bool GLWidget::frameStatsVisible() const
{
  return d->statsVisible;
}

void GLWidget::setFrameStatsVisible(bool visible)
{
  if (visible == d->statsVisible)
    return;
  d->statsVisible = visible;
  d->haveLastPaint = false;
  d->frameIntervalCount = 0;
  d->frameIntervalNext = 0;
  d->rebuildsSincePaint = 0;
  d->rebuildsAtLastPaint = 0;
  d->current = {};
  d->shown = {};
  makeCurrent();
  m_renderer.setTimingEnabled(visible);
  doneCurrent();
  update();
}

QSize GLWidget::pixelSize() const
{
  const qreal dpr = devicePixelRatioF();
  return QSize(static_cast<int>(std::lround(width() * dpr)),
               static_cast<int>(std::lround(height() * dpr)));
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

  QSize outSize = options.size;
  // A default-constructed QSize (-1, -1) means "the view size"; any other
  // non-positive size is a mistake and is rejected below.
  if (outSize == QSize())
    outSize = pixelSize();
  if (outSize.width() <= 0 || outSize.height() <= 0)
    return fail(tr("The image size must be positive."));
  const int k = options.supersample;
  if (k < 1 || k > RenderOptions::MaxSupersample)
    return fail(tr("Supersampling must be between 1 and 4."));
  if (m_updatingScene)
    return fail(tr("The scene is being rebuilt; try again in a moment."));
  if (!m_renderer.isValid())
    return fail(tr("The renderer is not valid: %1")
                  .arg(QString::fromStdString(m_renderer.error())));

  // Check the cheap limits before touching GL.
  const long long renderW = static_cast<long long>(outSize.width()) * k;
  const long long renderH = static_cast<long long>(outSize.height()) * k;
  if (renderW > RenderOptions::MaxDimension ||
      renderH > RenderOptions::MaxDimension) {
    return fail(tr("The image is too large: %1 x %2 pixels (including "
                   "supersampling) exceeds the maximum of %3.")
                  .arg(renderW)
                  .arg(renderH)
                  .arg(RenderOptions::MaxDimension));
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
    }
  } restore{ *this,
             fbo,
             m_renderer.pixelRatio(),
             m_renderer.camera().width(),
             m_renderer.camera().height(),
             m_renderer.projectionScale(),
             m_renderer.scene().backgroundColor() };

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
  else
    applyPendingSceneChanges();
  // updateScene() calls update() and leaves the context alone, but a scene
  // plugin may have spun an event loop; make sure we are still current.
  makeCurrent();

  // The logical height stays the view's, so labels and line widths keep their
  // on-screen proportions; the pixel ratio maps it onto the output height. The
  // logical width follows the output aspect ratio. The framebuffer and
  // viewport use the exact device size passed to GLRenderer::resize().
  const int viewW = std::max(1, restore.logicalWidth);
  const int logicalH = std::max(1, restore.logicalHeight);
  const auto pixelRatio =
    static_cast<float>(static_cast<double>(outSize.height()) * k / logicalH);
  const int logicalW = static_cast<int>(
    std::max<long long>(1, std::llround(static_cast<double>(outSize.width()) *
                                        logicalH / outSize.height())));

  float projectionScale = 1.0f;
  if (options.framing == RenderOptions::Framing::Fit) {
    const float viewAspect = static_cast<float>(viewW) / logicalH;
    const float outAspect =
      static_cast<float>(outSize.width()) / outSize.height();
    projectionScale = std::max(1.0f, viewAspect / outAspect);
  }

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

  // An opaque image is drawn straight over the real background colour, exactly
  // as the window is. A transparent one is drawn over (0, 0, 0, 0), which
  // leaves a premultiplied image in the framebuffer.
  const Vector4ub background = restore.background;
  if (options.transparentBackground)
    m_renderer.scene().setBackgroundColor(Vector4ub(0, 0, 0, 0));
  else
    m_renderer.scene().setBackgroundColor(
      Vector4ub(background[0], background[1], background[2], 255));
  m_renderer.setProjectionScale(projectionScale);
  m_renderer.setPixelRatio(pixelRatio);
  m_renderer.resize(logicalW, logicalH, static_cast<int>(renderW),
                    static_cast<int>(renderH));

  // Bind immediately before rendering: SolidPipeline::begin() records the
  // bound framebuffer as its output, and a pipeline that initialized lazily
  // would have left its own bound.
  if (!fbo->bind())
    return fail(tr("The offscreen framebuffer could not be bound."));
  m_renderer.render();

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

  if (!options.transparentBackground)
    return image.convertToFormat(QImage::Format_RGB32);

  // The framebuffer holds premultiplied colour. Qt labels the image that way,
  // so converting un-premultiplies it.
  return image.convertToFormat(QImage::Format_ARGB32);
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

bool GLWidget::event(QEvent* e)
{
  // Tools hit-test against the scene, so it must be current before any input
  // event reaches them.
  switch (e->type()) {
    case QEvent::MouseButtonPress:
    case QEvent::MouseButtonRelease:
    case QEvent::MouseButtonDblClick:
    case QEvent::MouseMove:
    case QEvent::Wheel:
    case QEvent::KeyPress:
    case QEvent::KeyRelease:
      applyPendingSceneChanges();
      break;
    default:
      break;
  }
  return QOpenGLWidget::event(e);
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
