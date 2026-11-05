/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "toolinteractionharness.h"

#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/sceneplugin.h>
#include <avogadro/qtgui/scenepluginmodel.h>
#include <avogadro/qtgui/toolplugin.h>
#include <avogadro/qtopengl/glwidget.h>
#include <avogadro/rendering/camera.h>
#include <avogadro/rendering/glrenderer.h>

#include <QtCore/QCoreApplication>
#include <QtGui/QKeyEvent>
#include <QtGui/QMouseEvent>
#include <QtGui/QWheelEvent>

#include <cmath>

namespace Avogadro::QtPluginsTests {

ToolInteractionHarness::ToolInteractionHarness()
  : m_widget(std::make_unique<QtOpenGL::GLWidget>())
{
  // Never shown, so resizeGL() never runs, and GLRenderer::resize() does
  // nothing without a GL context (it is not valid): size the cameras
  // directly, which is all picking and projection need.
  m_widget->resize(ViewportSize, ViewportSize);
  renderer().camera().setViewport(ViewportSize, ViewportSize);
  renderer().overlayCamera().setViewport(ViewportSize, ViewportSize);
  useHarnessMolecule();
}

ToolInteractionHarness::~ToolInteractionHarness()
{
  // The widget owns the tools; they must not outlive their molecule, which
  // the CommandTestHarness member destroys after this body.
  m_widget->setMolecule(nullptr);
  m_widget.reset();
}

Rendering::GLRenderer& ToolInteractionHarness::renderer()
{
  return m_widget->renderer();
}

Rendering::Camera& ToolInteractionHarness::camera()
{
  return renderer().camera();
}

void ToolInteractionHarness::addScenePlugin(QtGui::ScenePlugin* plugin)
{
  plugin->setEnabled(true);
  m_widget->sceneModel().addItem(plugin);
  updateScene();
}

void ToolInteractionHarness::setActiveTool(QtGui::ToolPlugin* tool)
{
  m_widget->setActiveTool(tool);
  if (tool != nullptr)
    tool->setEditMolecule(molecule()->undoMolecule());
}

void ToolInteractionHarness::setDefaultTool(QtGui::ToolPlugin* tool)
{
  m_widget->setDefaultTool(tool);
  if (tool != nullptr)
    tool->setEditMolecule(molecule()->undoMolecule());
}

template <typename Build>
void ToolInteractionHarness::replaceMolecule(Build build)
{
  m_widget->setMolecule(nullptr);
  for (QtGui::ToolPlugin* tool : m_widget->tools())
    tool->setEditMolecule(nullptr);
  build();
  useHarnessMolecule();
}

void ToolInteractionHarness::buildMethanol()
{
  replaceMolecule([this] { m_commands.buildMethanol(); });
}

void ToolInteractionHarness::buildPeroxideChain()
{
  replaceMolecule([this] { m_commands.buildPeroxideChain(); });
}

void ToolInteractionHarness::buildEmpty()
{
  replaceMolecule([this] { m_commands.buildEmpty(); });
}

void ToolInteractionHarness::useHarnessMolecule()
{
  // Scene plugins act on the active layer molecule, and are enabled per
  // molecule: MainWindow re-applies the display types on every new one.
  m_commands.setActiveLayerMolecule(nullptr);
  for (QtGui::ScenePlugin* plugin : m_widget->sceneModel().scenePlugins())
    plugin->setEnabled(true);
  m_widget->setMolecule(molecule());
  for (QtGui::ToolPlugin* tool : m_widget->tools())
    tool->setEditMolecule(molecule()->undoMolecule());
  updateScene();
  resetCamera();
}

void ToolInteractionHarness::updateScene()
{
  m_widget->updateScene();
  renderer().applyProjection();
}

void ToolInteractionHarness::resetCamera()
{
  renderer().resetCamera();
  renderer().applyProjection();
}

namespace {

// Camera::project() returns OpenGL window coordinates (origin bottom left);
// events, hit() and unProject() use Qt's (origin top left).
QPoint toWidget(const Rendering::Camera& camera, const Vector3f& world)
{
  const Vector3f window = camera.project(world);
  return { static_cast<int>(std::lround(window.x())),
           static_cast<int>(std::lround(camera.height() - window.y())) };
}

} // namespace

QPoint ToolInteractionHarness::pointOnAtom(Index atom) const
{
  const Vector3f position = molecule()->atomPosition3d(atom).cast<float>();
  return toWidget(m_widget->renderer().camera(), position);
}

QPoint ToolInteractionHarness::pointOnBond(Index bond) const
{
  const auto& pair = molecule()->bondPair(bond);
  const Vector3f mid = ((molecule()->atomPosition3d(pair.first) +
                         molecule()->atomPosition3d(pair.second)) /
                        2.0)
                         .cast<float>();
  return toWidget(m_widget->renderer().camera(), mid);
}

QPoint ToolInteractionHarness::emptyPoint() const
{
  // resetCamera() fits the molecule well inside the view, so a corner is
  // clear of it.
  return { 5, 5 };
}

Rendering::Identifier ToolInteractionHarness::hitAt(const QPoint& point) const
{
  return m_widget->renderer().hit(point.x(), point.y());
}

void ToolInteractionHarness::settle()
{
  QCoreApplication::processEvents();
  renderer().applyProjection();
}

namespace {

bool sendMouse(QWidget* widget, QEvent::Type type, const QPoint& point,
               Qt::MouseButton button, Qt::MouseButtons buttons,
               Qt::KeyboardModifiers modifiers)
{
  const QPointF local(point);
  QMouseEvent event(type, local, widget->mapToGlobal(local), button, buttons,
                    modifiers);
  event.setAccepted(false);
  QCoreApplication::sendEvent(widget, &event);
  return event.isAccepted();
}

} // namespace

bool ToolInteractionHarness::press(const QPoint& point, Qt::MouseButton button,
                                   Qt::KeyboardModifiers modifiers)
{
  const bool accepted =
    sendMouse(m_widget.get(), QEvent::MouseButtonPress, point, button,
              Qt::MouseButtons(button), modifiers);
  settle();
  return accepted;
}

bool ToolInteractionHarness::move(const QPoint& point, Qt::MouseButtons buttons,
                                  Qt::KeyboardModifiers modifiers)
{
  const bool accepted = sendMouse(m_widget.get(), QEvent::MouseMove, point,
                                  Qt::NoButton, buttons, modifiers);
  settle();
  return accepted;
}

bool ToolInteractionHarness::release(const QPoint& point,
                                     Qt::MouseButton button,
                                     Qt::KeyboardModifiers modifiers)
{
  const bool accepted = sendMouse(m_widget.get(), QEvent::MouseButtonRelease,
                                  point, button, Qt::NoButton, modifiers);
  settle();
  return accepted;
}

bool ToolInteractionHarness::dblClick(const QPoint& point,
                                      Qt::MouseButton button,
                                      Qt::KeyboardModifiers modifiers)
{
  // Qt delivers press, release, double-click, release. The double-click has to
  // be bracketed like that: QWidget's default handler turns an unaccepted one
  // into a press, which a tool then waits to see released.
  press(point, button, modifiers);
  release(point, button, modifiers);
  const bool accepted =
    sendMouse(m_widget.get(), QEvent::MouseButtonDblClick, point, button,
              Qt::MouseButtons(button), modifiers);
  settle();
  release(point, button, modifiers);
  return accepted;
}

bool ToolInteractionHarness::wheel(const QPoint& point, int angleDeltaY,
                                   Qt::KeyboardModifiers modifiers)
{
  const QPointF local(point);
  QWheelEvent event(local, m_widget->mapToGlobal(local), QPoint(),
                    QPoint(0, angleDeltaY), Qt::NoButton, modifiers,
                    Qt::NoScrollPhase, false);
  event.setAccepted(false);
  QCoreApplication::sendEvent(m_widget.get(), &event);
  settle();
  return event.isAccepted();
}

bool ToolInteractionHarness::keyPress(int key, Qt::KeyboardModifiers modifiers,
                                      const QString& text)
{
  QKeyEvent event(QEvent::KeyPress, key, modifiers, text);
  event.setAccepted(false);
  QCoreApplication::sendEvent(m_widget.get(), &event);
  settle();
  return event.isAccepted();
}

bool ToolInteractionHarness::keyRelease(int key,
                                        Qt::KeyboardModifiers modifiers,
                                        const QString& text)
{
  QKeyEvent event(QEvent::KeyRelease, key, modifiers, text);
  event.setAccepted(false);
  QCoreApplication::sendEvent(m_widget.get(), &event);
  settle();
  return event.isAccepted();
}

void ToolInteractionHarness::click(const QPoint& point, Qt::MouseButton button,
                                   Qt::KeyboardModifiers modifiers)
{
  press(point, button, modifiers);
  release(point, button, modifiers);
}

void ToolInteractionHarness::drag(const QPoint& from, const QPoint& to,
                                  Qt::MouseButton button,
                                  Qt::KeyboardModifiers modifiers, int steps)
{
  press(from, button, modifiers);
  steps = steps < 1 ? 1 : steps;
  for (int i = 1; i <= steps; ++i) {
    const QPoint step = from + (to - from) * i / steps;
    move(step, Qt::MouseButtons(button), modifiers);
  }
  release(to, button, modifiers);
}

} // namespace Avogadro::QtPluginsTests
