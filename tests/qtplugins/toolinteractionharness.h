/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_TESTS_TOOLINTERACTIONHARNESS_H
#define AVOGADRO_TESTS_TOOLINTERACTIONHARNESS_H

#include "commandtestharness.h"

#include <avogadro/core/avogadrocore.h>
#include <avogadro/rendering/primitive.h>

#include <QtCore/QPoint>
#include <QtCore/QString>

#include <memory>

namespace Avogadro {
namespace QtGui {
class ScenePlugin;
class ToolPlugin;
} // namespace QtGui
namespace QtOpenGL {
class GLWidget;
}
namespace Rendering {
class Camera;
class GLRenderer;
} // namespace Rendering
} // namespace Avogadro

namespace Avogadro::QtPluginsTests {

/**
 * Drives a tool plugin's mouse, wheel and key handlers the way a user does,
 * in-process and without an OpenGL context.
 *
 * The harness owns a QtOpenGL::GLWidget that is never shown, so events go
 * through the real GLWidget routing (active tool, then default tool, the
 * navigation-modifier latch) and the tool gets the same setGLWidget(),
 * setGLRenderer() and setMolecule() calls it gets in the application.
 * Picking needs no GL context: GLRenderer::hits() ray casts the scene graph
 * on the CPU, and the harness applies the camera projection itself, which
 * GLRenderer::render() would otherwise do every frame.
 *
 * The molecule, its fixtures and the invariant checks come from a
 * CommandTestHarness, so a test can assert snapshot().differences() exactly
 * as the command tests do. Tests click atoms by index (pointOnAtom()), never
 * by pixel, so they do not depend on the camera or viewport.
 */
class ToolInteractionHarness
{
public:
  /** Logical size of the viewport, in pixels. */
  static constexpr int ViewportSize = 400;

  ToolInteractionHarness();
  ~ToolInteractionHarness();

  ToolInteractionHarness(const ToolInteractionHarness&) = delete;
  ToolInteractionHarness& operator=(const ToolInteractionHarness&) = delete;

  /** Molecule fixtures, snapshots, undo/redo and invariant checks. */
  CommandTestHarness& commands() { return m_commands; }
  const CommandTestHarness& commands() const { return m_commands; }
  QtGui::Molecule* molecule() const { return m_commands.molecule(); }

  QtOpenGL::GLWidget& widget() { return *m_widget; }
  Rendering::GLRenderer& renderer();
  Rendering::Camera& camera();

  /**
   * Add a scene plugin, enabled, so the scene has geometry to pick. The
   * widget's scene model takes ownership.
   */
  void addScenePlugin(QtGui::ScenePlugin* plugin);

  /**
   * Make @p tool the active tool. The widget takes ownership (as in the
   * application, where tools are children of the GLWidget).
   */
  void setActiveTool(QtGui::ToolPlugin* tool);

  /** As setActiveTool(), for the tool that gets events the active one leaves.
   */
  void setDefaultTool(QtGui::ToolPlugin* tool);

  // Replace the molecule with a CommandTestHarness fixture (see there), hand
  // it to the widget and its tools, re-enable the scene plugins for it,
  // rebuild the scene and fit the camera. Use these rather than
  // commands().build...(), which would leave the tools pointing at the
  // molecule it deletes.
  void buildMethanol();
  void buildPeroxideChain();
  void buildEmpty();

  /** Rebuild the scene from the molecule and reapply the projection. */
  void updateScene();

  /** Fit the camera to the scene, as the application does on load. */
  void resetCamera();

  /** @return The window position of @p atom's centre. */
  QPoint pointOnAtom(Index atom) const;

  /** @return The window position of the midpoint of @p bond. */
  QPoint pointOnBond(Index bond) const;

  /** @return A window position with no atom or bond under it. */
  QPoint emptyPoint() const;

  /** @return What the renderer picks at @p point (invalid if nothing). */
  Rendering::Identifier hitAt(const QPoint& point) const;

  // Each event is sent to the widget, then pending events are processed (so
  // a molecule change rebuilds the scene, as it would in the application)
  // and the projection is reapplied. @return Whether anyone accepted it.
  bool press(const QPoint& point, Qt::MouseButton button = Qt::LeftButton,
             Qt::KeyboardModifiers modifiers = Qt::NoModifier);
  bool move(const QPoint& point, Qt::MouseButtons buttons = Qt::NoButton,
            Qt::KeyboardModifiers modifiers = Qt::NoModifier);
  bool release(const QPoint& point, Qt::MouseButton button = Qt::LeftButton,
               Qt::KeyboardModifiers modifiers = Qt::NoModifier);
  bool dblClick(const QPoint& point, Qt::MouseButton button = Qt::LeftButton,
                Qt::KeyboardModifiers modifiers = Qt::NoModifier);
  bool wheel(const QPoint& point, int angleDeltaY,
             Qt::KeyboardModifiers modifiers = Qt::NoModifier);
  bool keyPress(int key, Qt::KeyboardModifiers modifiers = Qt::NoModifier,
                const QString& text = QString());
  bool keyRelease(int key, Qt::KeyboardModifiers modifiers = Qt::NoModifier,
                  const QString& text = QString());

  /** press() then release() at the same point. */
  void click(const QPoint& point, Qt::MouseButton button = Qt::LeftButton,
             Qt::KeyboardModifiers modifiers = Qt::NoModifier);

  /**
   * Press at @p from, move to @p to in @p steps equal steps with the button
   * held, then release at @p to.
   */
  void drag(const QPoint& from, const QPoint& to,
            Qt::MouseButton button = Qt::LeftButton,
            Qt::KeyboardModifiers modifiers = Qt::NoModifier, int steps = 4);

private:
  template <typename Build>
  void replaceMolecule(Build build);
  void useHarnessMolecule();
  void settle();

  CommandTestHarness m_commands;
  std::unique_ptr<QtOpenGL::GLWidget> m_widget;
};

} // namespace Avogadro::QtPluginsTests

#endif // AVOGADRO_TESTS_TOOLINTERACTIONHARNESS_H
