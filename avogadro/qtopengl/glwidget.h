/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTOPENGL_GLWIDGET_H
#define AVOGADRO_QTOPENGL_GLWIDGET_H

#include "avogadroqtopenglexport.h"
#include "renderoptions.h"

#include <avogadro/qtgui/scenepluginmodel.h>
#include <avogadro/qtgui/toolplugin.h>
#include <avogadro/rendering/glrenderer.h>

#include <QImage>
#include <QPointer>
#include <QString>

#if QT_VERSION >= 0x060000
#include <QtOpenGLWidgets/QOpenGLWidget>
#else
#include <QOpenGLWidget>
#endif

namespace Avogadro {

namespace QtGui {
class Molecule;
}

namespace QtOpenGL {

/**
 * @class GLWidget glwidget.h <avogadro/qtopengl/glwidget.h>
 * @brief QOpenGLGLWidget derived object for displaying 3D molecular geometry.
 * @author Marcus D. Hanwell
 *
 * This class creates the GL context, and contains a renderer to render the
 * 3D molecular geometry.
 *
 * The GLWidget also manages a collection of ToolPlugins that are used to
 * respond to user input events. Use setTools() or addTool() to add tools to the
 * widget. Use setActiveTool() to indicate which tool is active. The active tool
 * will be given the opportunity to handle input events first. If the active
 * tool does not handle the event, the default tool will be used. If the default
 * tool also ignores the event, it will be passed to QOpenGLWidget's handlers.
 */

class AVOGADROQTOPENGL_EXPORT GLWidget : public QOpenGLWidget
{
  Q_OBJECT

public:
  explicit GLWidget(QWidget* parent = nullptr);
  ~GLWidget() override;

  /** Set the molecule the widget will render. */
  void setMolecule(QtGui::Molecule* molecule);

  /**
   * Get the molecule being rendered by the widget.
   * @{
   */
  QtGui::Molecule* molecule();
  const QtGui::Molecule* molecule() const;
  /** @}*/

  /** Get a reference to the renderer for the widget. */
  Rendering::GLRenderer& renderer() { return m_renderer; }

  /**
   * @return A list of the ToolPlugins owned by the GLWidget.
   */
  QList<QtGui::ToolPlugin*> tools() const { return m_tools; }

  /**
   * @return The active tool.
   */
  QtGui::ToolPlugin* activeTool() const { return m_activeTool; }

  /**
   * @return The default tool.
   */
  QtGui::ToolPlugin* defaultTool() const { return m_defaultTool; }

  /**
   * Get the GLWidget's ScenePluginModel, used to add, delete and modify the
   * scene plugin items.
   * @{
   */
  QtGui::ScenePluginModel& sceneModel() { return m_scenePlugins; }
  const QtGui::ScenePluginModel& sceneModel() const { return m_scenePlugins; }
  /** @}*/

  /**
   * Check if the GLWidget was able to acquire a context, and set up the
   * renderer correctly. If not valid, the error method may provide more
   * information.
   * @return true if value, false if not.
   */
  bool isValid() const { return m_renderer.isValid(); }

  /**
   * Get the error(s), if any, encountered when setting up the GLWidget.
   * @return A free form string containing errors encountered.
   */
  QString error() const { return m_renderer.error().c_str(); }

  /**
   * @brief Modifier reserved for camera navigation.
   *
   * A mouse gesture carrying this modifier is routed to the default
   * (navigation) tool regardless of which tool is currently active.
   * Defaults to Qt::AltModifier and is persisted in QSettings.
   */
  Qt::KeyboardModifiers navigationModifier() const;
  void setNavigationModifier(Qt::KeyboardModifiers modifier);

  /**
   * Render the current scene into an offscreen framebuffer and return it.
   *
   * The output is exactly options.size pixels (the view size times the device
   * pixel ratio if that is invalid), framed for its own aspect ratio rather
   * than cropped or letterboxed from the on-screen view. The widget needs a
   * current GL context, so it must have been shown at least once.
   *
   * The widget's on-screen state (renderer size, pixel ratio, projection and
   * background) is left exactly as it was, and the window is not resized.
   *
   * The render size (size times supersample) is limited to 8192 pixels per
   * side and to the GL implementation's texture, renderbuffer and viewport
   * limits; larger requests fail rather than being clamped. Memory use is
   * roughly 24 bytes per render pixel (8192 x 8192 needs about 1.5 GiB).
   *
   * @param options The size, framing and background to render with.
   * @param error If not null, receives a message when a null image is
   * returned.
   * @return The image, or a null image on failure.
   */
  QImage renderImage(const RenderOptions& options, QString* error = nullptr);

signals:
  void rendererInvalid();

public slots:
  /**
   * Update the scene plugins for the widget, this will generate geometry in
   * the scene etc.
   */
  void updateScene();

  /**
   * Request update of molecule properties (e.g., dipole moment)
   */
  void updateMolecule();

  /**
   * Clear the contents of the scene.
   */
  void clearScene();

  /** Reset the view to fit the entire scene. */
  void resetCamera();

  /** Reset the geometry when the molecule etc changes. */
  void resetGeometry();

  /**
   * Make the tools in toolList available to the GLWidget. The GLWidget takes
   * ownership of the tools.
   */
  void setTools(const QList<QtGui::ToolPlugin*>& toolList);

  /**
   * Make tool available to the GLWidget. The GLWidget takes ownership of the
   * tool.
   */
  void addTool(QtGui::ToolPlugin* tool);

  /**
   * Set the active tool. This is the tool that will be used to handle input
   * events first.
   * @{
   */
  void setActiveTool(const QString& name);
  void setActiveTool(QtGui::ToolPlugin* tool);
  /**@}*/

  /**
   * Set the default tool. This is the tool that will be used to handle input
   * events that are ignored by the active tool.
   * @{
   */
  void setDefaultTool(const QString& name);
  void setDefaultTool(QtGui::ToolPlugin* tool);
  /**@}*/

  /**
   * Request a repaint. Multiple requests before the next frame are
   * compressed into one, so camera moves stay interactive.
   */
  void requestUpdate();

protected:
  /** This is where the GL context is initialized. */
  void initializeGL() override;

  /** Take care of resizing the context. */
  void resizeGL(int width, int height) override;

  /** Main entry point for all GL rendering. */
  void paintGL() override;

  /** Reimplemented from QOpenGLWidget @{ */
  void mouseDoubleClickEvent(QMouseEvent*) override;
  void mousePressEvent(QMouseEvent*) override;
  void mouseMoveEvent(QMouseEvent*) override;
  void mouseReleaseEvent(QMouseEvent*) override;
  void wheelEvent(QWheelEvent*) override;
  void keyPressEvent(QKeyEvent*) override;
  void keyReleaseEvent(QKeyEvent*) override;
  /** @} */

private:
  bool isNavigationMouseGesture(const QMouseEvent* event) const;
  bool isNavigationKeyGesture(const QKeyEvent* event) const;

  QPointer<QtGui::Molecule> m_molecule;
  QList<QtGui::ToolPlugin*> m_tools;
  QtGui::ToolPlugin* m_activeTool;
  QtGui::ToolPlugin* m_defaultTool;
  Rendering::GLRenderer m_renderer;
  float m_pixelRatio = 0.0f;
  QtGui::ScenePluginModel m_scenePlugins;

  Qt::KeyboardModifiers m_navigationModifier;
  bool m_navigationDrag = false;
  /** True while updateScene() is building; guards against re-entry. */
  bool m_updatingScene = false;
  /** A change arrived mid-build; the scene must be rebuilt afterwards. */
  bool m_sceneUpdatePending = false;
};

} // namespace QtOpenGL
} // namespace Avogadro

#endif // AVOGADRO_QTOPENGL_GLWIDGET_H
