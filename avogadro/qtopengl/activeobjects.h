/* This source file is part of the Avogadro project.
   It is released under the 3-Clause BSD License, see "LICENSE". */

#ifndef AVOGADRO_QTOPENGL_ACTIVEOBJECTS_H
#define AVOGADRO_QTOPENGL_ACTIVEOBJECTS_H

#include "avogadroqtopenglexport.h"

#include <QtCore/QObject>

// #include "glwidget.h"

#include <QtCore/QPointer>

class QWidget;
namespace Avogadro {
namespace QtGui {
class Molecule;
}
namespace QtOpenGL {
class GLWidget;
/**
 * @class ActiveObjects activeobjects.h <avogadro/qtopengl/activeobjects.h>
 * @brief Singleton to provide access to active objects.
 *
 * This class provides access to the active objects in the running application.
 * If you write an application using the Avogadro libraries you need to keep
 * this class updated with changes in active objects in order for built in
 * features to work as expected.
 *
 * All returned objects are owned by the running application, nullptr indicates
 * that there is no currently active object of that type.
 */
class AVOGADROQTOPENGL_EXPORT ActiveObjects : public QObject
{
  Q_OBJECT

public:
  /** Return a reference to the singleton instance that can be queried. */
  static ActiveObjects& instance();

  /** Get the active GLWidget. **/
  GLWidget* activeGLWidget() const;

  /**
   * Get the active widget (more general, could be GLWidget, vtkGLWidget, etc).
   */
  QWidget* activeWidget() const;

  /**
   * Get the active molecule.
   */
  QtGui::Molecule* activeMolecule() const;

public slots:
  /** Set the active GLWidget. */
  void setActiveGLWidget(GLWidget* glWidget);

  /** Set the active widget (GLWidget, vtkGLWidget, etc). */
  void setActiveWidget(QWidget* widget);

  /** Set the active widget (GLWidget, vtkGLWidget, etc). */
  void setActiveMolecule(QtGui::Molecule* molecule);

signals:
  /** The active GL widget changed. */
  void activeGLWidgetChanged(GLWidget* glWidget);

  /** The active widget changed (GLWidget, vtkGLWidget, etc). */
  void activeWidgetChanged(QWidget* widget);

  /** The active molecule changed. */
  void activeMoleculeChanged(QtGui::Molecule* molecule);

private:
  ActiveObjects();
  ~ActiveObjects() override;
  Q_DISABLE_COPY(ActiveObjects)

  GLWidget* m_glWidget = nullptr;
  QWidget* m_widget = nullptr;
  QtGui::Molecule* m_molecule = nullptr;
};

} // namespace QtOpenGL
} // namespace Avogadro

#endif // AVOGADRO_QTOPENGL_ACTIVEOBJECTS_H
