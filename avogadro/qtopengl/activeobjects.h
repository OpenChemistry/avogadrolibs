/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTOPENGL_ACTIVEOBJECTS_H
#define AVOGADRO_QTOPENGL_ACTIVEOBJECTS_H

#include "avogadroqtopenglexport.h"

#include <QtCore/QObject>

#include <QtCore/QPointer>

namespace Avogadro {
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

public slots:
  /** Set the active GLWidget. **/
  void setActiveGLWidget(GLWidget* glWidget);

private:
  ActiveObjects();
  ~ActiveObjects() override;
  Q_DISABLE_COPY(ActiveObjects)

  QPointer<GLWidget> m_glWidget = nullptr;
};

} // End QtOpenGL namespace
} // End Avogadro namespace

#endif // AVOGADRO_QTOPENGL_ACTIVEOBJECTS_H