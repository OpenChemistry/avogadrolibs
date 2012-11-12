/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2012 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef AVOGADRO_QTOPENGL_EDITOR_H
#define AVOGADRO_QTOPENGL_EDITOR_H

#include <QtCore/QObject>

#include <avogadro/rendering/primitive.h>

#include <QtCore/QPoint>
#include <QtCore/Qt> // for Qt:: namespace

class QKeyEvent;
class QMouseEvent;
class QWheelEvent;

namespace Avogadro {

namespace Core {
class Molecule;
}

namespace QtOpenGL {
class GLWidget;

/**
 * @class Editor editor.h <avogadro/qtopengl/editor.h>
 * @brief The Editor class manipulates a molecule's geometry.
 * @author David C. Lonie
 */
class Editor : public QObject
{
  Q_OBJECT
public:
  explicit Editor(GLWidget *widget);
  ~Editor();

  /// Respond to user input
  void mousePressEvent(QMouseEvent *);

  /// Respond to user input
  void mouseReleaseEvent(QMouseEvent *);

  /// Respond to user input
  void mouseMoveEvent(QMouseEvent *);

  /// Respond to user input
  void mouseDoubleClickEvent(QMouseEvent *);

  /// Respond to user input
  void wheelEvent(QWheelEvent *);

  /// Respond to user input
  void keyPressEvent(QKeyEvent *);

  /// Respond to user input
  void keyReleaseEvent(QKeyEvent *);

  void setMolecule(Core::Molecule *mol) { m_molecule = mol; }
  Core::Molecule * molecule() { return m_molecule; }

signals:
  /// HACK -- the molecule should notify the scene plugins to update.
  void moleculeChanged();

private:
  /// Update the currently pressed buttons, accounting for modifier keys.
  /// @todo Account for modifier keys.
  void updatePressedButtons(QMouseEvent *, bool release);

  void resetObject() { m_object = Rendering::Primitive::Identifier(); }

  GLWidget *m_glWidget;
  Core::Molecule *m_molecule;
  Rendering::Primitive::Identifier m_object;
  Qt::MouseButtons m_pressedButtons;
  QPoint m_lastMousePosition;
};

} // namespace QtOpenGL
} // namespace Avogadro

#endif // AVOGADRO_QTOPENGL_NAVIGATOR_H
