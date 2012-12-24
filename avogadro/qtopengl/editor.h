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

namespace QtGui {
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

  /// Set the atomic number used for new atoms.
  void setAtomicNumber(unsigned char atomicNum) { m_atomicNumber = atomicNum; }

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

  void setMolecule(QtGui::Molecule *mol) { m_molecule = mol; }
  QtGui::Molecule * molecule() { return m_molecule; }

signals:
  /// HACK -- the molecule should notify the scene plugins to update.
  void moleculeChanged();

private:
  /// Update the currently pressed buttons, accounting for modifier keys.
  /// @todo Account for modifier keys.
  void updatePressedButtons(QMouseEvent *, bool release);

  void reset()
  {
    m_clickedObject = Rendering::Primitive::Identifier();
    m_newObject = Rendering::Primitive::Identifier();
    m_clickPosition = QPoint();
    m_pressedButtons = Qt::NoButton;
  }

  GLWidget *m_glWidget;
  QtGui::Molecule *m_molecule;
  unsigned char m_atomicNumber;
  Rendering::Primitive::Identifier m_clickedObject;
  Rendering::Primitive::Identifier m_newObject;
  Qt::MouseButtons m_pressedButtons;
  QPoint m_clickPosition;
};

} // namespace QtOpenGL
} // namespace Avogadro

#endif // AVOGADRO_QTOPENGL_NAVIGATOR_H
