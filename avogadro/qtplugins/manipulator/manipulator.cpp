/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2012-13 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "manipulator.h"

#include <avogadro/core/vector.h>

#include <avogadro/qtgui/molecule.h>

#include <avogadro/qtopengl/glwidget.h>

#include <avogadro/rendering/camera.h>
#include <avogadro/rendering/glrenderer.h>

#include <QtGui/QAction>
#include <QtGui/QKeyEvent>
#include <QtGui/QMouseEvent>
#include <QtGui/QWheelEvent>

using Avogadro::Core::Atom;
using Avogadro::Core::Bond;
using Avogadro::QtGui::Molecule;

using Avogadro::Rendering::Primitive;

namespace Avogadro {
namespace QtPlugins {

Manipulator::Manipulator(QObject *parent_)
  : QtGui::ToolPlugin(parent_),
    m_activateAction(new QAction(this)),
    m_molecule(NULL),
    m_glWidget(NULL),
    m_object(Primitive::Identifier()),
    m_pressedButtons(Qt::NoButton)
{
  m_activateAction->setText(tr("Manipulate"));
}

Manipulator::~Manipulator()
{
}

QWidget *Manipulator::toolWidget() const
{
  return NULL;
}

QUndoCommand * Manipulator::mousePressEvent(QMouseEvent *e)
{
  if (!m_glWidget)
    return NULL;

  updatePressedButtons(e, false);
  m_lastMousePosition = e->pos();

  if (m_pressedButtons & Qt::LeftButton) {
    m_object = m_glWidget->renderer().hit(e->pos().x(), e->pos().y());

    switch (m_object.type) {
    case Primitive::Atom:
      e->accept();
      return NULL;
    case Primitive::Bond: {
      Bond bond = m_molecule->bond(m_object.index);
      unsigned char currentOrder = bond.order();
      unsigned char maxOrder = static_cast<unsigned char>(3U);
      unsigned char increment = static_cast<unsigned char>(1U);
      bond.setOrder((currentOrder % maxOrder) + increment);
      m_molecule->emitChanged(Molecule::Bonds | Molecule::Modified);
      e->accept();
      return NULL;
    }
    default:
      break;
    }
  }

  return NULL;
}

QUndoCommand * Manipulator::mouseReleaseEvent(QMouseEvent *e)
{
  if (!m_glWidget)
    return NULL;

  updatePressedButtons(e, true);

  if (m_object.type == Primitive::Invalid)
    return NULL;

  switch (e->button()) {
  case Qt::LeftButton:
  case Qt::RightButton:
    resetObject();
    e->accept();
    break;
  default:
    break;
  }

  return NULL;
}

QUndoCommand * Manipulator::mouseMoveEvent(QMouseEvent *e)
{
  e->ignore();
  if (m_pressedButtons & Qt::LeftButton) {
    if (m_object.type == Primitive::Atom) {
      if (m_object.molecule == m_molecule) {
        // Update atom position
        Atom atom = m_molecule->atom(m_object.index);
        Vector2f windowPos(e->posF().x(), e->posF().y());
        Vector3f oldPos(atom.position3d().cast<float>());
        Vector3f newPos = m_glWidget->renderer().camera().unProject(windowPos,
                                                                    oldPos);
        atom.setPosition3d(newPos.cast<double>());
        m_molecule->emitChanged(Molecule::Atoms | Molecule::Modified);
        e->accept();
      }
    }
  }
  return NULL;
}

void Manipulator::updatePressedButtons(QMouseEvent *e, bool release)
{
  /// @todo Use modifier keys on mac
  if (release)
    m_pressedButtons &= e->buttons();
  else
    m_pressedButtons |= e->buttons();
}

} // namespace QtPlugins
} // namespace Avogadro
