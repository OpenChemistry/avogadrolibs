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

#include <avogadro/qtgui/rwmolecule.h>
#include <avogadro/qtgui/molecule.h>

#include <avogadro/qtopengl/glwidget.h>

#include <avogadro/rendering/camera.h>
#include <avogadro/rendering/glrenderer.h>

#include <QtWidgets/QAction>
#include <QtGui/QIcon>
#include <QtGui/QKeyEvent>
#include <QtGui/QMouseEvent>
#include <QtGui/QWheelEvent>

using Avogadro::Core::Atom;
using Avogadro::Core::Bond;
using Avogadro::QtGui::Molecule;

namespace Avogadro {
namespace QtPlugins {

using QtGui::RWAtom;
using QtGui::RWBond;
using QtGui::Molecule;
using QtGui::RWMolecule;
using Rendering::Identifier;

Manipulator::Manipulator(QObject *parent_)
  : QtGui::ToolPlugin(parent_),
    m_activateAction(new QAction(this)),
    m_molecule(NULL),
    m_renderer(NULL),
    m_pressedButtons(Qt::NoButton)
{
  m_activateAction->setText(tr("Manipulate"));
  m_activateAction->setIcon(QIcon(":/icons/manipulator.png"));
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
  if (!m_renderer)
    return NULL;

  updatePressedButtons(e, false);
  m_lastMousePosition = e->pos();

  if (m_molecule) {
    m_molecule->setInteractive(true);
  }

  if (m_pressedButtons & Qt::LeftButton) {
    m_object = m_renderer->hit(e->pos().x(), e->pos().y());

    switch (m_object.type) {
    case Rendering::AtomType:
      e->accept();
      return NULL;
    default:
      break;
    }
  }

  return NULL;
}

QUndoCommand * Manipulator::mouseReleaseEvent(QMouseEvent *e)
{
  if (!m_renderer)
    return NULL;

  updatePressedButtons(e, true);

  if (m_object.type == Rendering::InvalidType)
    return NULL;

  if (m_molecule) {
    m_molecule->setInteractive(false);
  }

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
  const Core::Molecule* mol = &m_molecule->molecule();
  if (m_pressedButtons & Qt::LeftButton
      && m_object.type == Rendering::AtomType
      && m_object.molecule == mol) {
    // Update atom position
    RWAtom atom = m_molecule->atom(m_object.index);
    Vector2f windowPos(e->localPos().x(), e->localPos().y());
    Vector3f oldPos(atom.position3d().cast<float>());
    Vector3f newPos = m_renderer->camera().unProject(windowPos, oldPos);
    atom.setPosition3d(newPos.cast<double>());
    m_molecule->emitChanged(Molecule::Atoms | Molecule::Modified);
    e->accept();
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
