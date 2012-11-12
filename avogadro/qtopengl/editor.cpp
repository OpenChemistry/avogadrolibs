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

#include "editor.h"

#include "glwidget.h"

#include <avogadro/core/atom.h>
#include <avogadro/core/bond.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/vector.h>
#include <avogadro/rendering/camera.h>
#include <avogadro/rendering/glrenderer.h>

#include <QtGui/QKeyEvent>
#include <QtGui/QMouseEvent>
#include <QtGui/QWheelEvent>

using Avogadro::Core::Atom;
using Avogadro::Core::Bond;
using Avogadro::Core::Molecule;

using Avogadro::Rendering::Primitive;

namespace Avogadro {
namespace QtOpenGL {

Editor::Editor(GLWidget *widget)
  : m_glWidget(widget),
    m_molecule(0),
    m_object(Primitive::Identifier()),
    m_pressedButtons(Qt::NoButton)
{
}

Editor::~Editor()
{
}

void Editor::mousePressEvent(QMouseEvent *e)
{
  updatePressedButtons(e, false);
  m_lastMousePosition = e->pos();

  if (m_pressedButtons & Qt::LeftButton) {
    m_object = m_glWidget->renderer().hit(e->pos().x(), e->pos().y());

    if (m_object.molecule != m_molecule) {
      e->ignore();
      return;
    }

    switch (m_object.type) {
    case Primitive::Invalid:
      e->ignore();
      return;
    case Primitive::Atom:
      e->accept();
      qDebug("Atom clicked: index=%lu\n", m_object.index);
      return;
    case Primitive::Bond:
      e->accept();
      qDebug("Bond clicked: index=%lu\n", m_object.index);
      return;
    }
  }
  else if (m_pressedButtons & Qt::RightButton) {
    // Delete the current primitive
    m_object = m_glWidget->renderer().hit(e->pos().x(), e->pos().y());

    if (m_object.molecule != m_molecule) {
      e->ignore();
      return;
    }

    switch (m_object.type) {
    case Primitive::Invalid:
      e->ignore();
      return;
    case Primitive::Atom:
      e->accept();
      /// @todo -- no removeAtom method.
//      m_object.molecule->removeAtom(m_object.index);
//      emit moleculeChanged();
      return;
    case Primitive::Bond:
      e->accept();
      /// @todo removeBond is declared, but not implemented
//      m_molecule->removeBond(m_object.index);
//      emit moleculeChanged();
      return;
    }
  }
}

void Editor::mouseReleaseEvent(QMouseEvent *e)
{
  updatePressedButtons(e, true);
  e->ignore();
  if (m_object.type != Primitive::Invalid) {
    resetObject();
    e->accept();
  }
}

void Editor::mouseMoveEvent(QMouseEvent *e)
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
        emit moleculeChanged();
        e->accept();
      }
    }
  }
}

void Editor::mouseDoubleClickEvent(QMouseEvent *e)
{
}

void Editor::wheelEvent(QWheelEvent *e)
{
}

void Editor::keyPressEvent(QKeyEvent *e)
{
}

void Editor::keyReleaseEvent(QKeyEvent *e)
{
}

void Editor::updatePressedButtons(QMouseEvent *e, bool release)
{
  /// @todo Use modifier keys on mac
  if (release)
    m_pressedButtons &= e->buttons();
  else
    m_pressedButtons |= e->buttons();
}

} // namespace QtOpenGL
} // namespace Avogadro
