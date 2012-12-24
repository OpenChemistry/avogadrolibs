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
#include <avogadro/qtgui/molecule.h>
#include <avogadro/core/vector.h>
#include <avogadro/rendering/camera.h>
#include <avogadro/rendering/glrenderer.h>

#include <QtGui/QKeyEvent>
#include <QtGui/QMouseEvent>
#include <QtGui/QWheelEvent>

using Avogadro::Core::Atom;
using Avogadro::Core::Bond;
using Avogadro::QtGui::Molecule;

using Avogadro::Rendering::Primitive;

namespace Avogadro {
namespace QtOpenGL {

Editor::Editor(GLWidget *widget)
  : m_glWidget(widget),
    m_molecule(0),
    m_clickedObject(Primitive::Identifier()),
    m_newObject(Primitive::Identifier()),
    m_pressedButtons(Qt::NoButton)
{
}

Editor::~Editor()
{
}

void Editor::mousePressEvent(QMouseEvent *e)
{
  updatePressedButtons(e, false);
  m_clickPosition = e->pos();

  if (m_pressedButtons & Qt::LeftButton) {
    m_clickedObject = m_glWidget->renderer().hit(e->pos().x(), e->pos().y());

    if (m_clickedObject.molecule &&
        m_clickedObject.molecule != static_cast<Core::Molecule *>(m_molecule)) {
      e->ignore();
      return;
    }

    switch (m_clickedObject.type) {
    case Primitive::Invalid: {
      // Add an atom at the clicked position
      Atom newAtom;
      newAtom = m_molecule->addAtom(m_atomicNumber);
      m_clickedObject.type = Primitive::Atom;
      m_clickedObject.molecule = m_molecule;
      m_clickedObject.index = newAtom.index();
      if (newAtom.isValid()) {
        Vector2f windowPos(e->posF().x(), e->posF().y());
        Vector3f newPos = m_glWidget->renderer().camera().unProject(windowPos);
        newAtom.setPosition3d(newPos.cast<double>());
        e->accept();
        emit moleculeChanged();
        return;
      }
      break;
    }
    case Primitive::Atom:
      e->accept();
      return;
    case Primitive::Bond:
      Bond bond = m_molecule->bond(m_clickedObject.index);
      bond.setOrder((bond.order() % static_cast<unsigned char>(3))
                    + static_cast<unsigned char>(1));
      emit moleculeChanged();
      e->accept();
      return;
    }
  }
  else if (m_pressedButtons & Qt::RightButton) {
    // Delete the current primitive
    m_clickedObject = m_glWidget->renderer().hit(e->pos().x(), e->pos().y());

    if (m_clickedObject.molecule != m_molecule) {
      e->ignore();
      return;
    }

    switch (m_clickedObject.type) {
    case Primitive::Invalid:
      e->ignore();
      return;
    case Primitive::Atom:
      e->accept();
      m_molecule->removeAtom(m_clickedObject.index);
      emit moleculeChanged();
      return;
    case Primitive::Bond:
      e->accept();
      m_molecule->removeBond(m_clickedObject.index);
      emit moleculeChanged();
      return;
    }
  }
}

void Editor::mouseReleaseEvent(QMouseEvent *e)
{
  updatePressedButtons(e, true);
  e->ignore();

  if (m_clickedObject.type == Primitive::Invalid)
    return;

  switch (e->button()) {
  case Qt::LeftButton:
    if (e->pos() != m_clickPosition) {
      // If the mouse has moved, we added a new atom bonded to the clicked atom.
      // Nothing to do but accept and reset.
      e->accept();
      reset();
    }
    else {
      // Otherwise, change the type of the clicked atom.
      if (m_clickedObject.type == Primitive::Atom) {
        Core::Atom atom = m_clickedObject.molecule->atom(m_clickedObject.index);
        atom.setAtomicNumber(m_atomicNumber);
        emit moleculeChanged();
        e->accept();
        reset();
        return;
      }
    }
    break;
  default:
    break;
  }
}

void Editor::mouseMoveEvent(QMouseEvent *e)
{
  e->ignore();
  if (m_pressedButtons & Qt::LeftButton) {
    if (m_clickedObject.type == Primitive::Atom &&
        m_molecule == m_clickedObject.molecule) {
      Core::Atom newAtom;
      // Add a new atom bonded to the clicked atom
      if (m_newObject.type == Primitive::Invalid) {
        Core::Atom clickedAtom = m_clickedObject.molecule->atom(
              m_clickedObject.index);
        newAtom = m_molecule->addAtom(m_atomicNumber);
        newAtom.setPosition3d(clickedAtom.position3d());
        m_molecule->addBond(clickedAtom, newAtom);
        m_newObject.type = Primitive::Atom;
        m_newObject.molecule = m_clickedObject.molecule;
        m_newObject.index = newAtom.index();
      }
      else if (m_newObject.type == Primitive::Atom) {
        newAtom = m_newObject.molecule->atom(m_newObject.index);
      }
      else {
        return;
      }

      if (newAtom.isValid()) {
        Vector2f windowPos(e->posF().x(), e->posF().y());
        Vector3f oldPos(newAtom.position3d().cast<float>());
        Vector3f newPos = m_glWidget->renderer().camera().unProject(windowPos,
                                                                    oldPos);
        newAtom.setPosition3d(newPos.cast<double>());

        e->accept();
        emit moleculeChanged();
        return;
      }
    }
  }
}

void Editor::mouseDoubleClickEvent(QMouseEvent *e)
{
  e->ignore();
}

void Editor::wheelEvent(QWheelEvent *e)
{
  e->ignore();
}

void Editor::keyPressEvent(QKeyEvent *e)
{
  e->ignore();
}

void Editor::keyReleaseEvent(QKeyEvent *e)
{
  e->ignore();
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
