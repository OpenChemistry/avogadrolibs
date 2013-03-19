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

#include "editor.h"

#include "editortoolwidget.h"

#include <avogadro/core/atom.h>
#include <avogadro/core/bond.h>
#include <avogadro/core/elements.h>
#include <avogadro/core/vector.h>

#include <avogadro/qtgui/molecule.h>

#include <avogadro/qtopengl/glwidget.h>

#include <avogadro/rendering/camera.h>
#include <avogadro/rendering/glrenderer.h>

#include <QtGui/QAction>
#include <QtGui/QComboBox>
#include <QtGui/QKeyEvent>
#include <QtGui/QMouseEvent>
#include <QtGui/QVBoxLayout>
#include <QtGui/QWheelEvent>
#include <QtGui/QWidget>

#include <QtCore/QDebug>
#include <QtCore/QTimer>

#include <limits>

namespace {
const unsigned char INVALID_ATOMIC_NUMBER =
    std::numeric_limits<unsigned char>::max();
}

namespace Avogadro {
namespace QtPlugins {

using Core::Atom;
using Core::Bond;
using QtGui::Molecule;
using Rendering::Identifier;
using QtOpenGL::GLWidget;

Editor::Editor(QObject *parent_)
  : QtGui::ToolPlugin(parent_),
    m_activateAction(new QAction(this)),
    m_molecule(NULL),
    m_glWidget(NULL),
    m_toolWidget(new EditorToolWidget(qobject_cast<QWidget*>(parent_))),
    m_pressedButtons(Qt::NoButton),
    m_clickedAtomicNumber(INVALID_ATOMIC_NUMBER),
    m_bondAdded(false)
{
  m_activateAction->setText(tr("Draw"));
  reset();
}

Editor::~Editor()
{
}

QWidget *Editor::toolWidget() const
{
  return m_toolWidget;
}

QUndoCommand *Editor::mousePressEvent(QMouseEvent *e)
{
  clearKeyPressBuffer();
  if (!m_glWidget)
    return NULL;

  updatePressedButtons(e, false);
  m_clickPosition = e->pos();

  if (m_pressedButtons & Qt::LeftButton) {
    m_clickedObject = m_glWidget->renderer().hit(e->pos().x(), e->pos().y());

    switch (m_clickedObject.type) {
    case Rendering::InvalidType:
      emptyLeftClick(e);
      return NULL;
    case Rendering::AtomType:
      atomLeftClick(e);
      return NULL;
    case Rendering::BondType:
      bondLeftClick(e);
      return NULL;
    }
  }
  else if (m_pressedButtons & Qt::RightButton) {
    m_clickedObject = m_glWidget->renderer().hit(e->pos().x(), e->pos().y());

    switch (m_clickedObject.type) {
    case Rendering::AtomType:
      atomRightClick(e);
      return NULL;
    case Rendering::BondType:
      bondRightClick(e);
      return NULL;
    default:
      break;
    }
  }

  return NULL;
}

QUndoCommand *Editor::mouseReleaseEvent(QMouseEvent *e)
{
  if (!m_glWidget)
    return NULL;

  updatePressedButtons(e, true);

  if (m_clickedObject.type == Rendering::InvalidType)
    return NULL;

  switch (e->button()) {
  case Qt::LeftButton:
  case Qt::RightButton:
    reset();
    e->accept();
    break;
  default:
    break;
  }

  return NULL;
}

QUndoCommand *Editor::mouseMoveEvent(QMouseEvent *e)
{
  if (!m_glWidget)
    return NULL;

  if (m_pressedButtons & Qt::LeftButton)
    if (m_clickedObject.type == Rendering::AtomType)
      atomLeftDrag(e);

  return NULL;
}

QUndoCommand *Editor::keyPressEvent(QKeyEvent *e)
{
  if (e->text().isEmpty())
    return NULL;

  e->accept();

  // Set a timer to clear the buffer on first keypress:
  if (m_keyPressBuffer.isEmpty())
    QTimer::singleShot(2000, this, SLOT(clearKeyPressBuffer()));

  m_keyPressBuffer.append(m_keyPressBuffer.isEmpty()
                          ? e->text().toUpper()
                          : e->text().toLower());

  if (m_keyPressBuffer.size() >= 3) {
    clearKeyPressBuffer();
    return NULL;
  }

  bool ok = false;
  int atomicNum = m_keyPressBuffer.toInt(&ok);
  if (!ok || atomicNum <= 0 || atomicNum > Core::Elements::elementCount()) {
    atomicNum = Core::Elements::atomicNumberFromSymbol(
          m_keyPressBuffer.toStdString());
  }

  if (atomicNum > 0 || atomicNum <= Core::Elements::elementCount())
    m_toolWidget->setAtomicNumber(static_cast<unsigned char>(atomicNum));

  return NULL;
}

void Editor::updatePressedButtons(QMouseEvent *e, bool release)
{
  /// @todo Use modifier keys on mac
  if (release)
    m_pressedButtons &= e->buttons();
  else
    m_pressedButtons |= e->buttons();
}

void Editor::reset()
{
  m_clickedObject = Identifier();
  m_newObject = Identifier();
  m_bondedAtom = Identifier();
  m_clickPosition = QPoint();
  m_pressedButtons = Qt::NoButton;
  m_clickedAtomicNumber = INVALID_ATOMIC_NUMBER;
  m_bondAdded = false;
}

void Editor::emptyLeftClick(QMouseEvent *e)
{
  // Add an atom at the clicked position
  Vector2f windowPos(e->posF().x(), e->posF().y());
  Vector3f atomPos = m_glWidget->renderer().camera().unProject(windowPos);
  Atom newAtom = m_molecule->addAtom(m_toolWidget->atomicNumber());
  newAtom.setPosition3d(atomPos.cast<double>());

  // Update the clicked object
  m_clickedObject.type = Rendering::AtomType;
  m_clickedObject.molecule = m_molecule;
  m_clickedObject.index = newAtom.index();

  // Emit changed signal
  m_molecule->emitChanged(Molecule::Atoms | Molecule::Modified);

  e->accept();
}

void Editor::atomLeftClick(QMouseEvent *e)
{
  Atom atom = m_clickedObject.molecule->atom(m_clickedObject.index);
  if (atom.isValid()) {
    // Store the original atomic number of the clicked atom before updating it.
    unsigned char atomicNumber = m_toolWidget->atomicNumber();
    if (atom.atomicNumber() != atomicNumber) {
      m_clickedAtomicNumber = atom.atomicNumber();
      atom.setAtomicNumber(atomicNumber);
      m_molecule->emitChanged(Molecule::Atoms | Molecule::Modified);
    }
    e->accept();
  }
}

void Editor::bondLeftClick(QMouseEvent *e)
{
  Bond bond = m_clickedObject.molecule->bond(m_clickedObject.index);
  unsigned char order = m_toolWidget->bondOrder();
  if (order != bond.order()) {
    bond.setOrder(order);
    m_molecule->emitChanged(Molecule::Bonds | Molecule::Modified);
  }
  e->accept();
}

void Editor::atomRightClick(QMouseEvent *e)
{
  e->accept();
  m_molecule->removeAtom(m_clickedObject.index);
  m_molecule->emitChanged(Molecule::Atoms | Molecule::Removed);
}

void Editor::bondRightClick(QMouseEvent *e)
{
  e->accept();
  m_molecule->removeBond(m_clickedObject.index);
  m_molecule->emitChanged(Molecule::Bonds | Molecule::Removed);
}

void Editor::atomLeftDrag(QMouseEvent *e)
{
  // Always accept move events when atoms are clicked:
  e->accept();

  // Build up a MoleculeChanges bitfield
  Molecule::MoleculeChanges changes = Molecule::NoChange;

  // Get the list of hits at the current mouse position:
  std::multimap<float, Identifier> hits =
      m_glWidget->renderer().hits(e->pos().x(), e->pos().y());

  // Check if the previously clicked atom is still under the mouse.
  float depth = -1.0f;
  for (std::multimap<float, Rendering::Identifier>::const_iterator
       it = hits.begin(), itEnd = hits.end(); it != itEnd; ++it) {
    if (it->second == m_clickedObject) {
      depth = it->first;
      break;
    }
  }

  // If the clicked atom is under the mouse...
  if (depth >= 0.f) {
    // ...and we've created a new atom, remove the new atom and reset the
    // clicked atom's atomic number
    if (m_newObject.type == Rendering::AtomType
        && m_molecule == m_newObject.molecule) {
      m_molecule->removeAtom(m_newObject.index);
      changes |= Molecule::Atoms | Molecule::Bonds | Molecule::Removed;
      m_newObject = Identifier();
      Atom atom = m_clickedObject.molecule->atom(m_clickedObject.index);
      if (atom.atomicNumber() != m_toolWidget->atomicNumber()) {
        m_clickedAtomicNumber = atom.atomicNumber();
        atom.setAtomicNumber(m_toolWidget->atomicNumber());
        changes |= Molecule::Atoms | Molecule::Modified;
      }
      m_molecule->emitChanged(changes);
      return;
    }

    // If there is no new atom, do nothing.
    return;
  }

  // If we get here, the clicked atom is no longer under the cursor.

  // If the clicked atom's identity has been changed from the initial click,
  // reset its atomic number
  if (m_clickedAtomicNumber != INVALID_ATOMIC_NUMBER) {
    Atom clickedAtom = m_clickedObject.molecule->atom(m_clickedObject.index);
    clickedAtom.setAtomicNumber(m_clickedAtomicNumber);
    m_clickedAtomicNumber = INVALID_ATOMIC_NUMBER;
    changes |= Molecule::Atoms | Molecule::Modified;
  }

  // Does a bonded atom already exist?
  if (m_bondedAtom.isValid()) {
    // Is it still under the mouse?
    depth = -1.0f;
    for (std::multimap<float, Identifier>::const_iterator
         it = hits.begin(), itEnd = hits.end(); it != itEnd; ++it) {
      if (it->second == m_bondedAtom) {
        depth = it->first;
        break;
      }
    }

    // If the bonded atom is no longer under the mouse, remove the bond.
    if (depth < 0.f) {
      Atom bondedAtom = m_bondedAtom.molecule->atom(m_bondedAtom.index);
      Atom clickedAtom = m_clickedObject.molecule->atom(m_clickedObject.index);
      if (m_bondAdded && m_molecule->removeBond(clickedAtom, bondedAtom))
        changes |= Molecule::Bonds | Molecule::Removed;
      m_bondedAtom = Identifier();
      m_bondAdded = false;
    }
  }

  // Is there another atom under the cursor, besides newAtom? If so, we'll draw
  // a bond to it.
  Identifier atomToBond;
  for (std::multimap<float, Identifier>::const_iterator
       it = hits.begin(), itEnd = hits.end(); it != itEnd; ++it) {
    const Identifier &ident = it->second;
    // Are we on an atom
    if (ident.type == Rendering::AtomType)
      // besides the one that was clicked or a new atom
      if (ident != m_newObject && ident != m_clickedObject) {
        // then we have an atom that we should be drawing a bond to.
        atomToBond = ident;
        break;
    }
  }

  if (atomToBond.isValid()) {
    // If we have a newAtom, destroy it
    if (m_newObject.type == Rendering::AtomType) {
      if (m_molecule->removeAtom(m_newObject.index))
        changes |= Molecule::Atoms | Molecule::Bonds | Molecule::Removed;
      m_newObject = Identifier();
    }

    // Skip the rest of this block if atomToBond is already bonded
    if (m_bondedAtom != atomToBond) {
      // If the currently bonded atom exists, break the bond
      if (m_bondedAtom.isValid()) {
        if (m_molecule->removeBond(
              m_bondedAtom.molecule->atom(m_bondedAtom.index),
              m_clickedObject.molecule->atom(m_clickedObject.index))) {
          changes |= Molecule::Bonds | Molecule::Removed;
        }
        m_bondedAtom = Identifier();
      }

      // Create a new bond between clicked atom and atomToBond.
      Atom clickedAtom = m_clickedObject.molecule->atom(m_clickedObject.index);
      Atom bondedAtom = atomToBond.molecule->atom(atomToBond.index);
      if (!m_molecule->bond(clickedAtom, bondedAtom).isValid()) {
        m_molecule->addBond(clickedAtom, bondedAtom, m_toolWidget->bondOrder());
        m_bondAdded = true;
      }
      m_bondedAtom = atomToBond;
      changes |= Molecule::Bonds | Molecule::Added;
    }

    m_molecule->emitChanged(changes);
    return;
  }

  // If we make it here, the cursor is not over any existing atom, with the
  // possible exception of a new atom we've added that's bonded to clicked atom.
  // We just need to create the new atom (if we haven't already), then update
  // its position.

  Atom newAtom;
  if (!m_newObject.isValid()) {
    // Add a new atom bonded to the clicked atom
    Atom clickedAtom = m_clickedObject.molecule->atom(m_clickedObject.index);
    newAtom = m_molecule->addAtom(m_toolWidget->atomicNumber());
    m_molecule->addBond(clickedAtom, newAtom, m_toolWidget->bondOrder());
    changes |= Molecule::Atoms | Molecule::Bonds | Molecule::Added;
    m_newObject.type = Rendering::AtomType;
    m_newObject.molecule = newAtom.molecule();
    m_newObject.index = newAtom.index();
  }
  else if (m_newObject.type == Rendering::AtomType) {
    // Grab the previously created atom
    newAtom = m_newObject.molecule->atom(m_newObject.index);
  }
  else {
    // Shouldn't happen
    qWarning() << "Editor::atomLeftDrag: m_newObject already set and not an "
                  "atom? This is a bug.";
  }

  if (newAtom.isValid()) {
    Vector2f windowPos(e->posF().x(), e->posF().y());
    Vector3f oldPos(newAtom.position3d().cast<float>());
    Vector3f newPos = m_glWidget->renderer().camera().unProject(windowPos,
                                                                oldPos);
    newAtom.setPosition3d(newPos.cast<double>());
    changes |= Molecule::Atoms | Molecule::Modified;
  }

  m_molecule->emitChanged(changes);
  return;
}

} // namespace QtOpenGL
} // namespace Avogadro
