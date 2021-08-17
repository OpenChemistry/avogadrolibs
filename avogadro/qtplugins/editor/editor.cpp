/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "editor.h"

#include "editortoolwidget.h"

#include <avogadro/core/atom.h>
#include <avogadro/core/bond.h>
#include <avogadro/core/elements.h>
#include <avogadro/core/vector.h>

#include <avogadro/qtgui/hydrogentools.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/rwmolecule.h>

#include <avogadro/qtopengl/glwidget.h>

#include <avogadro/rendering/camera.h>
#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/glrenderer.h>

#include <avogadro/rendering/groupnode.h>
#include <avogadro/rendering/textlabel2d.h>
#include <avogadro/rendering/textlabel3d.h>
#include <avogadro/rendering/textproperties.h>

#include <QtGui/QGuiApplication>
#include <QtGui/QIcon>
#include <QtGui/QKeyEvent>
#include <QtGui/QMouseEvent>
#include <QtGui/QWheelEvent>
#include <QtWidgets/QAction>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QWidget>

#include <QtCore/QDebug>
#include <QtCore/QTimer>

#include <limits>

namespace {
const unsigned char INVALID_ATOMIC_NUMBER =
  std::numeric_limits<unsigned char>::max();
}

namespace Avogadro {
namespace QtPlugins {

using QtGui::Molecule;
using QtGui::RWAtom;
using QtGui::RWBond;
using QtGui::RWMolecule;
using QtOpenGL::GLWidget;

using Avogadro::Core::Elements;
using Avogadro::Rendering::GeometryNode;
using Avogadro::Rendering::GroupNode;
using Avogadro::Rendering::Identifier;
using Avogadro::Rendering::TextLabel2D;
using Avogadro::Rendering::TextLabel3D;
using Avogadro::Rendering::TextProperties;

Editor::Editor(QObject* parent_)
  : QtGui::ToolPlugin(parent_), m_activateAction(new QAction(this)),
    m_molecule(nullptr), m_glWidget(nullptr), m_renderer(nullptr),
    m_toolWidget(new EditorToolWidget(qobject_cast<QWidget*>(parent_))),
    m_pressedButtons(Qt::NoButton),
    m_clickedAtomicNumber(INVALID_ATOMIC_NUMBER), m_bondAdded(false),
    m_fixValenceLater(false), m_layerManager("Editor")
{
  m_activateAction->setText(tr("Draw"));
  m_activateAction->setIcon(QIcon(":/icons/editor.png"));
  reset();
}

Editor::~Editor() {}

QWidget* Editor::toolWidget() const
{
  return m_toolWidget;
}

QUndoCommand* Editor::mousePressEvent(QMouseEvent* e)
{
  clearKeyPressBuffer();
  if (!m_renderer || !m_molecule)
    return nullptr;

  updatePressedButtons(e, false);
  m_clickPosition = e->pos();

  if (m_pressedButtons & Qt::LeftButton) {
    m_clickedObject = m_renderer->hit(e->pos().x(), e->pos().y());
    if (m_layerManager.activeLayerLocked()) {
      e->accept();
      return nullptr;
    }
    switch (m_clickedObject.type) {
      case Rendering::InvalidType:
        m_molecule->beginMergeMode(tr("Draw Atom"));
        emptyLeftClick(e);
        return nullptr;
      case Rendering::AtomType:
        // We don't know yet if we are drawing a bond/atom or replacing an atom
        // unfortunately...
        m_molecule->beginMergeMode(tr("Draw"));
        atomLeftClick(e);
        return nullptr;
      case Rendering::BondType:
        m_molecule->beginMergeMode(tr("Change Bond Type"));
        bondLeftClick(e);
        return nullptr;
    }
  } else if (m_pressedButtons & Qt::RightButton) {
    m_clickedObject = m_renderer->hit(e->pos().x(), e->pos().y());

    switch (m_clickedObject.type) {
      case Rendering::AtomType:
        m_molecule->beginMergeMode(tr("Remove Atom"));
        atomRightClick(e);
        return nullptr;
      case Rendering::BondType:
        m_molecule->beginMergeMode(tr("Remove Bond"));
        bondRightClick(e);
        return nullptr;
      default:
        break;
    }
  }

  return nullptr;
}

QUndoCommand* Editor::mouseReleaseEvent(QMouseEvent* e)
{
  if (!m_renderer || !m_molecule)
    return nullptr;
  if (m_layerManager.activeLayerLocked()) {
    e->accept();
    return nullptr;
  }
  updatePressedButtons(e, true);

  if (m_clickedObject.type == Rendering::InvalidType)
    return nullptr;

  switch (e->button()) {
    case Qt::LeftButton:
    case Qt::RightButton:
      reset();
      e->accept();
      m_molecule->endMergeMode();
      // Let's cover all possible changes - the undo stack won't update
      // without this
      m_molecule->emitChanged(Molecule::Atoms | Molecule::Bonds |
                              Molecule::Added | Molecule::Removed |
                              Molecule::Modified);
      break;
    default:
      break;
  }

  return nullptr;
}

QUndoCommand* Editor::mouseMoveEvent(QMouseEvent* e)
{
  if (!m_renderer)
    return nullptr;
  if (m_pressedButtons & Qt::LeftButton)
    if (m_clickedObject.type == Rendering::AtomType) {
      if (m_layerManager.activeLayerLocked()) {
        e->accept();
        return nullptr;
      }
      atomLeftDrag(e);
    }

  return nullptr;
}

QUndoCommand* Editor::keyPressEvent(QKeyEvent* e)
{
  if (e->text().isEmpty())
    return nullptr;
  e->accept();

  if (m_layerManager.activeLayerLocked()) {
    return nullptr;
  }
  // Set a timer to clear the buffer on first keypress:
  if (m_keyPressBuffer.isEmpty())
    QTimer::singleShot(2000, this, SLOT(clearKeyPressBuffer()));

  m_keyPressBuffer.append(m_keyPressBuffer.isEmpty() ? e->text().toUpper()
                                                     : e->text().toLower());

  if (m_keyPressBuffer.size() >= 3) {
    clearKeyPressBuffer();
    return nullptr;
  }

  bool ok = false;
  int atomicNum;
  int bondOrder = m_keyPressBuffer.toInt(&ok);

  if (ok && bondOrder > 0 && bondOrder <= 4) {
    m_toolWidget->setBondOrder(static_cast<unsigned char>(bondOrder));
  } else {
    atomicNum =
      Core::Elements::atomicNumberFromSymbol(m_keyPressBuffer.toStdString());

    if (atomicNum != Avogadro::InvalidElement)
      m_toolWidget->setAtomicNumber(static_cast<unsigned char>(atomicNum));
  }

  return nullptr;
}

void Editor::draw(Rendering::GroupNode& node)
{
  if (fabs(m_bondDistance) < 0.3)
    return;

  GeometryNode* geo = new GeometryNode;
  node.addChild(geo);

  // Determine the field width. Negate it to indicate left-alignment.
  QString distanceLabel = tr("Distance:");
  int labelWidth = -1 * distanceLabel.size();

  QString overlayText = tr("%1 %L2")
                          .arg(distanceLabel, labelWidth)
                          .arg(tr("%L1 Å").arg(m_bondDistance, 9, 'f', 3), 9);

  TextProperties overlayTProp;
  overlayTProp.setFontFamily(TextProperties::Mono);
  overlayTProp.setColorRgb(64, 255, 220);
  overlayTProp.setAlign(TextProperties::HLeft, TextProperties::VBottom);

  TextLabel2D* label = new TextLabel2D;
  label->setText(overlayText.toStdString());
  label->setTextProperties(overlayTProp);
  label->setRenderPass(Rendering::Overlay2DPass);
  label->setAnchor(Vector2i(10, 10));

  geo->addDrawable(label);
}

void Editor::updatePressedButtons(QMouseEvent* e, bool release)
{
  /// @todo Use modifier keys on mac
  if (release)
    m_pressedButtons &= e->buttons();
  else
    m_pressedButtons |= e->buttons();
}

void Editor::reset()
{
  if (m_fixValenceLater) {
    Index a1 = m_newObject.index;
    Index a2 = m_bondedAtom.index;
    Index a3 = m_clickedObject.index;

    // order them
    if (a1 > a2)
      std::swap(a1, a2);
    if (a1 > a3)
      std::swap(a1, a3);
    if (a2 > a3)
      std::swap(a2, a3);

    // This preserves the order so they are adjusted in order.
    Core::Array<Index> atomIds;
    atomIds.push_back(a3);
    atomIds.push_back(a2);
    atomIds.push_back(a1);
    // This function checks to make sure the ids are valid, so no need
    // to check out here.
    m_molecule->adjustHydrogens(atomIds);

    Molecule::MoleculeChanges changes = Molecule::Atoms | Molecule::Added;
    changes |= Molecule::Bonds | Molecule::Added | Molecule::Removed;

    m_molecule->emitChanged(changes);

    m_fixValenceLater = false;
  }

  m_clickedObject = Identifier();
  m_newObject = Identifier();
  m_bondedAtom = Identifier();
  m_clickPosition = QPoint();
  m_pressedButtons = Qt::NoButton;
  m_clickedAtomicNumber = INVALID_ATOMIC_NUMBER;
  m_bondAdded = false;

  m_bondDistance = 0.0f;
  emit drawablesChanged();
}

void Editor::emptyLeftClick(QMouseEvent* e)
{
  // Add an atom at the clicked position
  Vector2f windowPos(e->localPos().x(), e->localPos().y());
  Vector3f atomPos = m_renderer->camera().unProject(windowPos);
  RWAtom newAtom =
    m_molecule->addAtom(m_toolWidget->atomicNumber(), atomPos.cast<double>());

  Molecule::MoleculeChanges changes = Molecule::Atoms | Molecule::Modified;

  if (m_toolWidget->adjustHydrogens()) {
    m_fixValenceLater = true;
  }

  // Update the clicked object
  m_clickedObject.type = Rendering::AtomType;
  m_clickedObject.molecule = m_molecule;
  m_clickedObject.index = newAtom.index();

  // Emit changed signal
  m_molecule->emitChanged(changes);

  e->accept();
}

void Editor::atomLeftClick(QMouseEvent* e)
{
  RWAtom atom = m_molecule->atom(m_clickedObject.index);
  if (atom.isValid()) {
    // Store the original atomic number of the clicked atom before updating it.
    unsigned char atomicNumber = m_toolWidget->atomicNumber();
    if (atom.atomicNumber() != atomicNumber) {
      m_clickedAtomicNumber = atom.atomicNumber();
      atom.setAtomicNumber(atomicNumber);

      Molecule::MoleculeChanges changes = Molecule::Atoms | Molecule::Modified;

      if (m_toolWidget->adjustHydrogens())
        m_fixValenceLater = true;

      m_molecule->emitChanged(changes);
    }
    e->accept();
  }
}

void Editor::bondLeftClick(QMouseEvent* e)
{
  RWBond bond = m_molecule->bond(m_clickedObject.index);
  bond.setOrder(static_cast<unsigned char>((bond.order() % 3) + 1));

  Molecule::MoleculeChanges changes = Molecule::Bonds | Molecule::Modified;

  if (m_toolWidget->adjustHydrogens()) {
    // change for the new bond order
    RWAtom atom1 = bond.atom1();
    RWAtom atom2 = bond.atom2();
    QtGui::HydrogenTools::adjustHydrogens(atom1);
    QtGui::HydrogenTools::adjustHydrogens(atom2);

    changes |= Molecule::Atoms | Molecule::Added | Molecule::Removed;
  }

  m_molecule->emitChanged(changes);
  e->accept();
}

void Editor::atomRightClick(QMouseEvent* e)
{
  e->accept();
  m_molecule->removeAtom(m_clickedObject.index);
  m_molecule->emitChanged(Molecule::Atoms | Molecule::Removed);
}

void Editor::bondRightClick(QMouseEvent* e)
{
  e->accept();
  m_molecule->removeBond(m_clickedObject.index);
  m_molecule->emitChanged(Molecule::Bonds | Molecule::Removed);
}

int expectedBondOrder(RWAtom atom1, RWAtom atom2)
{
  Vector3 bondVector = atom1.position3d() - atom2.position3d();
  double bondDistance = bondVector.norm();
  double radiiSum;
  radiiSum = Elements::radiusCovalent(atom1.atomicNumber()) +
             Elements::radiusCovalent(atom2.atomicNumber());
  double ratio = bondDistance / radiiSum;

  int bondOrder;
  if (ratio > 1.0)
    bondOrder = 1;
  else if (ratio > 0.91 && ratio < 1.0)
    bondOrder = 2;
  else
    bondOrder = 3;

  return bondOrder;
}

void Editor::atomLeftDrag(QMouseEvent* e)
{
  // Always accept move events when atoms are clicked:
  e->accept();

  // Build up a MoleculeChanges bitfield
  Molecule::MoleculeChanges changes = Molecule::NoChange;

  // Get the list of hits at the current mouse position:
  const std::multimap<float, Identifier> hits =
    m_renderer->hits(e->pos().x(), e->pos().y());

  // Check if the previously clicked atom is still under the mouse.
  float depth = -1.0f;
  for (std::multimap<float, Rendering::Identifier>::const_iterator
         it = hits.begin(),
         itEnd = hits.end();
       it != itEnd; ++it) {
    if (it->second == m_clickedObject) {
      depth = it->first;
      break;
    }
  }

  // If the clicked atom is under the mouse...
  if (depth >= 0.f) {
    // ...and we've created a new atom, remove the new atom and reset the
    // clicked atom's atomic number
    if (m_newObject.type == Rendering::AtomType &&
        m_molecule == m_newObject.molecule) {
      m_molecule->removeAtom(m_newObject.index);
      changes |= Molecule::Atoms | Molecule::Bonds | Molecule::Removed;
      m_newObject = Identifier();
      RWAtom atom = m_molecule->atom(m_clickedObject.index);
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
    RWAtom clickedAtom = m_molecule->atom(m_clickedObject.index);
    clickedAtom.setAtomicNumber(m_clickedAtomicNumber);
    m_clickedAtomicNumber = INVALID_ATOMIC_NUMBER;
    changes |= Molecule::Atoms | Molecule::Modified;
  }

  // Does a bonded atom already exist?
  if (m_bondedAtom.isValid()) {
    // Is it still under the mouse?
    depth = -1.0f;
    for (std::multimap<float, Identifier>::const_iterator it = hits.begin(),
                                                          itEnd = hits.end();
         it != itEnd; ++it) {
      if (it->second == m_bondedAtom) {
        depth = it->first;
        break;
      }
    }

    // If the bonded atom is no longer under the mouse, remove the bond.
    if (depth < 0.f) {
      RWAtom bondedAtom = m_molecule->atom(m_bondedAtom.index);
      RWAtom clickedAtom = m_molecule->atom(m_clickedObject.index);
      if (m_bondAdded)
        m_molecule->removeBond(clickedAtom, bondedAtom);
      changes |= Molecule::Bonds | Molecule::Removed;
      m_bondedAtom = Identifier();
      m_bondAdded = false;
    }
  }

  // Is there another atom under the cursor, besides newAtom? If so, we'll draw
  // a bond to it.
  Identifier atomToBond;
  for (std::multimap<float, Identifier>::const_iterator it = hits.begin(),
                                                        itEnd = hits.end();
       it != itEnd; ++it) {
    const Identifier& ident = it->second;
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
    if (m_newObject.isValid() && atomToBond.index != m_newObject.index &&
        m_newObject.type == Rendering::AtomType) {
      m_molecule->removeAtom(m_newObject.index);
      changes |= Molecule::Atoms | Molecule::Bonds | Molecule::Removed;
      m_newObject = Identifier();
    }

    // Skip the rest of this block if atomToBond is already bonded
    if (m_bondedAtom != atomToBond) {
      // If the currently bonded atom exists, break the bond
      if (m_bondedAtom.isValid() && m_clickedObject.isValid() &&
          m_bondedAtom.index < m_molecule->atomCount() &&
          m_clickedObject.index < m_molecule->atomCount() &&
          m_molecule->bond(m_bondedAtom.index, m_clickedObject.index)
            .isValid()) {
        if (m_molecule->removeBond(m_molecule->atom(m_bondedAtom.index),
                                   m_molecule->atom(m_clickedObject.index))) {
          changes |= Molecule::Bonds | Molecule::Removed;
        }
        m_bondedAtom = Identifier();
      }

      // Create a new bond between clicked atom and atomToBond.
      RWAtom clickedAtom = m_molecule->atom(m_clickedObject.index);
      RWAtom bondedAtom = m_molecule->atom(atomToBond.index);
      if (!m_molecule->bond(clickedAtom, bondedAtom).isValid()) {

        int bondOrder = m_toolWidget->bondOrder();
        if (bondOrder == 0) {
          // automatic - guess the size
          bondOrder = expectedBondOrder(clickedAtom, bondedAtom);
        }
        m_molecule->addBond(clickedAtom, bondedAtom, bondOrder);
        m_bondAdded = true;
      } // we have a bond, but it might be the wrong order
      else {
        RWBond bond = m_molecule->bond(clickedAtom, bondedAtom);
        int bondOrder = m_toolWidget->bondOrder();
        if (bondOrder == 0) {
          // automatic - guess the size
          bondOrder = expectedBondOrder(clickedAtom, bondedAtom);
        }
        if (bond.order() != bondOrder)
          bond.setOrder(bondOrder);
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
  RWAtom newAtom;
  if (!m_newObject.isValid()) {
    // Add a new atom bonded to the clicked atom
    RWAtom clickedAtom = m_molecule->atom(m_clickedObject.index);
    newAtom = m_molecule->addAtom(m_toolWidget->atomicNumber(),
                                  clickedAtom.position3d());

    // Handle the automatic bond order
    int bondOrder = m_toolWidget->bondOrder();
    if (bondOrder == 0) {
      // automatic - guess the size
      bondOrder = expectedBondOrder(clickedAtom, newAtom);
    }
    m_molecule->addBond(clickedAtom, newAtom, bondOrder);

    // now if we need to adjust hydrogens, do it
    if (m_toolWidget->adjustHydrogens())
      m_fixValenceLater = true;

    changes |= Molecule::Atoms | Molecule::Bonds | Molecule::Added;
    m_newObject.type = Rendering::AtomType;
    m_newObject.index = newAtom.index();
    const Core::Molecule* mol = &m_molecule->molecule();
    m_newObject.molecule = mol;
  } else if (m_newObject.type == Rendering::AtomType) {
    // Grab the previously created atom
    newAtom = m_molecule->atom(m_newObject.index);
  } else {
    // Shouldn't happen

    qWarning() << "Editor::atomLeftDrag: m_newObject already set and not an "
                  "atom? This is a bug.";
  }

  if (newAtom.isValid()) {
    Vector2f windowPos(e->localPos().x(), e->localPos().y());
    Vector3f oldPos(newAtom.position3d().cast<float>());
    Vector3f newPos = m_renderer->camera().unProject(windowPos, oldPos);
    newAtom.setPosition3d(newPos.cast<double>());

    changes |= Molecule::Atoms | Molecule::Modified;

    RWAtom clickedAtom = m_molecule->atom(m_clickedObject.index);
    if (clickedAtom.isValid()) {
      Vector3f bondVector = clickedAtom.position3d().cast<float>() - newPos;
      m_bondDistance = bondVector.norm();

      // need to check if bond order needs to change
      if (m_toolWidget->bondOrder() == 0) { // automatic
        RWBond bond = m_molecule->bond(newAtom, clickedAtom);
        if (bond.isValid()) {
          int bondOrder = expectedBondOrder(newAtom, clickedAtom);
          if (bondOrder != bond.order())
            bond.setOrder(bondOrder);

          changes |= Molecule::Bonds | Molecule::Modified;
        }
      } // otherwise see if the bond order is different than what's there
      else {
        int bondOrder = m_toolWidget->bondOrder();
        RWBond bond = m_molecule->bond(newAtom, clickedAtom);
        if (bond.isValid() && bondOrder != bond.order())
          bond.setOrder(bondOrder);

        changes |= Molecule::Bonds | Molecule::Modified;
      }
    }
  }

  m_molecule->emitChanged(changes);
  return;
}

} // namespace QtPlugins
} // namespace Avogadro
