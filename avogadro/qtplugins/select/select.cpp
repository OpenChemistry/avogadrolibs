/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "select.h"

#include <avogadro/core/residue.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/periodictableview.h>
#include <avogadro/qtgui/rwlayermanager.h>
#include <avogadro/qtgui/rwmolecule.h>

#include <QtCore/QDebug>
#include <QtCore/QRegularExpression>
#include <QtCore/QRegularExpressionMatch>
#include <QtGui/QKeySequence>
#include <QtWidgets/QAction>
#include <QtWidgets/QInputDialog>

#include <QtCore/QStringList>

using Avogadro::QtGui::Molecule;

namespace Avogadro::QtPlugins {

Select::Select(QObject* parent_)
  : Avogadro::QtGui::ExtensionPlugin(parent_), m_layerManager("Select"),
    m_molecule(nullptr), m_elements(nullptr)
{
  auto* action = new QAction(tr("Select All"), this);
  action->setShortcut(QKeySequence("Ctrl+A"));
  action->setProperty("menu priority", 990);
  connect(action, SIGNAL(triggered()), SLOT(selectAll()));
  m_actions.append(action);

  action = new QAction(tr("Select None"), this);
  action->setShortcut(QKeySequence("Ctrl+Shift+A"));
  action->setProperty("menu priority", 980);
  connect(action, SIGNAL(triggered()), SLOT(selectNone()));
  m_actions.append(action);

  action = new QAction(this);
  action->setSeparator(true);
  action->setProperty("menu priority", 970);
  m_actions.append(action);

  action = new QAction(tr("Invert Selection"), this);
  action->setProperty("menu priority", 890);
  connect(action, SIGNAL(triggered()), SLOT(invertSelection()));
  m_actions.append(action);

  action = new QAction(tr("Select by Element…"), this);
  action->setProperty("menu priority", 880);
  connect(action, SIGNAL(triggered()), SLOT(selectElement()));
  m_actions.append(action);

  action = new QAction(tr("Select by Atom Index…"), this);
  action->setProperty("menu priority", 870);
  connect(action, SIGNAL(triggered()), SLOT(selectAtomIndex()));
  m_actions.append(action);

  action = new QAction(tr("Select by Residue…"), this);
  action->setProperty("menu priority", 860);
  connect(action, SIGNAL(triggered()), SLOT(selectResidue()));
  m_actions.append(action);

  action = new QAction(tr("Select Backbone Atoms…"), this);
  action->setProperty("menu priority", 858);
  connect(action, SIGNAL(triggered()), SLOT(selectBackboneAtoms()));
  m_actions.append(action);

  action = new QAction(tr("Select Sidechain Atoms…"), this);
  action->setProperty("menu priority", 855);
  connect(action, SIGNAL(triggered()), SLOT(selectSidechainAtoms()));
  m_actions.append(action);

  action = new QAction(tr("Select Water…"), this);
  action->setProperty("menu priority", 850);
  connect(action, SIGNAL(triggered()), SLOT(selectWater()));
  m_actions.append(action);

  action = new QAction(this);
  action->setProperty("menu priority", 840);
  action->setSeparator(true);
  m_actions.append(action);

  action = new QAction(tr("Enlarge Selection"), this);
  action->setProperty("menu priority", 790);
  connect(action, SIGNAL(triggered()), SLOT(enlargeSelection()));
  m_actions.append(action);

  action = new QAction(tr("Shrink Selection"), this);
  action->setProperty("menu priority", 780);
  connect(action, SIGNAL(triggered()), SLOT(shrinkSelection()));
  m_actions.append(action);

  action = new QAction(this);
  action->setProperty("menu priority", 700);
  action->setSeparator(true);
  m_actions.append(action);

  action = new QAction(tr("Create New Layer from Selection"), this);
  action->setProperty("menu priority", 300);
  connect(action, SIGNAL(triggered()), SLOT(createLayerFromSelection()));
  m_actions.append(action);
}

Select::~Select()
{
  if (m_elements)
    m_elements->deleteLater();
}

QString Select::description() const
{
  return tr("Change selections");
}

QList<QAction*> Select::actions() const
{
  return m_actions;
}

QStringList Select::menuPath(QAction*) const
{
  return QStringList() << tr("&Select");
}

void Select::setMolecule(QtGui::Molecule* mol)
{
  m_molecule = mol;
}

bool Select::evalSelect(bool input, Index index) const
{
  return !m_layerManager.atomLocked(index) && input;
}

void Select::selectAll()
{
  if (m_molecule) {
    for (Index i = 0; i < m_molecule->atomCount(); ++i) {
      m_molecule->atom(i).setSelected(evalSelect(true, i));
    }

    m_molecule->emitChanged(Molecule::Atoms);
  }
}

void Select::selectNone()
{
  if (m_molecule) {
    for (Index i = 0; i < m_molecule->atomCount(); ++i)
      m_molecule->atom(i).setSelected(false);

    m_molecule->emitChanged(Molecule::Atoms);
  }
}

void Select::selectElement()
{
  if (!m_molecule)
    return;

  if (m_elements == nullptr) {
    m_elements = new QtGui::PeriodicTableView(qobject_cast<QWidget*>(parent()));
    connect(m_elements, SIGNAL(elementChanged(int)), this,
            SLOT(selectElement(int)));
  }

  m_elements->show();
}

void Select::selectElement(int element)
{
  if (!m_molecule)
    return;

  for (Index i = 0; i < m_molecule->atomCount(); ++i) {
    if (m_molecule->atomicNumber(i) == element) {
      m_molecule->atom(i).setSelected(evalSelect(true, i));
    } else
      m_molecule->atom(i).setSelected(false);
  }

  m_molecule->emitChanged(Molecule::Atoms);
}

bool Select::isWaterOxygen(Index i)
{
  if (m_molecule->atomicNumber(i) != 8)
    return false;

  // check to see if it has two bonds
  auto bonds = m_molecule->bonds(i);
  if (bonds.size() != 2)
    return false;

  // check to see that both bonds are to hydrogens
  for (auto& bond : bonds) {
    if (m_molecule->atomicNumber(bond.getOtherAtom(i).index()) != 1)
      return false;
  }

  return true;
}

void Select::selectWater()
{
  if (!m_molecule)
    return;

  for (Index i = 0; i < m_molecule->atomCount(); ++i) {
    auto atomicNumber = m_molecule->atomicNumber(i);
    if (atomicNumber == 8 && isWaterOxygen(i)) {
      m_molecule->atom(i).setSelected(evalSelect(true, i));
      continue;
    } else if (atomicNumber == 1) {
      // check if it's attached to a water oxygen
      auto bonds = m_molecule->bonds(i);
      if (bonds.size() != 1 || !isWaterOxygen(bonds[0].getOtherAtom(i).index()))
        m_molecule->atom(i).setSelected(evalSelect(false, i));
      else
        m_molecule->atom(i).setSelected(evalSelect(true, i));

      continue;
    }

    m_molecule->atom(i).setSelected(evalSelect(false, i));
  }
  // also select water residues (which may be isolated "O" atoms)
  for (const auto residue : m_molecule->residues()) {
    if (residue.residueName() == "HOH") {
      for (auto atom : residue.residueAtoms()) {
        atom.setSelected(evalSelect(true, atom.index()));
      }
    }
  }

  m_molecule->emitChanged(Molecule::Atoms);
}

void Select::selectBackboneAtoms()
{
  // unselect everything
  selectNone();

  for (const auto residue : m_molecule->residues()) {
    for (auto atom : residue.residueAtoms()) {
      auto name = residue.getAtomName(atom);
      if (name == "CA" || name == "C" || name == "N" || name == "O")
        atom.setSelected(evalSelect(true, atom.index()));

      // also select hydrogens connected to the backbone atoms
      if (atom.atomicNumber() == 1) {
        auto bonds = m_molecule->bonds(atom.index());
        if (bonds.size() == 1) {
          auto otherAtom = bonds[0].getOtherAtom(atom.index());
          auto name = residue.getAtomName(otherAtom);
          if (name == "CA" || name == "C" || name == "N" || name == "O")
            atom.setSelected(evalSelect(true, atom.index()));
        }
      }
    }
  }

  m_molecule->emitChanged(Molecule::Atoms);
}

void Select::selectSidechainAtoms()
{
  // unselect everything
  selectNone();

  for (const auto residue : m_molecule->residues()) {
    for (auto atom : residue.residueAtoms()) {
      auto name = residue.getAtomName(atom);
      if (name != "CA" && name != "C" && name != "N" && name != "O")
        atom.setSelected(evalSelect(true, atom.index()));

      // or is it a hydrogen connected to a backbone atom?
      // (then we don't want to select it)
      if (atom.atomicNumber() == 1) {
        auto bonds = m_molecule->bonds(atom.index());
        if (bonds.size() == 1) {
          auto otherAtom = bonds[0].getOtherAtom(atom.index());
          auto otherName = residue.getAtomName(otherAtom);
          if (otherName == "CA" || otherName == "C" || otherName == "N" ||
              otherName == "O")
            atom.setSelected(evalSelect(false, atom.index()));
        }
      }
    }
  }

  m_molecule->emitChanged(Molecule::Atoms);
}

Vector3 Select::getSelectionCenter()
{
  Vector3 center(0, 0, 0);
  int count = 0;
  for (Index i = 0; i < m_molecule->atomCount(); ++i) {
    if (m_molecule->atomSelected(i)) {
      center += m_molecule->atomPosition3d(i);
      ++count;
    }
  }

  if (count > 0)
    center /= count;

  return center;
}

void Select::enlargeSelection()
{
  Vector3 center = getSelectionCenter();
  // find the current max distance of the selection
  Real maxDistance = 0.0;
  for (Index i = 0; i < m_molecule->atomCount(); ++i) {
    if (m_molecule->atomSelected(i)) {
      // we'll use the squaredNorm to save a bunch of square roots
      Vector3 displacement = m_molecule->atomPosition3d(i) - center;
      Real distance = displacement.squaredNorm();
      if (distance > maxDistance)
        maxDistance = distance;
    }
  }
  maxDistance = sqrt(maxDistance) + 2.5;
  maxDistance *= maxDistance; // square to compare with .squaredNorm() values

  // now select all atoms within the NEW max distance
  for (Index i = 0; i < m_molecule->atomCount(); ++i) {
    if (!m_molecule->atomSelected(i)) {
      Vector3 displacement = m_molecule->atomPosition3d(i) - center;
      Real distance = displacement.squaredNorm();
      if (distance < maxDistance)
        m_molecule->atom(i).setSelected(evalSelect(true, i));
    }
  }

  m_molecule->emitChanged(Molecule::Atoms);
}

void Select::shrinkSelection()
{
  Vector3 center = getSelectionCenter();
  // find the current max distance of the selection
  Real maxDistance = 0.0;
  for (Index i = 0; i < m_molecule->atomCount(); ++i) {
    if (m_molecule->atomSelected(i)) {
      // we'll use the squaredNorm to save a bunch of square roots
      Vector3 displacement = m_molecule->atomPosition3d(i) - center;
      Real distance = displacement.squaredNorm();
      if (distance > maxDistance)
        maxDistance = distance;
    }
  }
  maxDistance = sqrt(maxDistance) - 2.5;
  if (maxDistance < 0.0)
    maxDistance = 0.0;
  maxDistance *= maxDistance; // square to compare with .squaredNorm() values

  // now select ONLY atoms within the NEW max distance
  for (Index i = 0; i < m_molecule->atomCount(); ++i) {
    Vector3 displacement = m_molecule->atomPosition3d(i) - center;
    Real distance = displacement.squaredNorm();
    if (distance < maxDistance)
      m_molecule->atom(i).setSelected(evalSelect(true, i));
    else
      m_molecule->atom(i).setSelected(evalSelect(false, i));
  }

  m_molecule->emitChanged(Molecule::Atoms);
}

void Select::selectAtomIndex()
{
  if (!m_molecule)
    return;

  bool ok;
  QString text = QInputDialog::getText(
    qobject_cast<QWidget*>(parent()), tr("Select Atoms by Index"),
    tr("Atoms to Select:"), QLineEdit::Normal, QString(), &ok);

  if (!ok || text.isEmpty())
    return;

  auto list = text.simplified().split(',');
  foreach (const QString item, list) {
    // check if it's a range
    if (item.contains('-')) {
      auto range = item.split('-');
      if (range.size() >= 2) {
        bool ok1, ok2;
        int start = range.first().toInt(&ok1);
        int last = range.back().toInt(&ok2);
        if (ok1 && ok2) {
          for (Index i = start; i <= last; ++i) {
            m_molecule->atom(i).setSelected(evalSelect(true, i));
          }
        }
      }
    } else {
      int i = item.toInt(&ok);
      if (ok)
        m_molecule->atom(i).setSelected(evalSelect(true, i));
    }
  }

  m_molecule->emitChanged(Molecule::Atoms);
}

void Select::selectResidue()
{
  if (!m_molecule)
    return;

  bool ok;
  QString text = QInputDialog::getText(
    qobject_cast<QWidget*>(parent()), tr("Select Atoms by Residue"),
    tr("Residues to Select:"), QLineEdit::Normal, QString(), &ok);

  if (!ok || text.isEmpty())
    return;

  auto list = text.simplified().split(',');
  foreach (const QString item, list) {
    const QString label = item.simplified(); // get rid of whitespace
    // check if it's a number - select that residue index
    bool ok;
    int index = label.toInt(&ok);
    if (ok) {
      auto residueList = m_molecule->residues();
      if (index >= 1 && index < residueList.size()) {
        auto residue = residueList[index];
        for (auto& atom : residue.residueAtoms()) {
          atom.setSelected(evalSelect(true, atom.index()));
        }
      } // index makes sense
      continue;
    }

    // okay it's not just a number, so see if it's HIS57, etc.
    QRegularExpression re("([a-zA-Z]+)([0-9]+)");
    QRegularExpressionMatch match = re.match(label);
    if (match.hasMatch()) {
      QString name = match.captured(1);
      int index = match.captured(2).toInt();

      auto residueList = m_molecule->residues();
      if (index >= 1 && index < residueList.size()) {
        auto residue = residueList[index];
        if (name == residue.residueName().c_str()) {
          for (auto atom : residue.residueAtoms()) {
            atom.setSelected(evalSelect(true, atom.index()));
          }
        } // check if name matches specified (e.g. HIS57 is really a HIS)
      }   // index makes sense
    } else {
      // standard residue name
      for (const auto& residue : m_molecule->residues()) {
        if (label == residue.residueName().c_str()) {
          // select the atoms of the residue
          for (auto atom : residue.residueAtoms()) {
            atom.setSelected(evalSelect(true, atom.index()));
          }
        } // residue matches label
      }   // for(residues)
      continue;
    } // 3-character labels
  }

  m_molecule->emitChanged(Molecule::Atoms);
}

void Select::invertSelection()
{
  if (m_molecule) {
    for (Index i = 0; i < m_molecule->atomCount(); ++i)
      m_molecule->atom(i).setSelected(
        evalSelect(!m_molecule->atomSelected(i), i));
    m_molecule->emitChanged(Molecule::Atoms);
  }
}

void Select::createLayerFromSelection()
{
  if (!m_molecule)
    return;

  QtGui::RWMolecule* rwmol = m_molecule->undoMolecule();
  rwmol->beginMergeMode(tr("Change Layer"));
  Molecule::MoleculeChanges changes =
    Molecule::Atoms | Molecule::Layers | Molecule::Modified;

  auto& layerInfo = Core::LayerManager::getMoleculeInfo(m_molecule)->layer;
  QtGui::RWLayerManager rwLayerManager;
  rwLayerManager.addLayer(rwmol);
  int layer = layerInfo.maxLayer();

  for (Index i = 0; i < rwmol->atomCount(); ++i) {
    auto a = rwmol->atom(i);
    if (a.selected()) {
      a.setLayer(layer);
    }
  }
  rwmol->endMergeMode();
  rwmol->emitChanged(changes);
}

} // namespace Avogadro::QtPlugins
